package gateway

import (
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/atoonk/packetio-wireguard/internal/affinity"
	"github.com/atoonk/packetio-wireguard/internal/ether"
)

// TUN is the tun.Device: the plaintext side, made of the LAN VLAN.
//
// Read is called by wireguard-go's single RoutineReadFromTUN goroutine. It
// copies parked LAN frames out of the receive queues' rings; the owning
// receive goroutines recycle them afterwards. Write is called by each
// peer's sequential receiver with the decrypted packets, which go out on the
// LAN VLAN to their next hop.
type TUN struct {
	g      *Gateway
	events chan tun.Event
	closed atomic.Bool
	done   chan struct{}
	rr     int // where the last Read stopped, so queues are served fairly
	lastAt int64
	pinned bool
	wmu    sync.Mutex // Write is called from every peer's sequential receiver
	pkts   [][]byte   // under wmu

	// Packets the tunnel delivered to this gateway's own LAN address and
	// which are answered (ICMP echo): the replies wait here for Read, which
	// hands them back to wireguard-go to encrypt to the peer.
	lmu  sync.Mutex
	loop [][]byte
}

var _ tun.Device = (*TUN)(nil)

// TUN returns the gateway's tun.Device.
func (g *Gateway) TUN() *TUN {
	return &TUN{g: g, events: make(chan tun.Event, 4), done: make(chan struct{}), pkts: make([][]byte, 0, Batch)}
}

func (t *TUN) File() *os.File           { return nil }
func (t *TUN) Name() (string, error)    { return t.g.cfg.Name, nil }
func (t *TUN) MTU() (int, error)        { return t.g.cfg.MTU, nil }
func (t *TUN) Events() <-chan tun.Event { return t.events }
func (t *TUN) BatchSize() int           { return Batch }

// Close stops Read and closes the event channel, which ends wireguard-go's
// event reader.
func (t *TUN) Close() error {
	if !t.closed.Swap(true) {
		close(t.events)
		close(t.done)
	}
	return nil
}

// Read blocks until at least one LAN packet is available, then copies as
// many as fit. When the rings are empty it yields briefly, then blocks on
// the gateway's wake channel, which a receive goroutine signals when it
// parks a frame into an empty ring. It never sleeps on a timer: a timer
// sleep on Linux is a millisecond or more, and at a few hundred thousand
// packets per second that is a full ring lost every time.
func (t *TUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// The gap is the time wireguard-go spent away with the previous batch,
	// from Read's return to this call: the reader's per-batch cost.
	if t.g.cfg.Diagnostics && t.lastAt != 0 {
		gap(&t.lastAt, &t.g.Stats.TUNMaxGapNs, &t.g.Stats.TUNGaps)
	}
	if !t.pinned {
		t.pinned = true
		if err := affinity.Pin(t.g.cfg.TUNCPU); err != nil {
			t.g.log.Warn("pin TUN reader", "cpu", t.g.cfg.TUNCPU, "err", err)
		}
	}
	idle := 0
	for {
		if t.closed.Load() {
			return 0, os.ErrClosed
		}
		n := t.readOnce(bufs, sizes, offset)
		if n > 0 {
			t.g.Stats.TUNReads.Add(1)
			t.lastAt = nanotime()
			return n, nil
		}
		t.g.Stats.TUNEmpty.Add(1)
		idle++
		if t.g.cfg.TUNCPU >= 0 && !t.g.cfg.FastPath {
			// A core of its own: spin. Waking through the scheduler was measured
			// at up to two milliseconds behind a producer that never yields.
			// With the fast path on only punted packets come this way, so the
			// reader may block instead and the core is free.
			continue
		}
		if idle < 256 {
			runtime.Gosched()
			continue
		}
		select {
		case <-t.g.wake:
			t.g.Stats.TUNWakes.Add(1)
		case <-t.done:
		case <-time.After(10 * time.Millisecond): // belt and braces; also lets closed be rechecked
			t.g.Stats.TUNTimeouts.Add(1)
		}
	}
}

// echoBack answers a ping the tunnel delivered to this gateway's own LAN
// address (the fast path's fpEchoBack, for the stock path). The reply is a
// copy, since wireguard-go reuses the buffer, queued for Read.
func (t *TUN) echoBack(pkt []byte, h ether.IPv4) {
	g := t.g
	if !ether.EchoReplyIP(pkt, h) {
		g.Stats.RxOther.Add(1)
		return
	}
	g.Stats.RxICMP.Add(1)
	g.Stats.TxICMP.Add(1)
	t.lmu.Lock()
	t.loop = append(t.loop, append([]byte(nil), pkt[:h.TotalLen]...))
	t.lmu.Unlock()
	select {
	case g.wake <- struct{}{}:
	default:
	}
}

func (t *TUN) readOnce(bufs [][]byte, sizes []int, offset int) int {
	g := t.g
	n := 0
	t.lmu.Lock() // once per batch, uncontended: pings are rare
	for n < len(bufs) && len(t.loop) > 0 {
		sizes[n] = copy(bufs[n][offset:], t.loop[0])
		t.loop = t.loop[1:]
		n++
	}
	t.lmu.Unlock()
	for k := 0; k < len(g.rx) && n < len(bufs); k++ {
		rq := g.rx[(t.rr+k)%len(g.rx)]
		for n < len(bufs) {
			p, ok := rq.lan.peek()
			if !ok {
				break
			}
			f := rq.fr.packet(p.d)
			sizes[n] = copy(bufs[n][offset:], f[p.off:int(p.off)+int(p.n)])
			rq.lan.done()
			n++
		}
	}
	t.rr = (t.rr + 1) % len(g.rx)
	return n
}

// Write sends decrypted packets to the LAN.
func (t *TUN) Write(bufs [][]byte, offset int) (int, error) {
	if t.closed.Load() {
		return 0, os.ErrClosed
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	pkts := t.pkts[:0]
	for _, b := range bufs {
		if len(b) <= offset {
			continue
		}
		pkt := b[offset:]
		if h, ok := ether.ParseIPv4(pkt); ok && h.Dst == t.g.lIP {
			t.echoBack(pkt, h)
			continue
		}
		pkts = append(pkts, pkt)
	}
	if t.g.cfg.Sink {
		t.g.Stats.SinkPackets.Add(uint64(len(pkts)))
		return len(bufs), nil
	}
	if len(t.g.cfg.KernelTUN) > 0 {
		// The stock path only carries what the fast path punted (packets
		// before the first keypair, mostly); any queue will do.
		for _, pkt := range pkts {
			if _, err := unix.Write(t.g.cfg.KernelTUN[0], pkt); err != nil {
				t.g.Stats.KTUNWriteDropped.Add(1)
			} else {
				t.g.Stats.KTUNWrite.Add(1)
			}
		}
		return len(bufs), nil
	}
	n := t.g.tx[0].sendLAN(pkts)
	t.g.Stats.TxLAN.Add(uint64(n))
	return len(bufs), nil
}
