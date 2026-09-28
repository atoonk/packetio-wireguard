package gateway

// The plaintext side as kernel TUN queues, one per receive goroutine, driven
// by that goroutine with plain syscalls. This is the gateway design where the
// kernel keeps routing, firewalling and its own addresses, and wgpio does the
// tunnel: what arrives encrypted is decrypted in the DMA frame and written to
// this core's queue; what the kernel routes into the queue is read into a
// frame from this core's transmit pool and encrypted in place, exactly as the
// generator's frames are. wireguard-go's own pipeline sees only what the fast
// path punts, through the gateway's tun.Device as before.
//
// It costs one read or write system call per packet per core; the TUN has no
// batching for small packets. That is the price of keeping the kernel on the
// plaintext side, and it is what this file exists to measure.

import (
	"golang.org/x/sys/unix"

	"github.com/atoonk/packetio"

	"github.com/atoonk/packetio-wireguard/internal/ether"
)

// ktunState is one receive goroutine's queue.
type ktunState struct {
	on   bool
	fd   int
	free []packetio.Desc // frames from the transmit pool waiting for a read
	hdr  []byte          // the link header written in front of every packet read
}

// ktunSpare is what the fast path reaches back past the link header: the
// same as the generator leaves.
const ktunSpare = 48

func (g *Gateway) ktunInit(rq *rxQueue, i int) {
	if i >= len(g.cfg.KernelTUN) {
		return
	}
	st := &rq.ktun
	st.on, st.fd = true, g.cfg.KernelTUN[i]
	// A made-up LAN frame header, so the packet takes the path a LAN frame
	// takes: classify's link parse, then fpEncrypt, which reads l.Len to
	// find the plaintext and l.Src for nothing that matters here.
	st.hdr = make([]byte, ether.LinkLen(g.cfg.LANVLAN))
	ether.PutLink(st.hdr, g.mac, ether.MAC{0x02, 0x6b, 0x74, 0x75, 0x6e, byte(i)}, g.cfg.LANVLAN, ether.TypeIPv4)
}

// ktunPull reads what the kernel has queued for this core, up to a batch,
// and hands each packet to the fast path. It runs every receive turn; when
// the queue is empty it costs one system call that returns EAGAIN.
func (g *Gateway) ktunPull(rq *rxQueue) {
	st := &rq.ktun
	if !st.on || rq.tx == nil {
		return
	}
	mem := rq.fr.mem
	hdr := len(st.hdr)
	got := 0
	for got < Batch {
		if len(st.free) == 0 {
			if rq.txShared != nil {
				rq.txShared.mu.Lock()
			}
			st.free = rq.tx.Alloc(Batch)
			if rq.txShared != nil {
				rq.txShared.mu.Unlock()
			}
			if len(st.free) == 0 {
				break // the pool is empty; the kernel's queue holds the rest
			}
		}
		d := st.free[len(st.free)-1]
		start := int(d.Addr) + ktunSpare
		room := rq.fr.size - (start - int(d.Addr&^uint64(rq.fr.size-1))) - hdr
		n, err := unix.Read(st.fd, mem[start+hdr:start+hdr+room])
		if err != nil || n <= 0 {
			if err != unix.EAGAIN && err != unix.EINTR {
				rq.st.KTUNReadDropped.Add(1)
			}
			break
		}
		st.free = st.free[:len(st.free)-1]
		got++
		copy(mem[start:], st.hdr)
		fd := packetio.Desc{Addr: uint64(start), Len: uint32(hdr + n)}
		f := mem[start : start+hdr+n]
		l, _ := ether.ParseLink(f)
		h, ok := ether.ParseIPv4(f[l.Len:])
		if !ok || h.TotalLen > n || h.TotalLen > g.cfg.MTU {
			rq.giveBack(fd)
			rq.st.KTUNReadDropped.Add(1)
			continue
		}
		fd.Len = uint32(hdr + h.TotalLen)
		if rq.fpOn {
			switch g.fpEncrypt(rq, fd, f[:fd.Len], l, h) {
			case fpForwarded:
				continue
			case fpDropped:
				rq.giveBack(fd)
				rq.st.KTUNReadDropped.Add(1)
				continue
			}
			// Punted: no keypair yet. The stock path stages it and starts
			// the handshake; park it as classify parks a LAN frame.
		}
		wasEmpty := rq.lan.pending() == 0
		if !rq.lan.push(parked{d: fd, off: uint16(l.Len), n: uint16(h.TotalLen)}) {
			rq.giveBack(fd)
			rq.st.LANRingFull.Add(1)
			continue
		}
		if wasEmpty {
			select {
			case g.wake <- struct{}{}:
			default:
			}
		}
	}
	rq.st.KTUNRead.Add(uint64(got))
}

// ktunPush hands one decrypted packet to the kernel through this core's
// queue. A TUN write never blocks; it fails when the kernel's backlog for
// the queue is full, and that is a drop.
func (g *Gateway) ktunPush(rq *rxQueue, plain []byte) {
	if _, err := unix.Write(rq.ktun.fd, plain); err != nil {
		rq.st.KTUNWriteDropped.Add(1)
		return
	}
	rq.st.KTUNWrite.Add(1)
}
