package gateway

import (
	"sync"

	"github.com/atoonk/packetio"

	"github.com/atoonk/packetio-wireguard/internal/ether"
)

// txQueue is one transmit queue behind a mutex. wireguard-go transmits from
// its per-peer sender goroutines and from handshake timers, so the queue
// cannot have a single owner; the lock makes the whole
// complete-allocate-build-transmit cycle one critical section.
//
// On a queue of its own it only carries frames it allocated, so Complete
// (inside SendFunc) is the only completion path. When the fast path has no
// spare queue and shares this one (owner != nil), received frames are
// transmitted here too, and they must find their way home to the receive
// pool: see send.
type txQueue struct {
	mu    sync.Mutex
	q     packetio.TxQueue
	g     *Gateway
	id    uint16   // IPv4 identification, per queue so the counter is not shared
	owner *rxQueue // the fast-path receive goroutine sharing this queue, if any

	// Shared-queue state, under mu: received frames the stock path
	// completed, held for their owner to recycle, and scratch.
	orphans, descs, free []packetio.Desc

	// Per-call state for the builders, valid under mu.
	bufs   [][]byte
	dst    ether.MAC
	dstIP  [4]byte
	port   uint16
	built  int                           // frames the builder produced this call; built minus transmitted = ring refusals
	shorts int                           // calls that could not send everything, for the log
	errs   int                           // calls the backend refused, for the log
	build  func(i int, frame []byte) int // method value, made once
	buildL func(i int, frame []byte) int
}

func newTxQueue(q packetio.TxQueue, g *Gateway) *txQueue {
	t := &txQueue{q: q, g: g}
	t.build = t.buildTunnel
	t.buildL = t.buildLAN
	return t
}

// txForEndpoint spreads tunnel sends over the transmit queues above queue 0,
// which the LAN side and control traffic use, by endpoint.
func (g *Gateway) txForEndpoint(e *Endpoint) *txQueue {
	if len(g.tx) == 1 {
		return g.tx[0]
	}
	h := uint32(e.ip[0])<<24 | uint32(e.ip[1])<<16 | uint32(e.ip[2])<<8 | uint32(e.ip[3])
	h ^= uint32(e.port) * 0x9e3779b1
	return g.tx[1+int(h%uint32(len(g.tx)-1))]
}

// send is SendFunc under the caller's lock, with one exception. On a queue
// shared with a fast-path receive goroutine, SendFunc's own Complete would
// push that goroutine's received frames into this queue's pool, which
// refuses them (a pool takes only its own frames), and the receive pool
// would lose the in-flight count on every keepalive. So on a shared queue
// the completions are sorted first -- this pool's frames back to it, the
// receive pool's held for fpReclaim -- and the frames are then allocated,
// built and transmitted by hand. The build contract is SendFunc's: a
// return of 0 ends the batch.
func (t *txQueue) send(count int, build func(i int, frame []byte) int) int {
	if t.owner == nil {
		n, err := t.q.SendFunc(count, build)
		if err != nil {
			t.failed(err)
		}
		return n
	}
	t.reclaimShared()
	descs := t.q.Alloc(count)
	r := t.q.Region()
	built := 0
	for i := range descs {
		n := build(i, r.Writable(descs[i]))
		if n <= 0 {
			break
		}
		descs[i].Len = uint32(n)
		built++
	}
	if built < len(descs) {
		t.q.Free(descs[built:])
	}
	sent := t.q.Transmit(descs[:built])
	if sent < built {
		t.q.Free(descs[sent:built])
	}
	return sent
}

// reclaimShared takes the completions of a shared queue and sorts them by
// owner. Only the receive goroutine may Recycle its frames, so those wait
// in orphans until it next reclaims.
func (t *txQueue) reclaimShared() {
	t.descs = t.q.Reclaim(t.q.NumInFlight(), t.descs[:0])
	t.free = t.free[:0]
	for _, d := range t.descs {
		if t.owner.ownsFrame(d) {
			t.orphans = append(t.orphans, d)
		} else {
			t.free = append(t.free, d)
		}
	}
	if len(t.free) > 0 {
		t.q.Free(t.free)
	}
}

// sendTunnel wraps each buffer in Ethernet/802.1Q/IPv4/UDP to the endpoint
// and transmits them on the queue, under its lock. SendFunc takes fewer
// frames than asked when the pool or ring is short, so the remainder is
// retried; what it still refuses is counted as ring-full and dropped.
func (t *txQueue) sendTunnel(bufs [][]byte, dst ether.MAC, dstIP [4]byte, port uint16) int {
	t.mu.Lock()
	t.dst, t.dstIP, t.port = dst, dstIP, port
	sent := 0
	for try := 0; sent < len(bufs) && try < 4; try++ {
		t.bufs, t.built = bufs[sent:], 0
		n := t.send(len(bufs)-sent, t.build)
		t.g.Stats.TxRingFull.Add(uint64(t.built - n))
		sent += n
		if n == 0 {
			break
		}
	}
	if sent < len(bufs) {
		t.short(len(bufs) - sent)
	}
	t.bufs = nil
	t.mu.Unlock()
	return sent
}

// short records frames the queue would not take, and now and then says
// what the queue looked like, since "the ring is full" and "the pool is
// empty" call for different fixes.
func (t *txQueue) short(n int) {
	t.g.Stats.TxRingFull.Add(uint64(n))
	if t.shorts++; t.shorts == 1 || t.shorts%100000 == 0 {
		t.g.log.Warn("transmit queue short", "refused", n, "times", t.shorts,
			"free_frames", t.q.NumFreeFrames(), "free_slots", t.q.NumFreeSlots(),
			"in_flight", t.q.NumInFlight(), "completed", t.q.NumCompleted())
	}
}

// failed records a transmit call the backend refused outright -- a closed
// queue, a frame the builder sized wrongly -- which otherwise looks exactly
// like a full ring: zero frames sent, and the traffic silently gone.
func (t *txQueue) failed(err error) {
	t.g.Stats.TxError.Add(1)
	if t.errs++; t.errs == 1 || t.errs%100000 == 0 {
		t.g.log.Error("transmit failed", "times", t.errs, "err", err)
	}
}

func (t *txQueue) buildTunnel(i int, frame []byte) int {
	g := t.g
	payload := t.bufs[i]
	n := ether.PutLink(frame, t.dst, g.mac, g.cfg.UnderlayVLAN, ether.TypeIPv4)
	if n+ether.IPv4HdrLen+ether.UDPHdrLen+len(payload) > len(frame) {
		return 0
	}
	t.id++
	n += ether.PutIPv4(frame[n:], g.uIP, t.dstIP, ether.ProtoUDP, ether.UDPHdrLen+len(payload), t.id)
	n += ether.PutUDP(frame[n:], g.cfg.ListenPort, t.port, len(payload))
	n += copy(frame[n:], payload)
	t.built++
	return pad(frame, n)
}

// sendLAN transmits IP packets onto the LAN VLAN, each to the MAC of its
// next hop. Packets with no route or no known neighbor are skipped and
// counted; the rest go out in one batch. The frames are built in order so
// the first unroutable packet does not end the batch: the builder walks
// past it.
func (t *txQueue) sendLAN(pkts [][]byte) int {
	t.mu.Lock()
	t.bufs, t.built = pkts, 0
	sent := 0
	for try := 0; len(t.bufs) > 0 && try < 4; try++ {
		t.built = 0
		n := t.send(len(t.bufs), t.buildL)
		t.g.Stats.TxRingFull.Add(uint64(t.built - n))
		sent += n
		if n == 0 {
			break
		}
	}
	if len(t.bufs) > 0 {
		t.short(len(t.bufs))
	}
	t.bufs = nil
	t.mu.Unlock()
	return sent
}

func (t *txQueue) buildLAN(_ int, frame []byte) int {
	g := t.g
	for len(t.bufs) > 0 {
		pkt := t.bufs[0]
		t.bufs = t.bufs[1:]
		h, ok := ether.ParseIPv4(pkt)
		if !ok {
			g.Stats.TxShort.Add(1)
			continue
		}
		next, ok := g.nextHop(h.Dst)
		if !ok {
			g.Stats.TxNoRoute.Add(1)
			continue
		}
		mac, ok := g.nb.Lookup(next)
		if !ok {
			g.Stats.TxNoNeighbor.Add(1)
			g.arp.want(next)
			continue
		}
		n := ether.PutLink(frame, mac, g.mac, g.cfg.LANVLAN, ether.TypeIPv4)
		if n+h.TotalLen > len(frame) {
			g.Stats.TxShort.Add(1)
			continue
		}
		n += copy(frame[n:], pkt[:h.TotalLen])
		t.built++
		return pad(frame, n)
	}
	return 0
}
