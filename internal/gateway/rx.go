package gateway

import (
	"sync/atomic"

	"github.com/atoonk/packetio"
	"golang.zx2c4.com/wireguard/device"

	"github.com/atoonk/packetio-wireguard/internal/affinity"
	"github.com/atoonk/packetio-wireguard/internal/ether"
)

// rxQueue is one receive queue and the state of the goroutine that drives it.
type rxQueue struct {
	q                 packetio.RxQueue
	fr                frames
	cpu               int
	pinned            bool
	lan               ring             // LAN frames parked for tun.Read
	recycle           []packetio.Desc  // scratch: frames going back this call
	last              *Endpoint        // the previous packet's source, to share an Endpoint across a burst
	eps               [128]*Endpoint   // endpoints by source port, for spraying peers
	look              [256]lookupEntry // cryptokey-routing answers, keyed by address, valid for one configuration generation
	st                qStats
	tx                packetio.TxQueue // this goroutine's transmit queue: the fast path's, and where the generator allocates; nil when it needs neither
	txShared          *txQueue         // set when tx is also the stock path's: its mutex covers our use
	owned             []uint64         // bitmap of frames this receive queue has handed us: ours to Recycle
	fpOn              bool             // the inline fast path runs on this queue
	fp                fpBatch
	drained           []packetio.Desc  // scratch: frames the TUN reader has finished with
	free              []packetio.Desc  // scratch: frames going back to the transmit pool
	one               [1]packetio.Desc // scratch for the single-frame giveBack, so it allocates nothing
	ipID              uint16
	srcPort           uint16 // the UDP source port this queue's fast path sends from
	sprayFrom, sprayN uint16 // spray: this queue rotates over ports ListenPort+sprayFrom, +sprayN, ...
	sprayAt           uint16
	gen               genState
	ktun              ktunState
	lastAt            int64 // when receive last ran, for the gap statistics
}

func newRxQueue(q packetio.RxQueue, cpu int, srcPort uint16) *rxQueue {
	return &rxQueue{q: q, fr: newFrames(q.Region()), cpu: cpu, srcPort: srcPort, recycle: make([]packetio.Desc, 0, Batch+ringSize)}
}

// receive is one turn of the receive cycle for queue i, run by the
// wireguard-go goroutine that owns that queue. Tunnel datagrams are copied
// into packets; everything else is handled here. It returns how many
// datagrams it delivered, possibly zero.
func (g *Gateway) receive(rq *rxQueue, packets [][]byte, sizes []int, eps []Endpointer) int {
	if !rq.pinned {
		rq.pinned = true
		if err := affinity.Pin(rq.cpu); err != nil {
			g.log.Warn("pin receive goroutine", "cpu", rq.cpu, "err", err)
		}
	}
	if g.cfg.Diagnostics {
		gap(&rq.lastAt, &rq.st.RxMaxGapNs, &rq.st.RxGaps)
	}
	// Frames the TUN reader has finished with go back first, then the ring
	// is topped up, then the burst is taken. They do not all come from the
	// receive pool: with the fast path off the generator parks frames of its
	// own in the ring, and those belong to the transmit pool, so they are
	// sorted by owner on the way home.
	rq.drained = rq.lan.drain(rq.drained[:0])
	if len(rq.drained) > 0 {
		rq.giveBackAll(rq.drained)
	}
	if len(rq.recycle) > 0 {
		rq.q.Recycle(rq.recycle)
		rq.recycle = rq.recycle[:0]
	}
	if rq.fpOn {
		g.fpReclaim(rq)
	}
	rq.q.Fill(rq.q.NumFreeFillSlots())
	max := Batch
	if len(packets) < max {
		max = len(packets)
	}
	descs := rq.q.Receive(max)
	if rq.owned != nil {
		// Atomic: the stock path reads the bitmap under the shared queue's
		// lock (reclaimShared) while this goroutine sets bits for new frames
		// in the same words. Shared mode only, so the dedicated path pays
		// nothing.
		for _, d := range descs {
			ix := d.Addr >> rq.fr.shift
			atomic.OrUint64(&rq.owned[ix/64], 1<<(ix%64))
		}
	}
	n := 0
	for i, d := range descs {
		// The frames arrived by DMA and are cold; touch the first two cache
		// lines of the frame four ahead, so the miss overlaps the work on
		// this one.
		if i+4 < len(descs) {
			prefetch(rq.fr.mem[descs[i+4].Addr:])
			prefetch(rq.fr.mem[descs[i+4].Addr+64:])
		}
		if g.classify(rq, d, packets, sizes, eps, &n) {
			rq.recycle = append(rq.recycle, d)
		}
	}
	g.generate(rq)
	g.ktunPull(rq)
	if rq.fpOn {
		g.fpFlush(rq)
	}
	if len(rq.recycle) > 0 {
		rq.q.Recycle(rq.recycle)
		rq.recycle = rq.recycle[:0]
	}
	rq.st.RxFrames.Add(uint64(len(descs)))
	return n
}

// lookupEntry caches one cryptokey-routing answer.
type lookupEntry struct {
	ip   [4]byte
	gen  uint32
	peer *device.Peer
}

// giveBack returns a frame this goroutine is done with to the pool it came
// from: the receive pool if Receive handed it to us, the transmit pool
// otherwise (a generated frame, or the stock path's on a shared queue).
func (rq *rxQueue) giveBack(d packetio.Desc) {
	if rq.owned == nil || rq.ownsFrame(d) {
		rq.recycle = append(rq.recycle, d)
		return
	}
	rq.one[0] = d
	rq.freeToTx(rq.one[:])
}

// giveBackAll is giveBack for a batch: one Recycle and one Free rather than
// a lock and a call per frame.
func (rq *rxQueue) giveBackAll(ds []packetio.Desc) {
	if rq.owned == nil {
		rq.recycle = append(rq.recycle, ds...)
		return
	}
	rq.free = rq.free[:0]
	for _, d := range ds {
		if rq.ownsFrame(d) {
			rq.recycle = append(rq.recycle, d)
		} else {
			rq.free = append(rq.free, d)
		}
	}
	rq.freeToTx(rq.free)
}

// freeToTx returns frames to the transmit pool, which is unsynchronised; on
// a shared queue the stock path frees to it under the queue's lock.
func (rq *rxQueue) freeToTx(ds []packetio.Desc) {
	if len(ds) == 0 {
		return
	}
	if rq.txShared != nil {
		rq.txShared.mu.Lock()
	}
	rq.tx.Free(ds)
	if rq.txShared != nil {
		rq.txShared.mu.Unlock()
	}
}

// ownsFrame reports whether Receive ever handed this goroutine the frame,
// which is to say it belongs to the receive pool. Bits are never cleared: a
// frame's pool is for life.
func (rq *rxQueue) ownsFrame(d packetio.Desc) bool {
	ix := d.Addr >> rq.fr.shift
	return atomic.LoadUint64(&rq.owned[ix/64])&(1<<(ix%64)) != 0
}

// classify handles one received frame. It reports whether the frame is
// finished with and may be recycled now (false means it was parked).
func (g *Gateway) classify(rq *rxQueue, d packetio.Desc, packets [][]byte, sizes []int, eps []Endpointer, n *int) bool {
	f := rq.fr.packet(d)
	l, ok := ether.ParseLink(f)
	if !ok || l.Src == g.mac {
		rq.st.RxOther.Add(1)
		rq.st.OtherSelf.Add(1)
		return true
	}
	switch l.EtherType {
	case ether.TypeARP:
		rq.st.RxARP.Add(1)
		g.handleARP(rq, l, f[l.Len:])
		return true
	case ether.TypeIPv4:
	default:
		rq.st.RxOther.Add(1)
		rq.st.OtherType.Add(1)
		return true
	}
	h, ok := ether.ParseIPv4(f[l.Len:])
	if !ok {
		rq.st.RxTruncated.Add(1)
		return true
	}
	// The underlay and the LAN may be one VLAN (a gateway with a single tagged
	// port, as on the rig). A frame on it is the tunnel's only if it is
	// addressed to our underlay IP; anything else on that VLAN is LAN traffic
	// and falls through to the LAN case below.
	shared := g.cfg.UnderlayVLAN == g.cfg.LANVLAN
	switch {
	case l.VLAN == g.cfg.UnderlayVLAN && (h.Dst == g.uIP || !shared):
		if h.Dst != g.uIP {
			rq.st.RxOther.Add(1)
			rq.st.OtherUnderlayDst.Add(1)
			return true
		}
		switch h.Proto {
		case ether.ProtoUDP:
			u, ok := ether.ParseUDP(f[l.Len+h.HdrLen : l.Len+h.TotalLen])
			if !ok || u.DstPort-g.cfg.ListenPort >= g.ports {
				rq.st.RxOther.Add(1)
				return true
			}
			payload := f[l.Len+h.HdrLen+ether.UDPHdrLen : l.Len+h.HdrLen+u.Len]
			if rq.fpOn {
				switch g.fpDecrypt(rq, d, f, l, h, u, payload) {
				case fpForwarded:
					return false // out through Reclaim
				case fpDropped:
					return true
				}
			}
			if len(payload) > len(packets[*n]) {
				rq.st.RxTruncated.Add(1)
				return true
			}
			sizes[*n] = copy(packets[*n], payload)
			eps[*n] = rq.endpoint(h.Src, u.SrcPort, l.Src)
			*n++
			rq.st.RxTunnel.Add(1)
			return true
		case ether.ProtoICMP:
			g.echo(rq, f, l, h)
			return true
		}
		rq.st.RxOther.Add(1)
		return true
	case l.VLAN == g.cfg.LANVLAN:
		if h.Dst == g.lIP {
			if h.Proto == ether.ProtoICMP {
				g.echo(rq, f, l, h)
			} else {
				rq.st.RxOther.Add(1)
			}
			return true
		}
		if l.Dst != g.mac {
			rq.st.RxOther.Add(1) // broadcast, multicast, or someone else's unicast on a shared segment
			rq.st.OtherLANNotOurs.Add(1)
			return true
		}
		if h.TotalLen > g.cfg.MTU {
			rq.st.LANOversize.Add(1)
			return true
		}
		if rq.fpOn {
			switch g.fpEncrypt(rq, d, f, l, h) {
			case fpForwarded:
				return false
			case fpDropped:
				return true
			}
		}
		wasEmpty := rq.lan.pending() == 0
		if !rq.lan.push(parked{d: d, off: uint16(l.Len), n: uint16(h.TotalLen)}) {
			rq.st.LANRingFull.Add(1)
			return true
		}
		rq.st.RxLAN.Add(1)
		if wasEmpty {
			select { // the reader may be blocked; a stale token is harmless
			case g.wake <- struct{}{}:
			default:
			}
		}
		return false
	}
	rq.st.RxOther.Add(1)
	rq.st.OtherVLAN.Add(1)
	return true
}

// endpoint returns an Endpoint for a tunnel datagram's source, reusing the
// previous one when a burst comes from one peer, which is the normal case.
func (rq *rxQueue) endpoint(ip [4]byte, port uint16, mac ether.MAC) *Endpoint {
	if e := rq.last; e != nil && e.ip == ip && e.port == port && e.mac == mac {
		return e
	}
	// With spraying the port rotates per packet; keep one Endpoint per port
	// seen from the current peer address rather than allocating per packet.
	slot := int(port) % len(rq.eps)
	if e := rq.eps[slot]; e != nil && e.ip == ip && e.port == port && e.mac == mac {
		rq.last = e
		return e
	}
	e := &Endpoint{ip: ip, port: port, mac: mac}
	rq.eps[slot] = e
	rq.last = e
	return e
}

// echo answers an ICMP echo request addressed to one of our own addresses,
// so the rig can be pinged. The reply is built into a fresh transmit frame
// (a received frame never crosses to a transmit queue) on the transmit
// queue that pairs with this receive queue.
func (g *Gateway) echo(rq *rxQueue, f []byte, l ether.Link, h ether.IPv4) {
	rq.st.RxICMP.Add(1)
	src := f[:l.Len+h.TotalLen]
	tq := g.tx[len(g.tx)-1]
	tq.mu.Lock()
	defer tq.mu.Unlock()
	tq.send(1, func(_ int, frame []byte) int {
		n := copy(frame, src)
		if !ether.EchoReply(frame[:n], l.Len, h) {
			return 0
		}
		rq.st.TxICMP.Add(1)
		return pad(frame, n)
	})
}

// handleARP learns from replies and requests, and answers requests for our
// address on the VLAN the request arrived on.
func (g *Gateway) handleARP(rq *rxQueue, l ether.Link, body []byte) {
	a, ok := ether.ParseARP(body)
	if !ok {
		return
	}
	mine, ok := g.addrOn(l.VLAN)
	if !ok {
		return
	}
	// Learn the sender when it names us (a request for us, or a reply to
	// us): the same two cases a kernel learns from. The sender must be on
	// the prefix of the VLAN the frame arrived on -- one table serves both
	// VLANs, so without that check a host on the LAN could claim the
	// tunnel peer's underlay address and have handshakes sent to its MAC.
	if a.TargetIP == mine && !a.SenderMAC.IsMulticast() && !a.SenderMAC.IsZero() {
		if v, ok := g.vlanFor(a.SenderIP); ok && v == l.VLAN {
			g.nb.Learn(a.SenderIP, a.SenderMAC)
		} else {
			rq.st.OtherVLAN.Add(1)
		}
	}
	if a.Op == ether.ARPRequest && a.TargetIP == mine {
		g.sendARP(l.VLAN, ether.ARP{Op: ether.ARPReply, SenderMAC: g.mac, SenderIP: mine,
			TargetMAC: a.SenderMAC, TargetIP: a.SenderIP}, a.SenderMAC)
	}
}

// addrOn is our address on a VLAN.
func (g *Gateway) addrOn(vlan uint16) ([4]byte, bool) {
	switch vlan {
	case g.cfg.UnderlayVLAN:
		return g.uIP, true
	case g.cfg.LANVLAN:
		return g.lIP, true
	}
	return [4]byte{}, false
}

// sendARP transmits one ARP message on transmit queue 0.
func (g *Gateway) sendARP(vlan uint16, a ether.ARP, dst ether.MAC) {
	tq := g.tx[0]
	tq.mu.Lock()
	defer tq.mu.Unlock()
	tq.send(1, func(_ int, frame []byte) int {
		n := ether.PutLink(frame, dst, g.mac, vlan, ether.TypeARP)
		n += ether.PutARP(frame[n:], a)
		g.Stats.TxARP.Add(1)
		return pad(frame, n)
	})
}

// pad grows a frame to the Ethernet minimum with zeros.
func pad(frame []byte, n int) int {
	for n < ether.MinFrame {
		frame[n] = 0
		n++
	}
	return n
}
