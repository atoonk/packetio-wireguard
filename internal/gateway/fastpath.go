//go:build !stockwg

package gateway

// The inline fast path: transport packets decrypted, and plaintext packets
// encrypted, in the DMA frame they arrived in, on the receive goroutine,
// and transmitted from there. wireguard-go still owns every handshake,
// timer, key and the configuration; it is told about each batch through
// FastPathReceived and FastPathSent. Anything the fast path cannot handle
// -- handshakes, unknown or retired keypairs, a peer without a keypair yet,
// an unresolved next hop -- takes the stock path exactly as before.
//
// Ownership stays with packetio's rules: a frame forwarded here goes out on
// the transmit queue that pairs with this receive queue, which only this
// goroutine drives and which carries nothing but frames from this
// goroutine's receive pool, so Reclaim -> Recycle brings every frame home.

import (
	"crypto/cipher"
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/atoonk/packetio"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/device"

	"github.com/atoonk/packetio-wireguard/internal/ether"
)

const (
	msgTransport   = 4
	wgHdrLen       = 16 // type, receiver index, counter
	wgTagLen       = chacha20poly1305.Overhead
	outerHdrLen    = ether.IPv4HdrLen + ether.UDPHdrLen
	paddingMultipl = 16
)

// fpKeypair is one entry of the receiver-index table: what is needed to
// decrypt and to attribute a packet, and nothing else.
type fpKeypair struct {
	kp   *device.Keypair
	peer *device.Peer
	recv cipher.AEAD
}

// fpTable maps our receiver index to the keypair, copy-on-write: the
// receive goroutines load a pointer and read an immutable map; the
// observer, which runs rarely and under wireguard-go's locks, copies.
type fpTable struct {
	m  atomic.Pointer[map[uint32]*fpKeypair]
	mu sync.Mutex
}

func newFPTable() *fpTable {
	t := &fpTable{}
	m := map[uint32]*fpKeypair{}
	t.m.Store(&m)
	return t
}

func (t *fpTable) lookup(idx uint32) *fpKeypair { return (*t.m.Load())[idx] }

func (t *fpTable) set(idx uint32, e *fpKeypair) {
	t.mu.Lock()
	defer t.mu.Unlock()
	old := *t.m.Load()
	m := make(map[uint32]*fpKeypair, len(old)+1)
	for k, v := range old {
		m[k] = v
	}
	if e == nil {
		delete(m, idx)
	} else {
		m[idx] = e
	}
	t.m.Store(&m)
}

// Observe is the KeypairObserver to install on the device before it is
// configured. Established and Promoted keypairs may receive; Retired ones
// are dropped at once.
func (g *Gateway) Observe(peer *device.Peer, kp *device.Keypair, ev device.KeypairEvent) {
	switch ev {
	case device.KeypairEstablished, device.KeypairPromoted:
		g.fp.set(kp.LocalIndex(), &fpKeypair{kp: kp, peer: peer, recv: kp.ReceiveCipher()})
	case device.KeypairRetired:
		g.fp.set(kp.LocalIndex(), nil)
	}
}

// peerFor is the cryptokey routing table with a per-queue cache in front of
// it: the table's RWMutex, taken per packet from several cores, was a tenth
// of a decrypting core at 8 queues. An entry is valid only for the
// configuration generation it was filled at, so a change to a peer's
// allowed IPs is never served from a cache.
func (g *Gateway) peerFor(rq *rxQueue, ip [4]byte) *device.Peer {
	gen := g.gen.Load()
	h := (uint32(ip[0])*31 + uint32(ip[1])*17 + uint32(ip[2])*7 + uint32(ip[3])) & 255
	e := &rq.look[h]
	if e.gen == gen && e.ip == ip && (e.peer != nil || gen != 0) {
		return e.peer
	}
	p := g.wg.LookupPeerByIP(netip.AddrFrom4(ip))
	*e = lookupEntry{ip: ip, gen: gen, peer: p}
	return p
}

// fpVerdict is what the fast path did with a frame.
type fpVerdict int

const (
	fpPunt      fpVerdict = iota // not for the fast path: take the stock path
	fpForwarded                  // queued for transmit; comes back through Reclaim
	fpDropped                    // counted; recycle now
)

// fpBatch accumulates one receive turn's fast-path work: frames to
// transmit, and the per-peer bookkeeping to report afterwards.
type fpBatch struct {
	out  []packetio.Desc // frames to transmit on this queue's transmit queue
	back []packetio.Desc // scratch for Reclaim
	rx   []fpRxAcct      // per keypair received this turn
	tx   []fpTxAcct      // per peer sent this turn
}

type fpRxAcct struct {
	e        *fpKeypair
	endpoint *Endpoint
	packets  int
	bytes    uint64
	anyData  bool
	pending  []fpRxPending
	counters []uint64
	ok       []bool
	expired  bool
}

// fpRxPending is a decrypted, authenticated packet waiting for the batch's
// replay check: where its plaintext is and what to do with it after.
type fpRxPending struct {
	d        packetio.Desc
	ep       *Endpoint // where the datagram came from, for roaming if it passes
	plainAbs int
	plainLen int // 0 for a keepalive
}

type fpTxAcct struct {
	peer    *device.Peer
	kp      *device.Keypair
	send    cipher.AEAD
	ep      *Endpoint
	mac     ether.MAC
	packets int
	bytes   uint64
	anyData bool
	dead    bool // no keypair or endpoint this turn: punt everything to this peer
	pending []fpPending
}

// fpPending is a plaintext waiting for its nonce: sealed and framed in
// fpFlush, once the batch's nonces are reserved in one go.
type fpPending struct {
	plainAbs, plainLen, pad, start int // in frame memory; start = where the outer frame will begin
}

// expired answers Keypair.Expired once per keypair per turn; time.Since per
// packet was a few percent of a saturated core.
func (b *fpBatch) expired(e *fpKeypair) bool {
	for i := range b.rx {
		if b.rx[i].e == e {
			return b.rx[i].expired
		}
	}
	x := e.kp.Expired()
	b.rx = append(b.rx, fpRxAcct{e: e, expired: x})
	return x
}

func (b *fpBatch) rxAcct(e *fpKeypair) *fpRxAcct {
	for i := range b.rx {
		if b.rx[i].e == e {
			return &b.rx[i]
		}
	}
	b.rx = append(b.rx, fpRxAcct{e: e})
	return &b.rx[len(b.rx)-1]
}

func (b *fpBatch) txAcct(peer *device.Peer) *fpTxAcct {
	for i := range b.tx {
		if b.tx[i].peer == peer {
			return &b.tx[i]
		}
	}
	b.tx = append(b.tx, fpTxAcct{peer: peer})
	return &b.tx[len(b.tx)-1]
}

func (b *fpBatch) reset() {
	for i := range b.tx {
		b.tx[i].pending = b.tx[i].pending[:0]
	}
	for i := range b.rx {
		b.rx[i].pending, b.rx[i].counters = b.rx[i].pending[:0], b.rx[i].counters[:0]
	}
	b.out, b.rx, b.tx = b.out[:0], b.rx[:0], b.tx[:0]
}

// fpDecrypt handles a transport message addressed to us. It returns true
// when the frame was consumed by the fast path (forwarded, or dropped and
// counted) and false when it must take the stock path. h and u are the
// outer headers; payload is the WireGuard message.
func (g *Gateway) fpDecrypt(rq *rxQueue, d packetio.Desc, f []byte, l ether.Link, h ether.IPv4, u ether.UDP, payload []byte) fpVerdict {
	if len(payload) < wgHdrLen+wgTagLen || binary.LittleEndian.Uint32(payload[0:4]) != msgTransport {
		return fpPunt // handshake, cookie, or junk: the stock path knows what to do
	}
	e := g.fp.lookup(binary.LittleEndian.Uint32(payload[4:8]))
	if e == nil || rq.fp.expired(e) {
		rq.st.FPPunted.Add(1)
		return fpPunt // unknown, retired or expired keypair: let the stock path judge
	}
	counter := binary.LittleEndian.Uint64(payload[8:16])
	var nonce [chacha20poly1305.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	content := payload[wgHdrLen:]
	plain, err := e.recv.Open(content[:0], nonce[:], content, nil)
	if err != nil {
		rq.st.FPAuthFail.Add(1)
		return fpDropped // it would fail the same way on the stock path
	}
	acct := rq.fp.rxAcct(e)
	// The source goes with the packet, not the batch: a peer roams only on a
	// packet that also passes the replay check (fpFlush), as upstream's
	// validTailPacket. Recording it here would let a replayed datagram, sent
	// from an attacker's address or MAC and correctly rejected, still move
	// the peer's endpoint. rq.endpoint caches, so this is a compare.
	acct.pending = append(acct.pending, fpRxPending{d: d, ep: rq.endpoint(h.Src, u.SrcPort, l.Src), plainAbs: int(d.Addr) + len(f) - len(content), plainLen: len(plain)})
	acct.counters = append(acct.counters, counter)
	return fpForwarded // held until the batch's replay check
}

// fpForward finishes one authenticated, replay-checked packet: keepalive
// accounting, source check, sink or LAN rewrite. It reports whether the
// frame is queued for transmit, and so comes back through Reclaim, or must
// be given back now.
func (g *Gateway) fpForward(rq *rxQueue, e *fpKeypair, acct *fpRxAcct, p fpRxPending) bool {
	acct.packets++
	if p.plainLen == 0 {
		rq.st.FPKeepalive.Add(1)
		return false
	}
	// Before the parse, as upstream sets dataPacketReceived before its own
	// header checks: this drives timersDataReceived, which schedules the
	// keepalive back to the peer. A peer whose packets all fail the checks
	// below is still a peer that is sending, and must still be answered, or
	// it re-handshakes on its own timer.
	acct.anyData = true
	mem := rq.fr.mem
	plain := mem[p.plainAbs : p.plainAbs+p.plainLen]
	ih, ok := ether.ParseIPv4(plain)
	if !ok || g.peerFor(rq, ih.Src) != e.peer {
		rq.st.FPUnallowed.Add(1)
		return false
	}
	acct.bytes += uint64(p.plainLen)
	if g.cfg.Sink {
		rq.st.SinkPackets.Add(1)
		rq.st.FPDecrypted.Add(1)
		return false
	}
	if ih.Dst == g.lIP {
		return g.fpEchoBack(rq, p, ih)
	}
	if rq.ktun.on {
		// The kernel routes it from here: one write, on this core.
		g.ktunPush(rq, plain)
		rq.st.FPDecrypted.Add(1)
		return false
	}
	next, ok := g.nextHop(ih.Dst)
	if !ok {
		rq.st.TxNoRoute.Add(1)
		return false
	}
	mac, ok := g.nb.Lookup(next)
	if !ok {
		rq.st.TxNoNeighbor.Add(1)
		g.arp.want(next)
		return false
	}
	hdr := ether.LinkLen(g.cfg.LANVLAN)
	start := p.plainAbs - hdr
	ether.PutLink(mem[start:], mac, g.mac, g.cfg.LANVLAN, ether.TypeIPv4)
	n := hdr + ih.TotalLen
	for n < ether.MinFrame {
		mem[start+n] = 0
		n++
	}
	rq.fp.out = append(rq.fp.out, packetio.Desc{Addr: uint64(start), Len: uint32(n)})
	rq.st.FPDecrypted.Add(1)
	return true
}

// fpEchoBack answers a packet the tunnel delivered to this gateway's own
// LAN address: the far side's "is the tunnel up" ping. The reply is built
// over the request in place, given a link header so it looks like a LAN
// frame, and handed to fpEncrypt, which routes it back to the peer that
// sent it. Anything else addressed to us is dropped and counted; there is
// nothing behind the address to deliver to.
func (g *Gateway) fpEchoBack(rq *rxQueue, p fpRxPending, ih ether.IPv4) bool {
	hdr := ether.LinkLen(g.cfg.LANVLAN)
	start := p.plainAbs - hdr
	f := rq.fr.mem[start : p.plainAbs+ih.TotalLen]
	ether.PutLink(f, g.mac, g.mac, g.cfg.LANVLAN, ether.TypeIPv4)
	if ih.TotalLen > g.cfg.MTU || !ether.EchoReply(f, hdr, ih) {
		rq.st.RxOther.Add(1)
		return false
	}
	rq.st.RxICMP.Add(1)
	rq.st.TxICMP.Add(1)
	l, _ := ether.ParseLink(f)
	ih.Src, ih.Dst = ih.Dst, ih.Src
	d := packetio.Desc{Addr: uint64(start), Len: uint32(len(f))}
	return g.fpEncrypt(rq, d, f, l, ih) == fpForwarded
}

// fpEncrypt handles a LAN packet bound for the tunnel: fpForwarded when the
// plaintext is held for the batch's nonces (fpSeal), fpDropped when there is
// nothing to do with it, fpPunt when it should go to the stock path -- which
// is also what starts a handshake when there is no keypair yet.
func (g *Gateway) fpEncrypt(rq *rxQueue, d packetio.Desc, f []byte, l ether.Link, h ether.IPv4) fpVerdict {
	peer := g.peerFor(rq, h.Dst)
	if peer == nil {
		rq.st.FPNoPeer.Add(1)
		return fpDropped // no peer owns the destination; the stock path would drop it
	}
	acct := rq.fp.txAcct(peer)
	if acct.dead {
		return fpPunt
	}
	if acct.kp == nil {
		acct.kp = peer.FastPathSendKeypair()
		ep, _ := peer.FastPathEndpoint().(*Endpoint)
		if acct.kp == nil || ep == nil {
			acct.dead = true
			rq.st.FPNoKeypair.Add(1)
			return fpPunt // stock path: it stages the packet and handshakes
		}
		mac := ep.mac
		if mac.IsZero() {
			m, ok := g.nb.Lookup(ep.ip)
			if !ok {
				g.arp.want(ep.ip)
				acct.dead = true
				rq.st.TxNoNeighbor.Add(1)
				return fpPunt
			}
			mac = m
		}
		acct.send, acct.ep, acct.mac = acct.kp.SendCipher(), ep, mac
	}
	// Room: the outer headers and 16 bytes of transport header go in front
	// of the plaintext, where the old link header and DPDK's headroom are;
	// padding and the tag go behind it. All of that lies outside the packet
	// slice f, so work on the frame memory with absolute offsets.
	base := int(d.Addr)
	plainAbs := base + l.Len
	plainLen := h.TotalLen
	pad := g.wg.PaddingSize(plainLen)
	front := ether.LinkLen(g.cfg.UnderlayVLAN) + outerHdrLen + wgHdrLen
	inFrame := int(d.Addr & uint64(rq.fr.size-1)) // where the packet starts within its frame
	if l.Len+plainLen+pad+wgTagLen > rq.fr.tailroom(d) || inFrame+l.Len-front < g.cfg.MinOffset {
		rq.st.FPNoRoom.Add(1)
		return fpPunt
	}
	acct.pending = append(acct.pending, fpPending{plainAbs: plainAbs, plainLen: plainLen, pad: pad, start: plainAbs - front})
	return fpForwarded
}

// fpFlush transmits the turn's frames and reports the batches to
// wireguard-go. The NIC frees transmit descriptors in blocks (ixgbe: 32 at
// a time), so a burst is often accepted only in part; completions are
// reclaimed and the remainder retried before anything is given up on.
// Frames the queue still would not take go back to the pool, and are not
// reported as sent.
func (g *Gateway) fpFlush(rq *rxQueue) {
	b := &rq.fp
	for i := range b.rx {
		a := &b.rx[i]
		if len(a.pending) == 0 {
			continue
		}
		if cap(a.ok) < len(a.counters) {
			a.ok = make([]bool, len(a.counters))
		}
		a.ok = a.ok[:len(a.counters)]
		validateCounters(a.e.kp, a.counters, a.ok)
		for j, p := range a.pending {
			if !a.ok[j] {
				rq.st.FPReplay.Add(1)
				rq.giveBack(p.d)
				continue
			}
			a.endpoint = p.ep // the last packet past the window, as upstream
			if !g.fpForward(rq, a.e, a, p) {
				rq.giveBack(p.d)
			}
		}
		a.pending, a.counters = a.pending[:0], a.counters[:0]
	}
	g.fpSeal(rq)
	if len(b.out) > 0 {
		out := b.out
		for try := 0; len(out) > 0 && try < 4; try++ {
			if try > 0 {
				g.fpReclaim(rq)
			}
			if rq.txShared != nil {
				rq.txShared.mu.Lock()
			}
			sent := rq.tx.Transmit(out)
			if rq.txShared != nil {
				rq.txShared.mu.Unlock()
			}
			out = out[sent:]
			if sent == 0 {
				break
			}
		}
		if len(out) > 0 {
			rq.st.TxRingFull.Add(uint64(len(out)))
			for _, d := range out {
				rq.giveBack(d)
			}
			// They were counted when built; take them back from the batch
			// with the most, which is the only one there is in practice.
			if len(b.tx) > 0 {
				m := 0
				for i := range b.tx {
					if b.tx[i].packets > b.tx[m].packets {
						m = i
					}
				}
				if b.tx[m].packets >= len(out) {
					b.tx[m].packets -= len(out)
				}
			}
		}
	}
	for i := range b.rx {
		a := &b.rx[i]
		a.e.peer.FastPathReceived(a.e.kp, a.endpoint, a.packets, a.bytes, a.anyData)
	}
	for i := range b.tx {
		a := &b.tx[i]
		if a.packets > 0 {
			a.peer.FastPathSent(a.packets, a.bytes, a.anyData)
		}
	}
	b.reset()
}

// fpSeal reserves the batch's nonces per peer in one compare-and-swap and
// seals and frames every pending plaintext. A reservation the peer refuses
// (budget exhausted, expired) drops that peer's packets for this turn; the
// stock path's handshake will follow.
func (g *Gateway) fpSeal(rq *rxQueue) {
	b := &rq.fp
	mem := rq.fr.mem
	for i := range b.tx {
		a := &b.tx[i]
		if len(a.pending) == 0 {
			continue
		}
		nonce, ok := a.kp.ReserveNonces(uint64(len(a.pending)))
		if !ok {
			rq.st.FPNoKeypair.Add(uint64(len(a.pending)))
			for _, p := range a.pending {
				rq.giveBack(packetio.Desc{Addr: uint64(p.start), Len: 1})
			}
			a.pending = a.pending[:0]
			continue
		}
		for _, p := range a.pending {
			for k := 0; k < p.pad; k++ {
				mem[p.plainAbs+p.plainLen+k] = 0
			}
			plain := mem[p.plainAbs : p.plainAbs+p.plainLen+p.pad : p.plainAbs+p.plainLen+p.pad+wgTagLen]
			// Before the seal: it encrypts in place, and the port choice reads
			// the inner headers.
			srcPort := rq.sprayPort(g, plain[:p.plainLen])
			var nb [chacha20poly1305.NonceSize]byte
			binary.LittleEndian.PutUint64(nb[4:], nonce)
			sealed := a.send.Seal(plain[:0], nb[:], plain, nil)
			start := p.start
			n := ether.PutLink(mem[start:], a.mac, g.mac, g.cfg.UnderlayVLAN, ether.TypeIPv4)
			rq.ipID++
			n += ether.PutIPv4(mem[start+n:], g.uIP, a.ep.ip, ether.ProtoUDP, ether.UDPHdrLen+wgHdrLen+len(sealed), rq.ipID)
			n += ether.PutUDP(mem[start+n:], srcPort, a.ep.port, wgHdrLen+len(sealed))
			binary.LittleEndian.PutUint32(mem[start+n:], msgTransport)
			binary.LittleEndian.PutUint32(mem[start+n+4:], a.kp.RemoteIndex())
			binary.LittleEndian.PutUint64(mem[start+n+8:], nonce)
			nonce++
			n += wgHdrLen + len(sealed)
			for n < ether.MinFrame {
				mem[start+n] = 0
				n++
			}
			b.out = append(b.out, packetio.Desc{Addr: uint64(start), Len: uint32(n)})
			a.packets++
			a.bytes += uint64(n)
		}
		a.anyData = true
		rq.st.FPEncrypted.Add(uint64(len(a.pending)))
		a.pending = a.pending[:0]
	}
}

// fpReclaim brings transmitted frames home. On a queue of our own every
// completed frame came from our receive pool. On a shared queue the stock
// path's frames complete here too, and those belong to the transmit pool:
// the ownership bitmap tells them apart, since only frames Receive handed
// us are set in it.
// sprayPort picks the outer UDP source port for one packet from this
// queue's share of the spray range: ListenPort+sprayFrom, +sprayN, ... By
// default the queue rotates through them per packet. With SprayByFlow the
// inner packet's flow chooses, so a flow keeps one outer 5-tuple and the
// peer's RSS keeps it on one queue.
func (rq *rxQueue) sprayPort(g *Gateway, inner []byte) uint16 {
	if g.ports <= 1 {
		return rq.srcPort
	}
	if !g.cfg.SprayByFlow {
		p := g.cfg.ListenPort + rq.sprayAt
		if rq.sprayAt += rq.sprayN; rq.sprayAt >= g.ports {
			rq.sprayAt = rq.sprayFrom
		}
		return p
	}
	n := (uint32(g.ports) - uint32(rq.sprayFrom) + uint32(rq.sprayN) - 1) / uint32(rq.sprayN)
	return g.cfg.ListenPort + rq.sprayFrom + uint16(flowHash(inner)%n)*rq.sprayN
}

// flowHash is a cheap hash of an IPv4 packet's 5-tuple, for choosing among a
// few dozen ports: two multiplications and a fold. Not XOR: swapped
// addresses and equal-XOR port pairs would collide, and the low bits, which
// pick the bucket, carry the least entropy. Anything that is not an
// unfragmented TCP/UDP packet hashes on addresses and protocol alone.
func flowHash(p []byte) uint32 {
	if len(p) < ether.IPv4HdrLen {
		return 0
	}
	addrs := uint64(binary.BigEndian.Uint32(p[12:16]))<<32 | uint64(binary.BigEndian.Uint32(p[16:20]))
	var ports uint64
	ihl := int(p[0]&0xf) * 4
	if (p[9] == ether.ProtoTCP || p[9] == ether.ProtoUDP) && p[6]&0x1f == 0 && p[7] == 0 && len(p) >= ihl+4 {
		ports = uint64(binary.BigEndian.Uint32(p[ihl : ihl+4]))
	}
	h := addrs*0x9e3779b97f4a7c15 ^ (ports|uint64(p[9])<<48)*0xc2b2ae3d27d4eb4f
	h ^= h >> 32
	return uint32(h)
}

func (g *Gateway) fpReclaim(rq *rxQueue) {
	b := &rq.fp
	if rq.txShared != nil {
		rq.txShared.mu.Lock()
	}
	b.back = rq.tx.Reclaim(rq.tx.NumInFlight(), b.back[:0])
	if t := rq.txShared; t != nil && len(t.orphans) > 0 {
		// Our frames the stock path completed (txQueue.send), held for us.
		b.back = append(b.back, t.orphans...)
		t.orphans = t.orphans[:0]
	}
	if len(b.back) > 0 && rq.owned != nil {
		ours := b.back[:0]
		var theirs []packetio.Desc
		for _, d := range b.back {
			if rq.ownsFrame(d) {
				ours = append(ours, d)
			} else {
				theirs = append(theirs, d)
			}
		}
		if len(theirs) > 0 {
			rq.tx.Free(theirs)
		}
		b.back = ours
	}
	if rq.txShared != nil {
		rq.txShared.mu.Unlock()
	}
	if len(b.back) > 0 {
		rq.q.Recycle(b.back)
	}
}
