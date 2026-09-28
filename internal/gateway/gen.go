package gateway

// A built-in traffic source and sink for rigs with no third machine: the
// encrypting peer generates plaintext packets as if they had arrived on the
// LAN, the decrypting peer counts and drops them instead of forwarding.
// What is measured is then exactly the tunnel: encrypt, wire, decrypt.
//
// Generated frames come from the transmit pool (Alloc) rather than the
// receive pool, so they are handed back with Free, never Recycle; the
// ownership bitmap keeps the two apart wherever frames come home.

import (
	"encoding/binary"
	"net/netip"

	"github.com/atoonk/packetio"

	"github.com/atoonk/packetio-wireguard/internal/ether"
)

// Gen describes the generator.
type Gen struct {
	PPS   uint64 // aggregate rate over all queues; 0 = as fast as the queues go
	Size  int    // wire frame size incl. the 4-byte FCS and the 4-byte tag, as wireblast counts it
	Flows int    // distinct destination addresses (cycled) within Dst
	Src   netip.Addr
	Dst   netip.Prefix
	Port  uint16 // UDP destination port; the source port cycles with the flow
}

// genState is one queue's share of the generator.
type genState struct {
	on      bool
	perTurn int     // how many to make per receive turn when unlimited
	rate    float64 // packets per nanosecond for this queue; 0 = unlimited
	credit  float64
	last    int64
	flow    int
	seq     uint16
	tmpl    []byte // the LAN frame to send, link header included
	ipOff   int
}

// genPlaceholder keeps the frame fields at fixed offsets: dst IP is patched
// per packet, everything else is constant.
func (g *Gateway) genInit(rq *rxQueue, i, nq int) {
	c := g.cfg.Gen
	if c == nil {
		return
	}
	st := &rq.gen
	st.on = true
	st.perTurn = Batch
	if c.PPS > 0 {
		st.rate = float64(c.PPS) / float64(nq) / 1e9
	}
	st.last = nanotime()
	st.flow = i
	// The frame: link header (as if from the LAN VLAN, from a made-up host),
	// IPv4, UDP, zero payload, sized to c.Size on the wire.
	ipLen := c.Size - 4 /*FCS*/ - ether.LinkLen(g.cfg.LANVLAN)
	if ipLen < ether.IPv4HdrLen+ether.UDPHdrLen {
		ipLen = ether.IPv4HdrLen + ether.UDPHdrLen
	}
	f := make([]byte, ether.LinkLen(g.cfg.LANVLAN)+ipLen)
	n := ether.PutLink(f, g.mac, ether.MAC{0x02, 0x67, 0x65, 0x6e, 0, byte(i)}, g.cfg.LANVLAN, ether.TypeIPv4)
	st.ipOff = n
	n += ether.PutIPv4(f[n:], c.Src.As4(), c.Dst.Addr().As4(), ether.ProtoUDP, ipLen-ether.IPv4HdrLen, 0)
	ether.PutUDP(f[n:], 1024, c.Port, ipLen-ether.IPv4HdrLen-ether.UDPHdrLen)
	st.tmpl = f
}

// generate makes this turn's packets, if any are due, and hands them to the
// fast path, or, with the fast path off, parks them in this queue's LAN ring
// exactly as a received LAN frame is parked, so wireguard-go's own pipeline
// picks them up through tun.Read. It runs on the receive goroutine, after
// the received burst, and takes its frames from that goroutine's transmit
// queue.
func (g *Gateway) generate(rq *rxQueue) {
	st := &rq.gen
	if !st.on || rq.tx == nil {
		return
	}
	want := st.perTurn
	if st.rate > 0 {
		now := nanotime()
		st.credit += float64(now-st.last) * st.rate
		st.last = now
		if st.credit > float64(2*Batch) {
			st.credit = float64(2 * Batch) // never burst more than two turns' worth
		}
		want = int(st.credit)
		if want > st.perTurn {
			want = st.perTurn
		}
		if want == 0 {
			return
		}
	}
	if !rq.fpOn {
		// The ring is the only place to put them; asking the pool for frames
		// it would have to hand straight back is waste. The rate limiter's
		// credit is spent on what was allocated, so a short turn here is
		// caught up on the next one.
		if room := rq.lan.room(); want > room {
			want = room
		}
		if want == 0 {
			return
		}
	}
	// Frames from the transmit pool, with the plaintext placed so the fast
	// path's headers fit in front of it: the same layout a received LAN
	// frame has, plus the room the receive path would have had.
	if rq.txShared != nil {
		rq.txShared.mu.Lock()
	}
	descs := rq.tx.Alloc(want)
	if rq.txShared != nil {
		rq.txShared.mu.Unlock()
	}
	c := g.cfg.Gen
	mem := rq.fr.mem
	made := 0
	for _, d := range descs {
		const spare = 48 // in front of the link header: the fast path reaches back 62 from the plaintext, the link header is 18
		start := int(d.Addr) + spare
		copy(mem[start:], st.tmpl)
		// Patch the flow: destination address within the prefix, source port.
		dst := c.Dst.Addr().As4()
		dst[3] += byte(st.flow % c.Flows)
		ip := mem[start+st.ipOff:]
		copy(ip[16:20], dst[:])
		binary.BigEndian.PutUint16(ip[20:22], 1024+uint16(st.flow%c.Flows))
		st.seq++
		binary.BigEndian.PutUint16(ip[4:6], st.seq)
		ip[10], ip[11] = 0, 0
		binary.BigEndian.PutUint16(ip[10:12], ether.Checksum(ip[:ether.IPv4HdrLen], 0))
		st.flow++
		fd := packetio.Desc{Addr: uint64(start), Len: uint32(len(st.tmpl))}
		f := mem[start : start+len(st.tmpl)]
		l, _ := ether.ParseLink(f)
		h, _ := ether.ParseIPv4(f[l.Len:])
		if rq.fpOn {
			switch g.fpEncrypt(rq, fd, f, l, h) {
			case fpForwarded:
				made++
			default:
				// No keypair yet, or no room: the stock path would need a
				// copy into the ring, which the fast path's own frames do
				// not need; drop and count.
				rq.giveBack(fd)
				rq.st.GenDropped.Add(1)
			}
			continue
		}
		// Stock path: park it for tun.Read, as classify parks a LAN frame.
		// The frame is the transmit pool's, and the ring's drain gives it
		// back there (giveBackAll), not to the receive pool.
		wasEmpty := rq.lan.pending() == 0
		if !rq.lan.push(parked{d: fd, off: uint16(l.Len), n: uint16(h.TotalLen)}) {
			rq.giveBack(fd)
			rq.st.GenDropped.Add(1)
			continue
		}
		made++
		if wasEmpty {
			select { // the reader may be blocked; a stale token is harmless
			case g.wake <- struct{}{}:
			default:
			}
		}
	}
	if st.rate > 0 {
		st.credit -= float64(len(descs))
	}
	rq.st.GenPackets.Add(uint64(made))
}
