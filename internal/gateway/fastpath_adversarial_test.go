//go:build !stockwg

package gateway

// Adversarial tests for the caller's side of the fast-path API, written for
// the security review of patch 0001. The fork's API is safe only if this
// package keeps its rules; these tests attack the rules from the two places
// an attacker stands: the underlay (authentic packets with hostile
// plaintext, copies of captured datagrams) and the LAN (frames placed to
// make the encryptor write outside its frame, ports outside the accepted
// range).

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"

	"github.com/atoonk/packetio"
	"github.com/atoonk/packetio-wireguard/internal/ether"
	"github.com/atoonk/packetio-wireguard/internal/neigh"
)

// advRig is a gateway with one receive queue over plain memory, fed
// authentic transport packets from the session's far peer.
type advRig struct {
	s   *fpSession
	g   *Gateway
	rq  *rxQueue
	our [4]byte // our underlay address, what the far peer sends to
	far [4]byte // the far peer's underlay address
	mac ether.MAC
}

func newAdvRig(t *testing.T, sink bool) *advRig {
	t.Helper()
	s := newFPSession(t)
	r := &advRig{s: s, our: [4]byte{10, 131, 0, 2}, far: [4]byte{10, 131, 0, 3}, mac: ether.MAC{0x02, 0, 0, 0, 0, 0xaa}}
	r.g = &Gateway{
		cfg: Config{Sink: sink, MTU: 1420, MinOffset: 192, ListenPort: 51820},
		fp:  newFPTable(), wg: s.devs[0], nb: neigh.New(), log: slog.Default(),
		uIP: r.our, lIP: [4]byte{10, 154, 0, 2}, mac: ether.MAC{0x02, 0, 0, 0, 0, 0x01}, ports: 1,
	}
	r.g.Observe(s.peer, s.kpA, device.KeypairEstablished)
	r.rq = &rxQueue{fr: frames{mem: make([]byte, 16*4096), shift: 12, size: 4096}, fpOn: true}
	return r
}

// deliver hands one authentic transport message carrying plain to the fast
// path in frame slot i, from the given source MAC, and returns its verdict.
// The batch is not flushed; call flush.
func (r *advRig) deliver(t *testing.T, i int, plain []byte, src ether.MAC) fpVerdict {
	t.Helper()
	msg := r.s.transport(t, plain)
	base := i*4096 + 192
	b := r.rq.fr.mem[base:]
	n := ether.PutLink(b, r.g.mac, src, 0, ether.TypeIPv4)
	n += ether.PutIPv4(b[n:], r.far, r.our, ether.ProtoUDP, ether.UDPHdrLen+len(msg), 1)
	n += ether.PutUDP(b[n:], 51820, 51820, len(msg))
	n += copy(b[n:], msg)
	d := packetio.Desc{Addr: uint64(base), Len: uint32(n)}
	f := r.rq.fr.packet(d)
	l, _ := ether.ParseLink(f)
	h, _ := ether.ParseIPv4(f[l.Len:])
	u, _ := ether.ParseUDP(f[l.Len+h.HdrLen : l.Len+h.TotalLen])
	return r.g.fpDecrypt(r.rq, d, f, l, h, u, f[l.Len+h.HdrLen+ether.UDPHdrLen:l.Len+h.HdrLen+u.Len])
}

func (r *advRig) flush() { r.g.fpFlush(r.rq) }

// ipv4UDP builds a plaintext IPv4/UDP packet from src to dst with n payload bytes.
func ipv4UDP(src, dst [4]byte, n int) []byte {
	p := make([]byte, ether.IPv4HdrLen+ether.UDPHdrLen+n)
	ether.PutIPv4(p, src, dst, ether.ProtoUDP, ether.UDPHdrLen+n, 7)
	ether.PutUDP(p[ether.IPv4HdrLen:], 4000, 9000, n)
	return p
}

// icmpEcho builds a plaintext ICMP echo request (type 8) from src to dst.
func icmpEcho(src, dst [4]byte, typ byte) []byte {
	const icmpLen = 8 + 16
	p := make([]byte, ether.IPv4HdrLen+icmpLen)
	ether.PutIPv4(p, src, dst, ether.ProtoICMP, icmpLen, 9)
	ic := p[ether.IPv4HdrLen:]
	ic[0], ic[1] = typ, 0
	binary.BigEndian.PutUint16(ic[4:6], 0x1234)
	binary.BigEndian.PutUint16(ic[6:8], 1)
	binary.BigEndian.PutUint16(ic[2:4], ether.Checksum(ic, 0))
	return p
}

// P5. The far peer is authentic, but authentication says who sent the
// packet, not which addresses it may speak for. A decrypted packet whose
// inner source is not in the sending peer's allowed IPs must be dropped:
// not an address nobody owns, not the gateway's own, and not another
// peer's, which is the one that turns a compromised peer into a spoofer
// for every prefix behind the gateway.
func TestFastPathDropsPlaintextFromDisallowedSource(t *testing.T) {
	r := newAdvRig(t, true)
	// A third peer on dev0 owning 1.0.0.3, so that address is allowed --
	// for someone else.
	var k3 [32]byte
	rand.Read(k3[:])
	p3, _ := curve25519.X25519(k3[:], curve25519.Basepoint)
	if err := r.s.devs[0].IpcSet(fmt.Sprintf("public_key=%x\nallowed_ip=1.0.0.3/32\n", p3)); err != nil {
		t.Fatal(err)
	}
	r.g.ConfigChanged()

	legit := ether.MAC{0x02, 0, 0, 0, 0, 0xaa}
	cases := []struct {
		name string
		src  [4]byte
	}{
		{"nobody's address", [4]byte{1, 0, 0, 9}},
		{"the gateway's own LAN address", r.g.lIP},
		{"another peer's allowed address", [4]byte{1, 0, 0, 3}},
	}
	for i, c := range cases {
		if v := r.deliver(t, i, ipv4UDP(c.src, [4]byte{1, 0, 0, 1}, 32), legit); v != fpForwarded {
			t.Fatalf("%s: decrypt verdict %v, want held for the batch", c.name, v)
		}
	}
	// And one honest packet, so the test proves the rig forwards at all.
	if v := r.deliver(t, 3, ipv4UDP([4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 1}, 32), legit); v != fpForwarded {
		t.Fatalf("honest packet: verdict %v", v)
	}
	r.flush()

	if got := r.rq.st.FPUnallowed.Load(); got != uint64(len(cases)) {
		t.Fatalf("%d packets dropped as unallowed, want %d", got, len(cases))
	}
	if got := r.rq.st.SinkPackets.Load(); got != 1 {
		t.Fatalf("%d packets reached the sink, want exactly the honest one", got)
	}
	if got := r.rq.st.FPReplay.Load(); got != 0 {
		t.Fatalf("%d replays counted, want none", got)
	}
}

// P5. Every length and header the plaintext parser must refuse, each in an
// authentic packet. Upstream checks IPv4 header length, total length in
// both directions and the version; the fast path relies on ether.ParseIPv4
// for the same. Nothing here may panic, forward, or reach the sink.
func TestFastPathDropsMalformedPlaintext(t *testing.T) {
	r := newAdvRig(t, true)
	legit := ether.MAC{0x02, 0, 0, 0, 0, 0xaa}
	good := ipv4UDP([4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 1}, 20)

	mut := func(f func(p []byte)) []byte {
		p := append([]byte(nil), good...)
		f(p)
		return p
	}
	cases := []struct {
		name  string
		plain []byte
	}{
		{"one byte", []byte{0x45}},
		{"nineteen bytes", good[:19]},
		{"IP version 6", mut(func(p []byte) { p[0] = 0x65 })},
		{"IHL below five words", mut(func(p []byte) { p[0] = 0x44 })},
		{"total length past the plaintext", mut(func(p []byte) { binary.BigEndian.PutUint16(p[2:4], 4000) })},
		{"total length below a header", mut(func(p []byte) { binary.BigEndian.PutUint16(p[2:4], 10) })},
		{"all zero", make([]byte, 48)},
	}
	for i, c := range cases {
		if v := r.deliver(t, i, c.plain, legit); v != fpForwarded {
			t.Fatalf("%s: decrypt verdict %v, want held for the batch", c.name, v)
		}
	}
	// A keepalive is the one empty plaintext that is legitimate.
	if v := r.deliver(t, len(cases), nil, legit); v != fpForwarded {
		t.Fatalf("keepalive: verdict %v", v)
	}
	r.flush()

	if got := r.rq.st.FPUnallowed.Load(); got != uint64(len(cases)) {
		t.Fatalf("%d malformed packets dropped, want %d", got, len(cases))
	}
	if got := r.rq.st.FPKeepalive.Load(); got != 1 {
		t.Fatalf("%d keepalives counted, want 1", got)
	}
	if got := r.rq.st.SinkPackets.Load(); got != 0 {
		t.Fatalf("%d malformed packets reached the sink", got)
	}
}

// P5. A packet the tunnel delivers to the gateway's own LAN address is
// answered only if it is an ICMP echo request, only after the source check
// (so a peer cannot use the gateway to bounce packets to addresses it may
// not speak for), and the answer is routed back to the peer that sent it
// rather than onto the LAN.
func TestFastPathEchoAnswersOnlyTheAuthenticatedPeer(t *testing.T) {
	legit := ether.MAC{0x02, 0, 0, 0, 0, 0xaa}
	ok, bad := [4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 9}

	t.Run("echo request from an allowed source is answered to the peer", func(t *testing.T) {
		r := newAdvRig(t, false)
		if v := r.deliver(t, 0, icmpEcho(ok, r.g.lIP, 8), legit); v != fpForwarded {
			t.Fatalf("verdict %v", v)
		}
		r.flush()
		if r.rq.st.RxICMP.Load() != 1 || r.rq.st.TxICMP.Load() != 1 {
			t.Fatalf("rx_icmp=%d tx_icmp=%d, want 1/1", r.rq.st.RxICMP.Load(), r.rq.st.TxICMP.Load())
		}
		// The reply went to fpEncrypt for the peer; with no *Endpoint in
		// this rig it punts there, which is the tunnel side, not the LAN.
		if r.rq.st.FPNoKeypair.Load() != 1 {
			t.Fatalf("reply did not take the tunnel path (fp_nokey=%d)", r.rq.st.FPNoKeypair.Load())
		}
		if r.rq.st.TxNoRoute.Load() != 0 || r.rq.st.TxNoNeighbor.Load() != 0 {
			t.Fatal("reply was routed onto the LAN")
		}
	})
	t.Run("echo request from a disallowed source is dropped before it is answered", func(t *testing.T) {
		r := newAdvRig(t, false)
		if v := r.deliver(t, 0, icmpEcho(bad, r.g.lIP, 8), legit); v != fpForwarded {
			t.Fatalf("verdict %v", v)
		}
		r.flush()
		if r.rq.st.FPUnallowed.Load() != 1 {
			t.Fatalf("fp_unallowed=%d, want 1", r.rq.st.FPUnallowed.Load())
		}
		if r.rq.st.RxICMP.Load() != 0 || r.rq.st.TxICMP.Load() != 0 {
			t.Fatal("an echo from a disallowed source was answered")
		}
	})
	t.Run("anything else to our address is dropped", func(t *testing.T) {
		r := newAdvRig(t, false)
		if v := r.deliver(t, 0, icmpEcho(ok, r.g.lIP, 0), legit); v != fpForwarded { // an echo reply, not a request
			t.Fatalf("verdict %v", v)
		}
		if v := r.deliver(t, 1, ipv4UDP(ok, r.g.lIP, 16), legit); v != fpForwarded {
			t.Fatalf("verdict %v", v)
		}
		r.flush()
		if r.rq.st.RxOther.Load() != 2 {
			t.Fatalf("rx_other=%d, want 2", r.rq.st.RxOther.Load())
		}
		if r.rq.st.TxICMP.Load() != 0 || r.rq.st.TxNoRoute.Load() != 0 {
			t.Fatal("a non-echo packet to our address was answered or forwarded")
		}
	})
}

// P5, the encrypt side. The seal writes the outer headers in front of the
// plaintext and the padding and tag behind it, all outside the packet slice
// the LAN handed us. A LAN frame placed at the end of its DMA frame, or at
// its very start on a backend that reserves headroom, must be refused
// before anything is written, and handed to the stock path instead.
func TestFastPathEncryptRefusesFramesWithoutRoom(t *testing.T) {
	r := newAdvRig(t, false)
	// The keypair and endpoint are pre-resolved, as they would be after the
	// first packet of a batch, so the room check is what decides.
	r.rq.fp.tx = append(r.rq.fp.tx, fpTxAcct{peer: r.s.peer, kp: r.s.kpA, send: r.s.kpA.SendCipher(),
		ep: &Endpoint{ip: r.far, port: 51820}, mac: ether.MAC{0x02, 0, 0, 0, 0, 0xbb}})

	place := func(frame, inFrame int) fpVerdict {
		base := frame*4096 + inFrame
		b := r.rq.fr.mem[base:]
		n := ether.PutLink(b, r.g.mac, ether.MAC{0x02, 0, 0, 0, 0, 0xcc}, 0, ether.TypeIPv4)
		n += copy(b[n:], ipv4UDP([4]byte{10, 9, 9, 9}, [4]byte{1, 0, 0, 2}, 100)) // 128-byte packet, to a peer
		d := packetio.Desc{Addr: uint64(base), Len: uint32(n)}
		f := r.rq.fr.packet(d)
		l, _ := ether.ParseLink(f)
		h, _ := ether.ParseIPv4(f[l.Len:])
		return r.g.fpEncrypt(r.rq, d, f, l, h)
	}
	before := r.rq.st.FPNoRoom.Load()
	if v := place(0, 1024); v != fpForwarded {
		t.Fatalf("a frame with room on both sides: verdict %v", v)
	}
	if v := place(1, 3950); v != fpPunt { // 146 bytes of tailroom for a 158-byte result
		t.Fatalf("a frame whose tag would run off the end: verdict %v, want punt", v)
	}
	if v := place(2, 200); v != fpPunt { // 14 bytes of link header, 58 needed in front, floor at 192
		t.Fatalf("a frame whose outer headers would run into the headroom: verdict %v, want punt", v)
	}
	if got := r.rq.st.FPNoRoom.Load() - before; got != 2 {
		t.Fatalf("fp_noroom rose by %d, want 2", got)
	}
	if got := len(r.rq.fp.tx[0].pending); got != 1 {
		t.Fatalf("%d frames pending for the seal, want only the one with room", got)
	}
	r.rq.fp.reset()
}

// The classifier admits tunnel datagrams on ListenPort..ListenPort+Spray-1
// and nothing else. One past the range and one below it must never reach
// the decryptor, whatever they carry.
func TestClassifyRejectsPortsOutsideTheSprayRange(t *testing.T) {
	r := newAdvRig(t, true)
	r.g.ports = 64
	r.g.cfg.LANVLAN = 1 // keep the untagged frames on the underlay side of classify

	feed := func(frame int, dstPort uint16) {
		base := frame*4096 + 192
		b := r.rq.fr.mem[base:]
		payload := make([]byte, 48) // a plausible transport message with an unknown index
		binary.LittleEndian.PutUint32(payload[0:4], msgTransport)
		binary.LittleEndian.PutUint32(payload[4:8], 0xdeadbeef)
		n := ether.PutLink(b, r.g.mac, ether.MAC{0x02, 0, 0, 0, 0, 0xaa}, 0, ether.TypeIPv4)
		n += ether.PutIPv4(b[n:], r.far, r.our, ether.ProtoUDP, ether.UDPHdrLen+len(payload), 1)
		n += ether.PutUDP(b[n:], 40000, dstPort, len(payload))
		n += copy(b[n:], payload)
		d := packetio.Desc{Addr: uint64(base), Len: uint32(n)}
		packets, sizes, eps := [][]byte{make([]byte, 2048)}, make([]int, 1), make([]Endpointer, 1)
		var got int
		r.g.classify(r.rq, d, packets, sizes, eps, &got)
	}
	feed(0, 51820)    // first port of the range
	feed(1, 51820+63) // last port of the range
	if got := r.rq.st.FPPunted.Load(); got != 2 {
		t.Fatalf("in-range ports reached the decryptor %d times, want 2", got)
	}
	feed(2, 51820+64) // one past
	feed(3, 51819)    // one below
	if got := r.rq.st.FPPunted.Load(); got != 2 {
		t.Fatalf("an out-of-range port reached the decryptor (fp_punt=%d)", got)
	}
	if got := r.rq.st.RxOther.Load(); got != 2 {
		t.Fatalf("rx_other=%d, want the 2 out-of-range datagrams", got)
	}
}

// P5. When a copy of an authentic datagram and the original are in the
// same batch, whichever the replay check accepts sets the endpoint, and it
// accepts the first it sees. That is WireGuard's roaming rule, upstream
// included: the first authenticated arrival of a counter wins. The rule
// the fast path must keep is the narrower one, that the REJECTED copy never
// moves the endpoint, in either order.
func TestReplayInTheSameBatchNeverMovesTheEndpoint(t *testing.T) {
	legit := ether.MAC{0x02, 0, 0, 0, 0, 0xaa}
	attacker := ether.MAC{0x02, 0, 0, 0, 0, 0xbb}
	plain := ipv4UDP([4]byte{1, 0, 0, 2}, [4]byte{1, 0, 0, 1}, 16)

	for _, order := range []struct {
		name        string
		first, then ether.MAC
		want        ether.MAC
	}{
		{"original then copy", legit, attacker, legit},
		{"copy then original", attacker, legit, attacker},
	} {
		t.Run(order.name, func(t *testing.T) {
			r := newAdvRig(t, true)
			msg := r.s.transport(t, plain)
			put := func(i int, src ether.MAC) fpVerdict {
				base := i*4096 + 192
				b := r.rq.fr.mem[base:]
				n := ether.PutLink(b, r.g.mac, src, 0, ether.TypeIPv4)
				n += ether.PutIPv4(b[n:], r.far, r.our, ether.ProtoUDP, ether.UDPHdrLen+len(msg), 1)
				n += ether.PutUDP(b[n:], 51820, 51820, len(msg))
				n += copy(b[n:], msg)
				d := packetio.Desc{Addr: uint64(base), Len: uint32(n)}
				f := r.rq.fr.packet(d)
				l, _ := ether.ParseLink(f)
				h, _ := ether.ParseIPv4(f[l.Len:])
				u, _ := ether.ParseUDP(f[l.Len+h.HdrLen : l.Len+h.TotalLen])
				return r.g.fpDecrypt(r.rq, d, f, l, h, u, f[l.Len+h.HdrLen+ether.UDPHdrLen:l.Len+h.HdrLen+u.Len])
			}
			if put(0, order.first) != fpForwarded || put(1, order.then) != fpForwarded {
				t.Fatal("both copies should decrypt; only the replay check tells them apart")
			}
			r.flush()
			if r.rq.st.FPReplay.Load() != 1 {
				t.Fatalf("fp_replay=%d, want exactly the copy", r.rq.st.FPReplay.Load())
			}
			ep, _ := r.s.peer.FastPathEndpoint().(*Endpoint)
			if ep == nil {
				t.Fatal("no endpoint after an accepted packet")
			}
			if ep.mac != order.want {
				t.Fatalf("endpoint MAC %v, want %v (the accepted copy's)", ep.mac, order.want)
			}
		})
	}
}

// A gateway with one tagged port carries the tunnel and the LAN on the same
// VLAN. A frame on it is the tunnel's only if it is addressed to our
// underlay IP; plaintext for a host behind the peer must reach the LAN
// side, and must not be thrown away as "underlay, not for us" (which is
// what happened on the rig before the classifier learned the difference).
// With two VLANs the old rule stands: a frame on the underlay VLAN that is
// not for our underlay IP is nobody's.
func TestClassifySharesOneVLANBetweenUnderlayAndLAN(t *testing.T) {
	feed := func(t *testing.T, r *advRig, vlan uint16, dst [4]byte, dstPort uint16) {
		t.Helper()
		base := 192
		b := r.rq.fr.mem[base:]
		n := ether.PutLink(b, r.g.mac, ether.MAC{0x02, 0, 0, 0, 0, 0xaa}, vlan, ether.TypeIPv4)
		n += ether.PutIPv4(b[n:], [4]byte{10, 200, 2, 1}, dst, ether.ProtoUDP, ether.UDPHdrLen+16, 1)
		n += ether.PutUDP(b[n:], 40000, dstPort, 16)
		n += 16
		d := packetio.Desc{Addr: uint64(base), Len: uint32(n)}
		packets, sizes, eps := [][]byte{make([]byte, 2048)}, make([]int, 1), make([]Endpointer, 1)
		var got int
		r.g.classify(r.rq, d, packets, sizes, eps, &got)
	}
	plaintextFor := [4]byte{10, 200, 3, 1} // behind the peer: LAN traffic to forward

	t.Run("one VLAN: plaintext reaches the LAN side", func(t *testing.T) {
		r := newAdvRig(t, false)
		r.rq.fpOn = false // the stock path parks LAN frames for tun.Read; count there
		r.g.cfg.UnderlayVLAN, r.g.cfg.LANVLAN = 7, 7
		feed(t, r, 7, plaintextFor, 9000)
		if got := r.rq.st.OtherUnderlayDst.Load(); got != 0 {
			t.Fatalf("plaintext on the shared VLAN was dropped as underlay-not-ours (%d)", got)
		}
		if got := r.rq.st.RxLAN.Load(); got != 1 {
			t.Fatalf("rx_lan=%d, want 1", got)
		}
		// And the tunnel still finds its own datagrams on the same VLAN.
		feed(t, r, 7, r.our, 51820)
		if got := r.rq.st.RxTunnel.Load(); got != 1 {
			t.Fatalf("rx_tunnel=%d, want 1: a datagram for our underlay IP on the shared VLAN", got)
		}
	})
	t.Run("two VLANs: the underlay VLAN takes nothing else", func(t *testing.T) {
		r := newAdvRig(t, false)
		r.rq.fpOn = false
		r.g.cfg.UnderlayVLAN, r.g.cfg.LANVLAN = 7, 8
		feed(t, r, 7, plaintextFor, 9000)
		if got := r.rq.st.OtherUnderlayDst.Load(); got != 1 {
			t.Fatalf("o_udst=%d, want 1: plaintext on a separate underlay VLAN is not ours", got)
		}
		if got := r.rq.st.RxLAN.Load(); got != 0 {
			t.Fatalf("rx_lan=%d, want 0", got)
		}
	})
}
