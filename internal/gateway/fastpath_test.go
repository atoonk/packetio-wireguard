//go:build !stockwg

package gateway

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/atoonk/packetio"
	"github.com/atoonk/packetio-wireguard/internal/ether"
	"github.com/atoonk/packetio-wireguard/internal/neigh"
)

// fpSession is two wireguard-go devices with a session between them, and
// the keypair on each side of it, so a test can hand the fast path real
// transport messages without a NIC.
type fpSession struct {
	devs [2]*device.Device
	kpA  *device.Keypair // dev0's receive side of the session
	peer *device.Peer    // dev1 as dev0 sees it
	kpB  *device.Keypair // dev1's send side
}

func newFPSession(t *testing.T) *fpSession {
	t.Helper()
	var k1, k2 [32]byte
	rand.Read(k1[:])
	rand.Read(k2[:])
	p1, _ := curve25519.X25519(k1[:], curve25519.Basepoint)
	p2, _ := curve25519.X25519(k2[:], curve25519.Basepoint)
	binds := bindtest.NewChannelBinds()
	tuns := [2]*tuntest.ChannelTUN{tuntest.NewChannelTUN(), tuntest.NewChannelTUN()}
	cfg := [2]string{
		fmt.Sprintf("private_key=%x\nlisten_port=0\nreplace_peers=true\npublic_key=%x\nallowed_ip=1.0.0.2/32\nendpoint=127.0.0.1:2\n", k1[:], p2),
		fmt.Sprintf("private_key=%x\nlisten_port=0\nreplace_peers=true\npublic_key=%x\nallowed_ip=1.0.0.1/32\nendpoint=127.0.0.1:1\n", k2[:], p1),
	}
	type ev struct {
		peer *device.Peer
		kp   *device.Keypair
	}
	var mu sync.Mutex
	var events [2][]ev
	s := &fpSession{}
	for i := range s.devs {
		s.devs[i] = device.NewDevice(tuns[i].TUN(), binds[i], device.NewLogger(device.LogLevelError, fmt.Sprintf("dev%d ", i)))
		s.devs[i].SetKeypairObserver(func(peer *device.Peer, kp *device.Keypair, e device.KeypairEvent) {
			if e == device.KeypairRetired {
				return
			}
			mu.Lock()
			events[i] = append(events[i], ev{peer, kp})
			mu.Unlock()
		})
		if err := s.devs[i].IpcSet(cfg[i]); err != nil {
			t.Fatal(err)
		}
		if err := s.devs[i].Up(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.devs[i].Close)
	}
	// A ping from dev0 to dev1 drives the handshake. bindtest picks the v4
	// or v6 channel at random, so try both endpoints.
	delivered := false
	for _, port := range []int{1, 3} {
		s.devs[0].IpcSet(fmt.Sprintf("public_key=%x\nendpoint=127.0.0.1:%d\n", p2, port))
		tuns[0].Outbound <- tuntest.Ping(netip.MustParseAddr("1.0.0.2"), netip.MustParseAddr("1.0.0.1"))
		select {
		case <-tuns[1].Inbound:
			delivered = true
		case <-time.After(2 * time.Second):
		}
		if delivered {
			break
		}
	}
	if !delivered {
		t.Fatal("no ping delivered")
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	for _, e := range events[1] {
		s.kpB = e.kp
	}
	for _, e := range events[0] {
		if s.kpB != nil && e.kp.LocalIndex() == s.kpB.RemoteIndex() {
			s.kpA, s.peer = e.kp, e.peer
		}
	}
	if s.kpA == nil || s.kpB == nil {
		t.Fatal("no session keypairs observed")
	}
	return s
}

// transport is one authenticated transport message from dev1 to dev0 on a
// fresh nonce: a keepalive when plain is empty.
func (s *fpSession) transport(t *testing.T, plain []byte) []byte {
	t.Helper()
	nonce, ok := s.kpB.ReserveNonces(1)
	if !ok {
		t.Fatal("no nonce")
	}
	var nb [12]byte
	binary.LittleEndian.PutUint64(nb[4:], nonce)
	msg := make([]byte, 16, 16+len(plain)+16)
	binary.LittleEndian.PutUint32(msg[0:4], 4)
	binary.LittleEndian.PutUint32(msg[4:8], s.kpB.RemoteIndex())
	binary.LittleEndian.PutUint64(msg[8:16], nonce)
	return s.kpB.SendCipher().Seal(msg, nb[:], plain, nil)
}

// A replayed transport message is authentic, so it decrypts, and it fails
// the replay check. It must not move the peer's endpoint: an attacker on
// the underlay who re-sends a captured datagram from its own MAC would
// otherwise have the tunnel's outbound traffic delivered to it.
func TestFastPathReplayDoesNotMoveEndpoint(t *testing.T) {
	s := newFPSession(t)
	g := &Gateway{cfg: Config{Sink: true, MTU: 1420}, fp: newFPTable(), wg: s.devs[0], nb: neigh.New(), log: slog.Default()}
	g.Observe(s.peer, s.kpA, device.KeypairEstablished)
	rq := &rxQueue{fr: frames{mem: make([]byte, 4*4096), shift: 12, size: 4096}}

	peerIP, ourIP := [4]byte{10, 131, 0, 3}, [4]byte{10, 131, 0, 2}
	legit := ether.MAC{0x02, 0, 0, 0, 0, 0xaa}
	attacker := ether.MAC{0x02, 0, 0, 0, 0, 0xbb}
	msg := s.transport(t, nil)

	feed := func(frame int, src ether.MAC) fpVerdict {
		base := frame*4096 + 192
		b := rq.fr.mem[base:]
		n := ether.PutLink(b, g.mac, src, 0, ether.TypeIPv4)
		n += ether.PutIPv4(b[n:], peerIP, ourIP, ether.ProtoUDP, ether.UDPHdrLen+len(msg), 1)
		n += ether.PutUDP(b[n:], 51820, 51820, len(msg))
		n += copy(b[n:], msg)
		d := packetio.Desc{Addr: uint64(base), Len: uint32(n)}
		f := rq.fr.packet(d)
		l, _ := ether.ParseLink(f)
		h, _ := ether.ParseIPv4(f[l.Len:])
		u, _ := ether.ParseUDP(f[l.Len+h.HdrLen : l.Len+h.TotalLen])
		return g.fpDecrypt(rq, d, f, l, h, u, f[l.Len+h.HdrLen+ether.UDPHdrLen:l.Len+h.HdrLen+u.Len])
	}
	if v := feed(0, legit); v != fpForwarded {
		t.Fatalf("legitimate packet: verdict %v", v)
	}
	if v := feed(1, attacker); v != fpForwarded {
		t.Fatalf("replayed packet decrypts too: verdict %v", v)
	}
	g.fpFlush(rq)

	if got := rq.st.FPReplay.Load(); got != 1 {
		t.Fatalf("replays counted: %d, want 1", got)
	}
	ep, _ := s.peer.FastPathEndpoint().(*Endpoint)
	if ep == nil {
		t.Fatal("peer has no endpoint after an accepted packet")
	}
	if ep.mac != legit {
		t.Fatalf("peer endpoint MAC is %v, want the legitimate peer's %v", ep.mac, legit)
	}
}

// Flow-affine spray: a flow's packets all take one outer source port, so
// the peer's RSS keeps them on one queue; distinct flows spread over the
// queue's share of the range; and the hash is not fooled by the cases a
// plain XOR would be (swapped addresses, port pairs with an equal XOR).
func TestSprayByFlowIsStablePerFlowAndSpreadsFlows(t *testing.T) {
	g := &Gateway{cfg: Config{ListenPort: 51820, SprayByFlow: true}, ports: 64}
	rq := &rxQueue{sprayFrom: 3, sprayN: 8} // queue 3 of 8: ports 51823, 51831, ... (8 of them)
	pkt := func(src, dst [4]byte, sport, dport uint16) []byte {
		p := make([]byte, 28)
		ether.PutIPv4(p, src, dst, ether.ProtoTCP, 8, 64)
		binary.BigEndian.PutUint16(p[20:], sport)
		binary.BigEndian.PutUint16(p[22:], dport)
		return p
	}
	a, b := [4]byte{10, 200, 2, 1}, [4]byte{10, 200, 3, 1}
	p1 := rq.sprayPort(g, pkt(a, b, 40000, 443))
	for i := 0; i < 100; i++ {
		if got := rq.sprayPort(g, pkt(a, b, 40000, 443)); got != p1 {
			t.Fatalf("one flow, two ports: %d then %d", p1, got)
		}
	}
	if (p1-51820-3)%8 != 0 || p1 < 51823 || p1 >= 51820+64 {
		t.Fatalf("port %d is not in queue 3's share of the range", p1)
	}
	seen := map[uint16]int{}
	for s := uint16(40000); s < 40000+256; s++ {
		seen[rq.sprayPort(g, pkt(a, b, s, 443))]++
	}
	if len(seen) < 8 {
		t.Fatalf("256 flows used only %d of the queue's 8 ports: %v", len(seen), seen)
	}
	for port, n := range seen {
		if n < 16 || n > 48 { // 32 expected; a plain XOR would pile up
			t.Fatalf("port %d got %d of 256 flows", port, n)
		}
	}
	if flowHash(pkt(a, b, 1000, 2000)) == flowHash(pkt(b, a, 1000, 2000)) ||
		flowHash(pkt(a, b, 1000, 2000)) == flowHash(pkt(a, b, 2000, 1000)) {
		t.Fatal("swapped addresses or ports collide, as they would with XOR")
	}
}

// Through fpSeal, not just sprayPort: the seal encrypts the packet in place,
// so the port must be chosen from the inner headers before that, or the
// "flow hash" is a hash of ciphertext and every packet takes a random port
// (which is what the first version did, and it reordered TCP as badly as
// rotation). Two packets of one flow must leave with one source port.
func TestSprayByFlowReadsThePlaintextNotTheCiphertext(t *testing.T) {
	s := newFPSession(t)
	g := &Gateway{cfg: Config{ListenPort: 51820, SprayByFlow: true, UnderlayVLAN: 0},
		wg: s.devs[1], uIP: [4]byte{10, 49, 0, 1}, mac: ether.MAC{0x02, 0, 0, 0, 0, 1}, ports: 64}
	rq := &rxQueue{fr: frames{mem: make([]byte, 16*4096), shift: 12, size: 4096}, fpOn: true, sprayFrom: 2, sprayN: 8}
	ep := &Endpoint{ip: [4]byte{10, 49, 0, 2}, port: 51820, mac: ether.MAC{0x02, 0, 0, 0, 0, 2}}
	front := ether.LinkLen(0) + outerHdrLen + wgHdrLen
	place := func(i int, sport uint16) {
		plain := ipv4UDP([4]byte{10, 200, 2, 1}, [4]byte{1, 0, 0, 2}, 40)
		binary.BigEndian.PutUint16(plain[20:22], sport)
		plainAbs := i*4096 + 256
		copy(rq.fr.mem[plainAbs:], plain)
		a := rq.fp.txAcct(s.peer)
		if a.kp == nil {
			a.kp, a.send, a.ep, a.mac = s.kpB, s.kpB.SendCipher(), ep, ep.mac
		}
		a.pending = append(a.pending, fpPending{plainAbs: plainAbs, plainLen: len(plain), pad: g.wg.PaddingSize(len(plain)), start: plainAbs - front})
	}
	place(0, 4000)
	place(1, 4000) // same flow
	place(2, 4001) // another flow
	place(3, 4002)
	place(4, 4003)
	g.fpSeal(rq)
	if len(rq.fp.out) != 5 {
		t.Fatalf("%d frames sealed, want 5", len(rq.fp.out))
	}
	port := func(k int) uint16 {
		f := rq.fr.mem[rq.fp.out[k].Addr : rq.fp.out[k].Addr+uint64(rq.fp.out[k].Len)]
		return binary.BigEndian.Uint16(f[ether.LinkLen(0)+ether.IPv4HdrLen:])
	}
	if port(0) != port(1) {
		t.Fatalf("one flow left on two ports: %d and %d (the hash read ciphertext?)", port(0), port(1))
	}
	seen := map[uint16]bool{port(0): true, port(2): true, port(3): true, port(4): true}
	if len(seen) < 2 {
		t.Fatalf("four flows all on port %d", port(0))
	}
	for k := 0; k < 5; k++ {
		if p := port(k); p < 51822 || (p-51822)%8 != 0 {
			t.Fatalf("frame %d on port %d, outside queue 2's share", k, p)
		}
	}
	rq.fp.reset()
}
