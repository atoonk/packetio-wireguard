package mqtun

import (
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/atoonk/packetio-wireguard/internal/ether"
)

// Needs root and /dev/net/tun. The device is created with two queues and
// addressed; a UDP datagram the kernel routes into it must come out of
// Read, and a packet put in with Write must reach a socket listening on the
// device's own address.
func TestRoundTripThroughTheKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const name = "mqtuntest0"
	d, err := Open(name, 1420, 2)
	if err != nil {
		t.Skip("cannot open a TUN here:", err)
	}
	defer d.Close()
	if d.Queues() != 2 {
		t.Fatalf("%d queues, want 2", d.Queues())
	}
	for _, args := range [][]string{
		{"addr", "add", "10.250.77.1/24", "dev", name},
		{"link", "set", name, "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	if err := exec.Command("sysctl", "-qw", "net.ipv4.conf."+name+".rp_filter=0").Run(); err != nil {
		t.Logf("rp_filter: %v (continuing)", err)
	}
	if ev := <-d.Events(); ev != 1 { // tun.EventUp
		t.Fatalf("first event %v, want EventUp", ev)
	}

	// Kernel -> Read. Several flows, so both queues are exercised.
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(10, 250, 77, 2), Port: 9})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const want = 8
	for i := 0; i < want; i++ {
		cc, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(10, 250, 77, 2), Port: 9000 + i})
		if err != nil {
			t.Fatal(err)
		}
		cc.Write([]byte("hello"))
		cc.Close()
	}
	bufs, sizes := make([][]byte, batchSize), make([]int, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 2048)
	}
	got := 0
	deadline := time.Now().Add(2 * time.Second)
	for got < want && time.Now().Before(deadline) {
		done := make(chan int, 1)
		go func() { n, _ := d.Read(bufs, sizes, 16); done <- n }()
		select {
		case n := <-done:
			for k := 0; k < n; k++ {
				p := bufs[k][16 : 16+sizes[k]]
				if p[0]>>4 == 4 && p[9] == 17 && p[19] == 2 { // IPv4 UDP to .2
					got++
				}
			}
		case <-time.After(time.Until(deadline)):
		}
	}
	if got < want {
		t.Fatalf("Read saw %d of the %d datagrams the kernel routed into the device", got, want)
	}

	// Write -> kernel. A datagram from the far side to a socket on our address.
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(10, 250, 77, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.LocalAddr().(*net.UDPAddr).Port
	payload := []byte("from the tunnel")
	pkt := make([]byte, 16+ether.IPv4HdrLen+ether.UDPHdrLen+len(payload))
	n := 16
	n += ether.PutIPv4(pkt[n:], [4]byte{10, 250, 77, 2}, [4]byte{10, 250, 77, 1}, ether.ProtoUDP, ether.UDPHdrLen+len(payload), 64)
	n += ether.PutUDP(pkt[n:], 4000, uint16(port), len(payload))
	copy(pkt[n:], payload)
	if _, err := d.Write([][]byte{pkt}, 16); err != nil {
		t.Fatal(err)
	}
	l.SetReadDeadline(time.Now().Add(2 * time.Second))
	rb := make([]byte, 100)
	rn, from, err := l.ReadFromUDP(rb)
	if err != nil {
		t.Fatalf("the written packet did not reach the socket: %v", err)
	}
	if string(rb[:rn]) != string(payload) || from.Port != 4000 {
		t.Fatalf("got %q from %v", rb[:rn], from)
	}
	if d.WritePackets.Load() != 1 || d.ReadPackets.Load() < uint64(want) {
		t.Fatalf("counters: read %d write %d", d.ReadPackets.Load(), d.WritePackets.Load())
	}
}

func TestFlowHashKeepsAFlowTogetherAndSpreadsFlows(t *testing.T) {
	mk := func(sport uint16) []byte {
		p := make([]byte, 28)
		ether.PutIPv4(p, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, ether.ProtoUDP, 8, 64)
		ether.PutUDP(p[20:], sport, 9, 0)
		return p
	}
	if flowHash(mk(1000)) != flowHash(mk(1000)) {
		t.Fatal("one flow, two hashes")
	}
	seen := map[uint32]bool{}
	for s := uint16(1000); s < 1064; s++ {
		seen[flowHash(mk(s))%8] = true
	}
	if len(seen) < 6 {
		t.Fatalf("64 flows landed on only %d of 8 queues", len(seen))
	}
}
