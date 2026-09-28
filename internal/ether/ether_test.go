package ether

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestLinkRoundTrip(t *testing.T) {
	dst, src := MAC{1, 2, 3, 4, 5, 6}, MAC{7, 8, 9, 10, 11, 12}
	for _, vlan := range []uint16{0, 2131} {
		var b [VLANHdrLen]byte
		n := PutLink(b[:], dst, src, vlan, TypeIPv4)
		if n != LinkLen(vlan) {
			t.Fatalf("vlan %d: wrote %d, LinkLen says %d", vlan, n, LinkLen(vlan))
		}
		l, ok := ParseLink(b[:n])
		if !ok || l.Dst != dst || l.Src != src || l.VLAN != vlan || l.EtherType != TypeIPv4 || l.Len != n {
			t.Fatalf("vlan %d: parsed %+v ok=%v", vlan, l, ok)
		}
	}
	if _, ok := ParseLink(make([]byte, 13)); ok {
		t.Error("13 bytes parsed as a frame")
	}
	if _, ok := ParseLink([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x81, 0x00, 0, 1}); ok {
		t.Error("truncated tag parsed")
	}
}

// A real IPv4/UDP header captured from the wire, checksum included.
const goldenIPv4UDP = "45000021abcd40004011" + "0000" + "0a9a0001" + "0ac80305" + "04002328000d0000"

func TestIPv4Checksum(t *testing.T) {
	raw, _ := hex.DecodeString(goldenIPv4UDP)
	want := Checksum(raw[:20], 0)
	var b [33]byte
	PutIPv4(b[:], [4]byte{10, 154, 0, 1}, [4]byte{10, 200, 3, 5}, ProtoUDP, 13, 0xabcd)
	if got := uint16(b[10])<<8 | uint16(b[11]); got != want {
		t.Fatalf("checksum %04x, want %04x", got, want)
	}
	// A correct header sums to zero when the checksum field is included.
	if Checksum(b[:20], 0) != 0 {
		t.Fatal("verification of a good header is not zero")
	}
	h, ok := ParseIPv4(b[:])
	if !ok || h.Proto != ProtoUDP || h.TotalLen != 33 || h.Src != [4]byte{10, 154, 0, 1} {
		t.Fatalf("parsed %+v ok=%v", h, ok)
	}
	if _, ok := ParseIPv4(b[:25]); ok {
		t.Error("declared length beyond the slice accepted")
	}
}

func TestUDP(t *testing.T) {
	var b [8]byte
	PutUDP(b[:], 51820, 9000, 100)
	u, ok := ParseUDP(append(b[:], make([]byte, 100)...))
	if !ok || u.SrcPort != 51820 || u.DstPort != 9000 || u.Len != 108 {
		t.Fatalf("parsed %+v ok=%v", u, ok)
	}
	if _, ok := ParseUDP(b[:]); ok {
		t.Error("declared length beyond the slice accepted")
	}
}

func TestARP(t *testing.T) {
	a := ARP{Op: ARPReply, SenderMAC: MAC{1, 2, 3, 4, 5, 6}, SenderIP: [4]byte{10, 0, 0, 1},
		TargetMAC: MAC{7, 8, 9, 10, 11, 12}, TargetIP: [4]byte{10, 0, 0, 2}}
	var b [ARPLen]byte
	PutARP(b[:], a)
	got, ok := ParseARP(b[:])
	if !ok || got != a {
		t.Fatalf("parsed %+v ok=%v", got, ok)
	}
	b[5] = 6 // protocol address length
	if _, ok := ParseARP(b[:]); ok {
		t.Error("non-IPv4 ARP accepted")
	}
}

func TestEchoReply(t *testing.T) {
	var f [VLANHdrLen + IPv4HdrLen + 16]byte
	n := PutLink(f[:], MAC{1, 1, 1, 1, 1, 1}, MAC{2, 2, 2, 2, 2, 2}, 2154, TypeIPv4)
	ip := f[n:]
	icmp := ip[IPv4HdrLen:]
	icmp[0] = 8
	copy(icmp[4:], []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8})
	icmp[2], icmp[3] = 0, 0
	sum := Checksum(icmp, 0)
	icmp[2], icmp[3] = byte(sum>>8), byte(sum)
	PutIPv4(ip, [4]byte{10, 154, 0, 1}, [4]byte{10, 154, 0, 2}, ProtoICMP, 16, 7)
	h, _ := ParseIPv4(ip)
	if !EchoReply(f[:], n, h) {
		t.Fatal("request not recognised")
	}
	l, _ := ParseLink(f[:])
	if l.Dst != (MAC{2, 2, 2, 2, 2, 2}) || l.Src != (MAC{1, 1, 1, 1, 1, 1}) {
		t.Errorf("MACs not swapped: %+v", l)
	}
	h2, ok := ParseIPv4(ip)
	if !ok || h2.Src != [4]byte{10, 154, 0, 2} || h2.Dst != [4]byte{10, 154, 0, 1} {
		t.Errorf("IPs not swapped: %+v", h2)
	}
	if Checksum(ip[:IPv4HdrLen], 0) != 0 || Checksum(icmp, 0) != 0 || icmp[0] != 0 {
		t.Errorf("checksums or type wrong: type %d", icmp[0])
	}
	if !bytes.Equal(icmp[4:], []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Error("payload changed")
	}
	if EchoReply(f[:], n, h2) { // it is a reply now
		t.Error("reply treated as a request")
	}
}

func TestMACString(t *testing.T) {
	if s := (MAC{0x3c, 0xec, 0xef, 0xb4, 0xc2, 0xdc}).String(); s != "3c:ec:ef:b4:c2:dc" {
		t.Fatal(s)
	}
}
