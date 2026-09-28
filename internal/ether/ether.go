// Package ether parses and builds the few headers a WireGuard gateway needs
// to own once it has the whole NIC: Ethernet with an optional 802.1Q tag,
// IPv4, UDP, ARP and ICMP echo. Pure functions over byte slices, no
// allocation, so they can run on the receive path for every frame.
package ether

import "encoding/binary"

const (
	HdrLen     = 14 // Ethernet header, untagged
	VLANHdrLen = 18 // Ethernet header with one 802.1Q tag
	TypeIPv4   = 0x0800
	TypeARP    = 0x0806
	TypeVLAN   = 0x8100

	IPv4HdrLen = 20 // no options
	UDPHdrLen  = 8
	ARPLen     = 28 // Ethernet/IPv4 ARP body
	ProtoICMP  = 1
	ProtoUDP   = 17
	ProtoTCP   = 6

	// MinFrame is the shortest frame the wire accepts, not counting the FCS
	// the NIC appends. Anything shorter must be padded before transmit.
	MinFrame = 60
)

// MAC is an Ethernet address.
type MAC [6]byte

// Broadcast is the all-ones Ethernet address.
var Broadcast = MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// IsMulticast reports whether the group bit is set (broadcast included).
func (m MAC) IsMulticast() bool { return m[0]&1 != 0 }

// IsZero reports whether the address is unset.
func (m MAC) IsZero() bool { return m == MAC{} }

// String formats the address as aa:bb:cc:dd:ee:ff.
func (m MAC) String() string {
	const hex = "0123456789abcdef"
	var b [17]byte
	for i, c := range m {
		b[i*3], b[i*3+1] = hex[c>>4], hex[c&0xf]
		if i < 5 {
			b[i*3+2] = ':'
		}
	}
	return string(b[:])
}

// Link describes the link header of a received frame.
type Link struct {
	Dst, Src  MAC
	VLAN      uint16 // 0 when untagged
	EtherType uint16
	Len       int // bytes of link header; the payload starts here
}

// ParseLink reads the Ethernet header and one 802.1Q tag if present. ok is
// false for a frame too short to hold the header. QinQ is not understood:
// the inner tag is reported as the EtherType and left to the caller.
func ParseLink(f []byte) (l Link, ok bool) {
	if len(f) < HdrLen {
		return l, false
	}
	copy(l.Dst[:], f[0:6])
	copy(l.Src[:], f[6:12])
	l.EtherType = binary.BigEndian.Uint16(f[12:14])
	l.Len = HdrLen
	if l.EtherType != TypeVLAN {
		return l, true
	}
	if len(f) < VLANHdrLen {
		return l, false
	}
	l.VLAN = binary.BigEndian.Uint16(f[14:16]) & 0x0fff
	l.EtherType = binary.BigEndian.Uint16(f[16:18])
	l.Len = VLANHdrLen
	return l, true
}

// LinkLen is the size of the header PutLink writes: 14 untagged, 18 tagged.
func LinkLen(vlan uint16) int {
	if vlan != 0 {
		return VLANHdrLen
	}
	return HdrLen
}

// PutLink writes an Ethernet header, tagged when vlan is nonzero (priority
// and DEI zero), and returns its length. b must have LinkLen(vlan) bytes.
func PutLink(b []byte, dst, src MAC, vlan uint16, etherType uint16) int {
	copy(b[0:6], dst[:])
	copy(b[6:12], src[:])
	if vlan == 0 {
		binary.BigEndian.PutUint16(b[12:14], etherType)
		return HdrLen
	}
	binary.BigEndian.PutUint16(b[12:14], TypeVLAN)
	binary.BigEndian.PutUint16(b[14:16], vlan&0x0fff)
	binary.BigEndian.PutUint16(b[16:18], etherType)
	return VLANHdrLen
}

// IPv4 is the part of an IPv4 header a gateway looks at.
type IPv4 struct {
	Src, Dst [4]byte
	Proto    uint8
	TTL      uint8
	HdrLen   int // 20 plus options
	TotalLen int // header plus payload as declared by the packet
}

// ParseIPv4 reads a header from the start of p. ok is false when p is too
// short, not version 4, or declares a length that p cannot hold. The packet
// may be followed by padding (short frames are); use TotalLen, not len(p).
func ParseIPv4(p []byte) (h IPv4, ok bool) {
	if len(p) < IPv4HdrLen || p[0]>>4 != 4 {
		return h, false
	}
	h.HdrLen = int(p[0]&0x0f) * 4
	h.TotalLen = int(binary.BigEndian.Uint16(p[2:4]))
	if h.HdrLen < IPv4HdrLen || h.TotalLen < h.HdrLen || h.TotalLen > len(p) {
		return h, false
	}
	h.TTL = p[8]
	h.Proto = p[9]
	copy(h.Src[:], p[12:16])
	copy(h.Dst[:], p[16:20])
	return h, true
}

// PutIPv4 writes a 20-byte header with no options, DF set, the given
// identification, and a correct header checksum. payloadLen is what follows
// the header. Returns IPv4HdrLen.
func PutIPv4(b []byte, src, dst [4]byte, proto uint8, payloadLen int, id uint16) int {
	b[0] = 0x45
	b[1] = 0
	binary.BigEndian.PutUint16(b[2:4], uint16(IPv4HdrLen+payloadLen))
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], 0x4000) // DF
	b[8] = 64
	b[9] = proto
	b[10], b[11] = 0, 0
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	binary.BigEndian.PutUint16(b[10:12], Checksum(b[:IPv4HdrLen], 0))
	return IPv4HdrLen
}

// Checksum is the ones-complement Internet checksum of b, folded, with an
// initial sum to chain over a pseudo header. The caller stores the result.
func Checksum(b []byte, initial uint32) uint16 {
	sum := initial
	for ; len(b) >= 2; b = b[2:] {
		sum += uint32(b[0])<<8 | uint32(b[1])
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// UDP is a parsed UDP header.
type UDP struct {
	SrcPort, DstPort uint16
	Len              int // header plus payload as declared
}

// ParseUDP reads a header from p, which starts at the UDP header. ok is false
// when the declared length does not fit in p.
func ParseUDP(p []byte) (u UDP, ok bool) {
	if len(p) < UDPHdrLen {
		return u, false
	}
	u.SrcPort = binary.BigEndian.Uint16(p[0:2])
	u.DstPort = binary.BigEndian.Uint16(p[2:4])
	u.Len = int(binary.BigEndian.Uint16(p[4:6]))
	if u.Len < UDPHdrLen || u.Len > len(p) {
		return u, false
	}
	return u, true
}

// PutUDP writes a UDP header with a zero checksum, which IPv4 permits and
// which spares the transmit path a pass over the ciphertext; the WireGuard
// payload authenticates itself. Returns UDPHdrLen.
func PutUDP(b []byte, srcPort, dstPort uint16, payloadLen int) int {
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	binary.BigEndian.PutUint16(b[4:6], uint16(UDPHdrLen+payloadLen))
	b[6], b[7] = 0, 0
	return UDPHdrLen
}

// ARP is an Ethernet/IPv4 ARP message.
type ARP struct {
	Op        uint16 // 1 request, 2 reply
	SenderMAC MAC
	SenderIP  [4]byte
	TargetMAC MAC
	TargetIP  [4]byte
}

const (
	ARPRequest = 1
	ARPReply   = 2
)

// ParseARP reads an Ethernet/IPv4 ARP body from p.
func ParseARP(p []byte) (a ARP, ok bool) {
	if len(p) < ARPLen || binary.BigEndian.Uint16(p[0:2]) != 1 ||
		binary.BigEndian.Uint16(p[2:4]) != TypeIPv4 || p[4] != 6 || p[5] != 4 {
		return a, false
	}
	a.Op = binary.BigEndian.Uint16(p[6:8])
	copy(a.SenderMAC[:], p[8:14])
	copy(a.SenderIP[:], p[14:18])
	copy(a.TargetMAC[:], p[18:24])
	copy(a.TargetIP[:], p[24:28])
	return a, true
}

// PutARP writes an Ethernet/IPv4 ARP body and returns ARPLen.
func PutARP(b []byte, a ARP) int {
	binary.BigEndian.PutUint16(b[0:2], 1)
	binary.BigEndian.PutUint16(b[2:4], TypeIPv4)
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:8], a.Op)
	copy(b[8:14], a.SenderMAC[:])
	copy(b[14:18], a.SenderIP[:])
	copy(b[18:24], a.TargetMAC[:])
	copy(b[24:28], a.TargetIP[:])
	return ARPLen
}

// EchoReply turns an ICMP echo request into the reply, in place: the frame
// in f (link header of linkLen bytes, then the IPv4 packet) has its MACs and
// IPs swapped, the ICMP type set to 0 and both checksums fixed. It returns
// false, leaving f untouched, if the packet is not an ICMP echo request.
// The result is ready to transmit as is.
func EchoReply(f []byte, linkLen int, h IPv4) bool {
	if !EchoReplyIP(f[linkLen:], h) {
		return false
	}
	var mac [6]byte
	copy(mac[:], f[0:6])
	copy(f[0:6], f[6:12])
	copy(f[6:12], mac[:])
	return true
}

// EchoReplyIP is EchoReply for a bare IPv4 packet with no link header.
func EchoReplyIP(ip []byte, h IPv4) bool {
	if h.Proto != ProtoICMP {
		return false
	}
	if len(ip) < h.TotalLen || h.TotalLen < h.HdrLen+8 {
		return false
	}
	icmp := ip[h.HdrLen:h.TotalLen]
	if icmp[0] != 8 || icmp[1] != 0 {
		return false
	}
	copy(ip[12:16], h.Dst[:])
	copy(ip[16:20], h.Src[:])
	ip[8] = 64
	ip[10], ip[11] = 0, 0
	binary.BigEndian.PutUint16(ip[10:12], Checksum(ip[:h.HdrLen], 0))
	icmp[0] = 0
	// Type went 8 -> 0, so the checksum rises by 8<<8 in ones complement.
	icmp[2], icmp[3] = 0, 0
	binary.BigEndian.PutUint16(icmp[2:4], Checksum(icmp, 0))
	return true
}
