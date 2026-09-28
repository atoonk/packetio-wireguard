package gateway

import (
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/atoonk/packetio-wireguard/internal/ether"
)

// Endpoint is a peer's address on the underlay: IP and port, plus the MAC
// its last packet came from, so replies need no neighbor lookup. wireguard-go
// replaces a peer's endpoint with the one from every authenticated packet,
// which is what makes carrying the MAC here safe: it is only ever the MAC an
// authenticated packet arrived from, and roaming to a new IP, port or MAC
// works without any ARP. An endpoint parsed from configuration has no MAC
// yet; sends to it resolve through the neighbor table.
type Endpoint struct {
	ip   [4]byte
	port uint16
	mac  ether.MAC
}

// Endpointer is conn.Endpoint, named so receive can fill a []conn.Endpoint.
type Endpointer = conn.Endpoint

var _ conn.Endpoint = (*Endpoint)(nil)

func (e *Endpoint) ClearSrc()           {}
func (e *Endpoint) SrcToString() string { return "" }
func (e *Endpoint) DstToString() string {
	return netip.AddrPortFrom(netip.AddrFrom4(e.ip), e.port).String()
}
func (e *Endpoint) DstIP() netip.Addr { return netip.AddrFrom4(e.ip) }
func (e *Endpoint) SrcIP() netip.Addr { return netip.Addr{} }

// DstToBytes feeds the cookie MAC2 computation. IP and port only, like the
// standard bind: a peer whose frames start arriving from another MAC must
// not have its cookies invalidated.
func (e *Endpoint) DstToBytes() []byte {
	b, _ := netip.AddrPortFrom(netip.AddrFrom4(e.ip), e.port).MarshalBinary()
	return b
}

// parseEndpoint accepts what wg(8) writes: "10.131.0.3:51820".
func parseEndpoint(s string) (*Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	if !ap.Addr().Unmap().Is4() {
		return nil, fmt.Errorf("endpoint %s: IPv4 only", s)
	}
	return &Endpoint{ip: ap.Addr().Unmap().As4(), port: ap.Port()}, nil
}
