// Package backend opens the packetio device the gateway runs on. Which
// backend is compiled in is a build tag (dpdk today; afxdp and mlx5 are the
// same gateway over a different Open), so the gateway itself never imports
// one.
package backend

import (
	"net/netip"

	"github.com/atoonk/packetio"
	"github.com/atoonk/packetio-wireguard/internal/ether"
)

// Options describe the device to open.
type Options struct {
	Name      string // PCI address, interface name, or a DPDK vdev spec
	Queues    int    // receive queues, one goroutine each
	TxQueues  int    // transmit queues; 0 means as many as receive queues
	MTU       int    // largest untagged frame payload the port accepts
	FrameSize int    // 0 for the backend's default
	Frames    int    // 0 for the backend's default
	NoHugeMB  int    // >0: run without hugepages on this much ordinary memory (virtual devices only)
	Promisc   bool
	MAC       ether.MAC // override the port's own address (needs Promisc)
	DevArgs   string    // backend-specific device arguments
	// SteerVLAN installs a steering rule for this VLAN id. On a bifurcated
	// port (a ConnectX under mlx5_core, which the kernel keeps) that is what
	// diverts traffic to our queues at all; everything else stays with the
	// host. On an exclusive port it only chooses queues. 0 = none.
	SteerVLAN uint16
	// SteerDstIP narrows the rule to frames addressed to this prefix on
	// that VLAN, leaving the rest of the VLAN to the kernel. With a kernel
	// TUN it is the underlay address: we take the tunnel, the host keeps
	// the plaintext it is going to route. Needs SteerVLAN.
	SteerDstIP netip.Prefix
	// RxDepth is how many buffers a receive queue keeps posted; 0 for the
	// backend's default. Deeper rings absorb a longer burst before the
	// queue is drained.
	RxDepth int
}

// steering is the match list for SteerVLAN and SteerDstIP, ANDed.
func (o Options) steering() []packetio.Match {
	m := []packetio.Match{packetio.MatchVLAN(o.SteerVLAN)}
	if o.SteerDstIP.IsValid() {
		m = append(m, packetio.MatchDstIP(o.SteerDstIP))
	}
	return m
}

// Info is what the gateway needs to know about what was opened.
type Info struct {
	Backend  string
	MAC      ether.MAC
	MaxFrame int
	Queues   int

	// PortStats reports the port's own view of what it dropped, when the
	// backend has one: frames missed for want of a receive buffer, receive
	// errors, and transmit errors. nil when the backend cannot say.
	PortStats func() (missed, rxErrors, txErrors uint64, err error)

	// MinOffset is how far into a frame a descriptor may start: DPDK keeps
	// its mbuf in the first 192 bytes and refuses a descriptor inside them;
	// the verbs backends allow the frame's first byte.
	MinOffset int
}
