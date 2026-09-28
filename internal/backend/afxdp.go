//go:build afxdp

package backend

import (
	"fmt"
	"net"

	"github.com/atoonk/packetio"
	"github.com/atoonk/packetio/afxdp"
)

// Open opens a port through packetio's AF_XDP backend. The kernel keeps the
// interface and its driver; an eBPF program on the interface redirects the
// frames we asked for into our sockets and leaves the rest to the host. No
// hugepages, no binding a device away, and it works on any driver with XDP
// support rather than only on the cards DPDK or verbs know about.
//
// One difference from the other backends matters to the gateway: an AF_XDP
// socket is one queue, both directions, so there is no spare transmit queue
// to give the fast path. The gateway notices (NumTxQueues == NumRxQueues) and
// shares each receive goroutine's transmit queue with the stock path under
// that queue's mutex, which is the same arrangement it uses on a virtual
// device with a single queue pair.
func Open(o Options) (packetio.Device, Info, error) {
	frameSize := o.FrameSize
	if frameSize == 0 {
		frameSize = 4096
	}
	opts := []afxdp.Option{afxdp.WithoutAffinity(), afxdp.WithQueues(o.Queues), afxdp.WithFrameSize(frameSize)}
	if o.Frames > 0 {
		opts = append(opts, afxdp.WithFrames(o.Frames))
	}
	// Steering is how an AF_XDP socket gets anything at all beyond the queue
	// it is bound to: the filter is compiled to eBPF and attached to the
	// interface. Without a VLAN to match we take everything, which on a
	// shared interface means the host stops seeing its own traffic.
	if o.SteerVLAN != 0 {
		opts = append(opts, afxdp.WithSteering(packetio.SteeringFilter{
			Match: o.steering(), Promiscuous: o.Promisc}))
	} else if o.Promisc {
		opts = append(opts, afxdp.WithSteering(packetio.SteeringFilter{Promiscuous: true}))
	}
	d, err := afxdp.Open(o.Name, opts...)
	if err != nil {
		return nil, Info{}, fmt.Errorf("afxdp: %w", err)
	}
	info := Info{Backend: "afxdp", MaxFrame: d.Capabilities().MaxFrameSize, Queues: o.Queues, MinOffset: 0}
	if !o.MAC.IsZero() {
		info.MAC = o.MAC
	} else if ifc, err := net.InterfaceByName(o.Name); err == nil && len(ifc.HardwareAddr) == 6 {
		copy(info.MAC[:], ifc.HardwareAddr)
	} else {
		d.Close()
		return nil, Info{}, fmt.Errorf("afxdp: cannot read the MAC of %s: %v", o.Name, err)
	}
	info.PortStats = func() (uint64, uint64, uint64, error) {
		var missed, rxErr, txErr uint64
		for i := 0; i < d.NumRxQueues(); i++ {
			if st, err := d.RxQueue(i).Stats(); err == nil {
				missed += st.Dropped
				rxErr += st.Errors
			}
		}
		return missed, rxErr, txErr, nil
	}
	return d, info, nil
}
