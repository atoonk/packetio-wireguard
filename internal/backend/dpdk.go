//go:build dpdk

package backend

import (
	"fmt"

	"github.com/atoonk/packetio"
	"github.com/atoonk/packetio/dpdk"
)

// Open opens a DPDK port. The gateway pins its own receive goroutines and
// transmits from arbitrary goroutines, so packetio's placement is off.
func Open(o Options) (packetio.Device, Info, error) {
	tx := o.TxQueues
	if tx == 0 {
		tx = o.Queues
	}
	opts := []dpdk.Option{dpdk.WithoutAffinity(), dpdk.WithRxQueues(o.Queues), dpdk.WithTxQueues(tx)}
	if o.MTU > 0 {
		opts = append(opts, dpdk.WithMTU(o.MTU))
	}
	// 4096-byte frames by default, not packetio's 2048. Intel's ixgbe programs its
	// receive buffer size in 1 KB units, so the 1728 bytes a 2048-byte frame leaves
	// for the packet become a 1024-byte buffer and every larger frame is dropped
	// (measured on an X550: 928-byte packets pass, 1028-byte ones vanish). 4096
	// leaves 3776, a 3 KB buffer, room for any 1522-byte tagged frame.
	frameSize := o.FrameSize
	if frameSize == 0 {
		frameSize = 4096
	}
	opts = append(opts, dpdk.WithFrameSize(frameSize))
	if o.Frames > 0 {
		opts = append(opts, dpdk.WithFrames(o.Frames))
	}
	if o.NoHugeMB > 0 {
		opts = append(opts, dpdk.WithoutHugePages(o.NoHugeMB))
	}
	if o.Promisc || !o.MAC.IsZero() {
		opts = append(opts, dpdk.WithPromiscuous())
	}
	if o.DevArgs != "" {
		opts = append(opts, dpdk.WithDevArgs(o.DevArgs))
	}
	if o.SteerVLAN != 0 {
		opts = append(opts, dpdk.WithSteering(packetio.SteeringFilter{Match: o.steering()}))
	}
	d, err := dpdk.Open(o.Name, opts...)
	if err != nil {
		return nil, Info{}, fmt.Errorf("dpdk: %w", err)
	}
	di := d.Info()
	info := Info{Backend: "dpdk/" + di.Driver, MAC: di.MAC, MaxFrame: di.MaxPacket, Queues: di.RxQueues, MinOffset: 192}
	if !o.MAC.IsZero() {
		info.MAC = o.MAC
	}
	info.PortStats = func() (uint64, uint64, uint64, error) {
		st, err := d.PortStats()
		return st.Missed + st.NoBuffer, st.InErrors, st.OutErrors, err
	}
	return d, info, nil
}
