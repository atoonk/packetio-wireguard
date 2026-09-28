//go:build mlx5

package backend

import (
	"fmt"
	"net"

	"github.com/atoonk/packetio"
	"github.com/atoonk/packetio/mlx5"
)

// Open opens a ConnectX port through packetio's direct-verbs backend. The
// kernel keeps the interface; a steering rule diverts our VLAN to our
// queues. No hugepages, no binding.
func Open(o Options) (packetio.Device, Info, error) {
	tx := o.TxQueues
	if tx == 0 {
		tx = o.Queues
	}
	frameSize := o.FrameSize
	if frameSize == 0 {
		frameSize = 4096
	}
	// One send ring per transmit queue: each queue has one owner, and the backend
	// would otherwise open four rings per queue and run out at 16 queues.
	opts := []mlx5.Option{mlx5.WithoutAffinity(), mlx5.WithRxQueues(o.Queues), mlx5.WithTxQueues(tx), mlx5.WithFrameSize(frameSize), mlx5.WithRingsPerQueue(1)}
	if o.Frames > 0 {
		opts = append(opts, mlx5.WithFrames(o.Frames))
	}
	if o.RxDepth > 0 {
		opts = append(opts, mlx5.WithRxDepth(o.RxDepth))
	}
	if o.SteerVLAN != 0 {
		opts = append(opts, mlx5.WithSteering(packetio.SteeringFilter{Match: o.steering(), Promiscuous: o.Promisc}))
	} else if o.Promisc {
		opts = append(opts, mlx5.WithSteering(packetio.SteeringFilter{Promiscuous: true}))
	}
	d, err := mlx5.Open(o.Name, opts...)
	if err != nil {
		return nil, Info{}, fmt.Errorf("mlx5: %w", err)
	}
	info := Info{Backend: "mlx5/verbs", MaxFrame: d.Capabilities().MaxFrameSize, Queues: o.Queues, MinOffset: 0}
	if !o.MAC.IsZero() {
		info.MAC = o.MAC
	} else if ifc, err := net.InterfaceByName(o.Name); err == nil && len(ifc.HardwareAddr) == 6 {
		copy(info.MAC[:], ifc.HardwareAddr)
	} else {
		d.Close()
		return nil, Info{}, fmt.Errorf("mlx5: cannot read the MAC of %s: %v", o.Name, err)
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
