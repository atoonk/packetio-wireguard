//go:build !dpdk && !mlx5 && !afxdp

package backend

import (
	"errors"

	"github.com/atoonk/packetio"
)

// Open fails: no backend was compiled in. Build with -tags dpdk.
func Open(Options) (packetio.Device, Info, error) {
	return nil, Info{}, errors.New("no packet backend compiled in; build with -tags dpdk or -tags mlx5")
}
