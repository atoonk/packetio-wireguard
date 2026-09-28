//go:build !stockwg && wgreplay1

package gateway

import "golang.zx2c4.com/wireguard/device"

// validateCounters runs the batch's replay checks one at a time, which is
// what the fast path did before patch 0002: a lock, a window slide and an
// unlock per packet. Built with -tags wgreplay1 to measure that difference.
func validateCounters(kp *device.Keypair, counters []uint64, ok []bool) {
	for i, c := range counters {
		ok[i] = kp.ValidateCounter(c)
	}
}
