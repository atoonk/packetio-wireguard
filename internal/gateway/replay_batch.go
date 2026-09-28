//go:build !stockwg && !wgreplay1

package gateway

import "golang.zx2c4.com/wireguard/device"

// validateCounters runs the batch's replay checks. The fork's ValidateCounters
// (patch 0002) takes the keypair's lock once for the whole batch and slides
// the window once; per packet it is a shift and a test.
func validateCounters(kp *device.Keypair, counters []uint64, ok []bool) {
	kp.ValidateCounters(counters, ok)
}
