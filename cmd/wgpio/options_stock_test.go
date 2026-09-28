//go:build stockwg

package main

import (
	"strings"
	"testing"
)

// A stock build has no fast path to turn on, and -fastpath defaults to true:
// it must say so rather than run with everything silently punted.
func TestStockBuildRefusesTheFastPath(t *testing.T) {
	o := options{dev: "0000:01:00.0", uIPs: "10.131.0.2/24", lIPs: "10.154.0.2/24",
		queues: 1, batch: 64, tunCPU: -1, portMTU: 1500, mtu: 1420, fastPath: true, port: 51820}
	err := o.validate([]int{0})
	if err == nil {
		t.Fatal("validate accepted -fastpath in a stock build")
	}
	if !strings.Contains(err.Error(), "stockwg") {
		t.Errorf("error %q does not name the build tag", err)
	}
}
