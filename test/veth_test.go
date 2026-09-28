//go:build dpdk

package test

import (
	"os"
	"os/exec"
	"testing"
)

// TestVeth runs the single-box end-to-end test (test/veth.sh): two gateways
// on a veth pair through DPDK's net_af_packet vdev. It needs root and a
// built ../bin/wgpio, and skips otherwise.
func TestVeth(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("../bin/wgpio"); err != nil {
		t.Skip("build bin/wgpio first: go build -tags dpdk -o bin/wgpio ./cmd/wgpio")
	}
	cmd := exec.Command("bash", "veth.sh", "../bin/wgpio")
	cmd.Env = append(os.Environ(), "LOAD=20000")
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
}
