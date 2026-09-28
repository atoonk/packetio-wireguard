package main

import (
	"runtime"
	"strings"
	"testing"
)

// The flag combinations that used to start a gateway which quietly
// forwarded nothing, or ran its packet cores somewhere else.
func TestValidateRejects(t *testing.T) {
	base := func() options {
		return options{dev: "0000:01:00.0", uIPs: "10.131.0.2/24", lIPs: "10.154.0.2/24",
			queues: 1, batch: 64, tunCPU: -1, portMTU: 1500, mtu: 1420, fastPath: true, port: 51820}
	}
	ncpu := runtime.NumCPU()
	for _, tc := range []struct {
		name string
		cpus []int
		want string
		edit func(*options)
	}{
		{name: "no device", want: "required", edit: func(o *options) { o.dev = "" }},
		{name: "no queues", want: "at least one", edit: func(o *options) { o.queues = 0 }},
		{name: "batch too big", want: "1..128", edit: func(o *options) { o.batch = 1000 }},
		{name: "cpu does not exist", cpus: []int{ncpu + 5}, want: "does not exist"},
		{name: "tun cpu overlaps", cpus: []int{0}, want: "also in -cpus", edit: func(o *options) { o.tunCPU = 0 }},
		{name: "fewer cpus than queues", cpus: []int{0}, want: "needs 2 cpus in -cpus",
			edit: func(o *options) { o.queues = 2 }},
		{name: "mtu past the port", want: "more than -port-mtu", edit: func(o *options) { o.mtu = 1500 }},
		{name: "spray past 65535", want: "past 65535", edit: func(o *options) { o.spray = 20000 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base()
			if tc.edit != nil {
				tc.edit(&o)
			}
			err := o.validate(tc.cpus)
			if err == nil {
				t.Fatalf("validate accepted it")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestValidateAcceptsTheDefaults(t *testing.T) {
	o := options{dev: "0000:01:00.0", uIPs: "10.131.0.2/24", lIPs: "10.154.0.2/24",
		queues: 1, batch: 64, tunCPU: -1, portMTU: 1500, mtu: 1420, fastPath: fastPathAvailable, port: 51820, spray: 64}
	if err := o.validate([]int{0}); err != nil {
		t.Fatalf("validate rejected a sane configuration: %v", err)
	}
}

// The generator works without the fast path: it parks its frames in the LAN
// ring for wireguard-go's own pipeline, which is how the stock step of the
// benchmark ladder is driven from one of the two boxes.
func TestValidateAcceptsGenWithoutTheFastPath(t *testing.T) {
	o := options{dev: "0000:01:00.0", uIPs: "10.131.0.2/24", lIPs: "10.154.0.2/24",
		queues: 1, batch: 64, tunCPU: -1, portMTU: 1500, mtu: 1420, fastPath: false, port: 51820,
		genSpec: "pps=1k"}
	if err := o.validate([]int{0}); err != nil {
		t.Fatalf("validate rejected -gen without the fast path: %v", err)
	}
}
