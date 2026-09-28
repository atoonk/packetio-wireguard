//go:build !stockwg

package main

import (
	"golang.zx2c4.com/wireguard/device"

	"github.com/atoonk/packetio-wireguard/internal/gateway"
)

// fastPathAvailable says whether this binary was built against the packetio
// fork of wireguard-go, which is what the fast path needs.
const fastPathAvailable = true

// installKeypairObserver tells the gateway about every keypair the device
// establishes, promotes and retires, which is how the fast path knows what
// it may decrypt with. Call it before the device is configured: the observer
// does not replay keypairs that already exist.
func installKeypairObserver(wg *device.Device, g *gateway.Gateway) {
	wg.SetKeypairObserver(g.Observe)
}
