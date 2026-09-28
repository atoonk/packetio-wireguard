//go:build stockwg

package main

import (
	"golang.zx2c4.com/wireguard/device"

	"github.com/atoonk/packetio-wireguard/internal/gateway"
)

// fastPathAvailable is false here: this binary is built with -tags stockwg
// against unmodified wireguard-go, which has no keypair observer to install
// and none of the rest of the fast path's API. validate() refuses -fastpath.
const fastPathAvailable = false

func installKeypairObserver(wg *device.Device, g *gateway.Gateway) {}
