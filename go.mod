module github.com/atoonk/packetio-wireguard

go 1.26.0

require (
	github.com/atoonk/packetio v0.1.11
	golang.org/x/crypto v0.37.0
	golang.org/x/sys v0.48.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
)

require (
	github.com/atoonk/go-afxdp v0.12.0 // indirect
	github.com/cilium/ebpf v0.16.0 // indirect
	github.com/vishvananda/netlink v1.3.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/exp v0.0.0-20230224173230-c95f2b4c22f2 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace golang.zx2c4.com/wireguard => ../wireguard-go-packetio
