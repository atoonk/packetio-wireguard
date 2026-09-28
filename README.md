# packetio-wireguard

WireGuard as a userspace gateway on one NIC port, built on
[packetio](https://github.com/atoonk/packetio) (DPDK or mlx5 direct verbs) with
upstream [wireguard-go](https://git.zx2c4.com/wireguard-go) — unmodified in phase 1,
and with **four small, recorded patches** for the fast path that is on by default.

`wgpio` takes a port away from the kernel and runs two VLANs on it: the tunnel's
UDP on one, the plaintext LAN on the other. wireguard-go does the protocol —
handshakes, keys, timers, cryptokey routing, `wg(8)` configuration — through the
two interfaces it already has for that purpose, `conn.Bind` and `tun.Device`.
wgpio provides those two, plus the Ethernet/IP/UDP framing, ARP and ICMP echo that
owning a NIC requires. With the fast path on, transport packets are also decrypted
and encrypted in the NIC's own frames, on the receive goroutines, using the
session keys wireguard-go negotiated; everything that is not a transport packet
(handshakes, cookies, keepalives, anything the fast path punts) still takes
wireguard-go's own pipeline, and `-fastpath=false` sends everything through it.

```
                       ┌──────── wireguard-go device.Device ────────┐
NIC rx queue i ──► ReceiveFunc i ─┬► handshakes ... ──► Bind.Send ──► NIC tx  [tunnel VLAN]
       │                          └► decrypt in frame ─────────────► NIC tx  [LAN VLAN]
       └► LAN frames ─────────────── encrypt in frame ─────────────► NIC tx  [tunnel VLAN]
                     (-fastpath=false: tun.Read ► encrypt ► Bind.Send, decrypt ► tun.Write)
```

## Status

Works end to end on a single box (veth test), on a 10G Intel X550 rig (DPDK) and on
100G ConnectX-6 Dx machines (DPDK, Direct Verbs and AF_XDP). Numbers are in
[docs/BENCHMARKS.md](docs/BENCHMARKS.md): with the plaintext on a real wire at both
ends, one tunnel carries 29.9 Mpps of 68-byte packets clean on 16 cores (kernel
WireGuard: 550 k, wireguard-go: 350 k) and runs at line rate on 100G from 512-byte
packets up.

Phase 1 ran upstream wireguard-go **unmodified**. Phase 2 runs a fork with four small
patches — the fast-path API, batch replay validation, a wider replay window, and
throttled timer bookkeeping — each recorded in
[docs/CHANGES-TO-WIREGUARD-GO.md](docs/CHANGES-TO-WIREGUARD-GO.md) with its security
argument and the numbers that justified it, and reproducible from
[patches/](patches/) (`make check-patches`). `-fastpath=false` restores phase 1.

## Run it

```bash
# the wireguard-go fork (upstream + patches/) is a sibling directory, via `replace` in go.mod
git clone -b packetio https://github.com/atoonk/wireguard-go ../wireguard-go-packetio
make build                                        # = go build -tags dpdk -o bin/wgpio ./cmd/wgpio; needs libdpdk-dev (DPDK >= 23.11)
go build -tags mlx5 -o bin/wgpio ./cmd/wgpio      # or: ConnectX through direct verbs (libibverbs, libmlx5)

# on each peer: hand the port to DPDK (see packetio's docs/dpdk.md)
sysctl vm.nr_hugepages=128; ip link set eno2 down; dpdk-devbind.py --bind=vfio-pci 0000:01:00.0

sudo bin/wgpio -i 0000:01:00.0 -queues 4 -cpus 2-5 \
    -underlay-vlan 2131 -underlay-ip 10.131.0.2/24 \
    -lan-vlan 2154 -lan-ip 10.154.0.2/24 -route 10.200.2.0/24=10.154.0.1 \
    -config /etc/wireguard/wgpio0.conf                # wg setconf format
wg show wgpio0                                        # the usual tools work
```

Useful flags: `-cpus`/`-tun-cpu` pin the receive goroutines and the reader;
`-spray 64` sends from 64 source ports so the peer's RSS spreads one tunnel over
its queues (without it one tunnel is one queue at the peer: 3 M packets/s instead
of 34 M), and `-spray-mode flow` (the default) picks each packet's port from its
inner 5-tuple so a TCP connection keeps one outer tuple and arrives in order, see
[docs/DESIGN.md](docs/DESIGN.md#spray-and-the-order-of-a-flow); `-steer-vlan` is
needed on a port the kernel keeps (ConnectX);
`-gen`/`-sink` are the built-in generator and sink for a two-box rig;
`-fastpath=false` is the phase 1 pipeline: every packet through wireguard-go's own
goroutines (the fork's replay-window lock and wider window still apply). See
[docs/DESIGN.md](docs/DESIGN.md).

## Test without hardware

```bash
make build && sudo test/veth.sh    # two gateways over a veth pair through DPDK's net_af_packet vdev
```

On a fresh Ubuntu 24.04 box that takes Go 1.26, `git`, `libdpdk-dev` (or `libibverbs-dev`
for the mlx5 build), `tcpdump` and `python3`; `make check-patches` needs no git
identity, and the whole sequence, clone to PASS, was checked on a machine that had none
of it installed.

The script kills every `wgpio` on the box when it cleans up; do not run it on a
gateway host.
