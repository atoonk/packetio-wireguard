# Benchmarks

WireGuard as a userspace gateway on [packetio](https://github.com/atoonk/packetio),
measured against the kernel's WireGuard and against stock wireguard-go, one change at a
time, on three 100G machines with the plaintext on a real wire at both ends.

Every row here is a median of three runs from
[`bench/results/rig3/results.csv`](../bench/results/rig3/results.csv) (packet rates) and
[`bench/results/rig3/tcp.csv`](../bench/results/rig3/tcp.csv) (TCP through the tunnel),
summarised by `bench/rig3/report.py`. An earlier two-box round with an in-process
generator and sink is in `bench/results/blog/` and `bench/results/rnd-2026-09-19/`; its
numbers are higher because the gateway never had to receive its plaintext from a NIC,
and are quoted below only for the backend comparison, which was not repeated.

## Method

Three identical boxes (AMD EPYC 9275F, 24 cores, ConnectX-6 Dx at 100 GbE, one tagged
VLAN, Ubuntu 24.04, kernel 7.0), described in [TESTBED-SAO.md](TESTBED-SAO.md). Box 3 is
both sites: it sends plaintext addressed to a host behind gateway B, gateway A encrypts,
gateway B decrypts and forwards, and box 3 counts what comes back. Offered and delivered
are box 3's own NIC counters, one machine and one clock; every point also records both
gateways' counters and names the hop that lost (`limiter` column).

The load is a rate ladder, never a flood: `bench/rig3/run.sh point <pps>` for each rung.
**Clean** is the highest offered rate whose median loss is under 1%; **peak** is the
most that was ever delivered, at any loss. All packet rates are 68-byte plaintext frames
(130 bytes on the wire after WireGuard) unless a frame size is given. The gateways run
packetio's Direct Verbs backend; wgpio uses `-rx-depth 4096` and `-spray 64`
throughout, with `-spray-mode flow` where marked.

What line rate is at each frame size, on the wire after encryption:

| plaintext frame | on the wire | line rate |
|---:|---:|---:|
| 68 B | 130 B | 83.3 Mpps |
| 512 B | 578 B | 20.9 Mpps |
| 1442 B | 1506 B | 8.19 Mpps |

## Baselines

| | clean | peak |
|---|---:|---:|
| kernel IP forwarding, no tunnel | 15.0 M | 23.5 M |
| packetio `l3fwd` example, no tunnel (the rig's own ceiling) | — | 74.5 M |
| kernel WireGuard | 550 k | 559 k |
| kernel WireGuard, 512 B | 550 k | 557 k |
| kernel WireGuard, 1442 B | 597 k | 597 k (top of ladder) |
| wireguard-go | 350 k | 362 k |
| wireguard-go, 512 B / 1442 B | 350 k / 350 k | 359 k / 350 k |

Both are flat across frame sizes: the limit is per packet, not per byte. Kernel
WireGuard's is the per-peer transmit worker (`wg_packet_tx_worker`, one core at
99.9%); wireguard-go's is its single TUN-reading goroutine.

## wgpio, one patch at a time

Sixteen receive queues (one goroutine and one core each), the fork at each state:

| | clean | peak |
|---|---:|---:|
| unmodified wireguard-go on packetio (`-fastpath=false`) | 1.50 M | 1.74 M |
| + 0001, the fast path | 9.8 M at 2% loss (never under 1%) | 10.2 M |
| + 0002, the replay window checked per batch | — (never under 1%) | 24.4 M |
| + 0003, a 131008-counter window | 29.7 M | 36.0 M |
| + 0004, timers touched every 50 ms at most | 29.9 M (33.7 M at 1.0%) | 37.9 M |

Patch 0004 at 24 queues, where the timer lock is contended by more cores: without it
34.2 M peak (29.1 M at 3% loss at 30 M offered), with it 39.8 M peak (29.7 M at 1.1%).

All four patches, by core count:

| receive queues | clean | peak |
|---:|---:|---:|
| 8 | 19.9 M | 22.9 M |
| 16 | 29.9 M | 37.9 M |
| 24 | 29.7 M at 1.1% | 39.8 M |

By frame size, 16 queues:

| frame | delivered | plaintext | of line rate |
|---|---:|---:|---:|
| 68 B | 29.9 M | 16 Gbit/s | 36% |
| 512 B | 20.4 M | 80 Gbit/s | 98% |
| 1442 B | 8.15 M | 93 Gbit/s | 99.5% |

## Spray, and the order of a flow

One tunnel is one outer 5-tuple; `-spray N` sends from N source ports so the peer's RSS
spreads it. 16 queues, all four patches:

| | clean | peak | of the peer's 16 queues in use |
|---|---:|---:|---:|
| `-spray 0` | 2.0 M | 3.2 M | 1 |
| `-spray 16` | 20.0 M | 26.5 M | 11, unevenly |
| `-spray 64 -spray-mode rotate` (port per packet) | 33.9 M | 40.8 M | 16 |
| `-spray 64 -spray-mode flow` (port per inner flow, the default) | 33.7 M | 38.2 M | 16 |

Rotating the port per packet spreads one inner flow over all of the peer's queues,
which forward it out of order. Real TCP through the tunnel (`bench/rig3/tcp.sh`: iperf3
between a namespace behind each gateway; retransmits and `TcpExtTCPSACKReorder` at the
sender, 10 s runs):

| 1 stream | Gbit/s | retransmits | reordering events |
|---|---:|---:|---:|
| kernel WireGuard | 7.9 | 15,019 | 4 |
| wgpio, `-spray 0` | 11.9 | 307 | 0 |
| wgpio, rotate | 10.9 | 28,107 | 1,641,020 |
| wgpio, flow | 12.0 | 211 | 27 |

| streams | kernel | `-spray 0` | rotate | flow |
|---|---:|---:|---:|---:|
| 8 | 7.6 Gbit/s | 11.5 | 16.5 (16–46 across runs) | 66.0 |
| 32 | 7.2 | 11.4 | 51.7 | 88.8 |
| 8, reverse | 7.3 | 11.8 | 43.8 | 64.4 |

The reasoning and the cost of flow mode are in [DESIGN.md](DESIGN.md#spray-and-the-order-of-a-flow).

## With the kernel on the plaintext side

The same gateways with a kernel TUN for the plaintext, so the kernel keeps routing
(`-kernel-tun`), 8 packet cores unless noted:

| plaintext side | encrypted side | crypto pipeline | clean | peak |
|---|---|---|---:|---:|
| wireguard-go's own TUN, 1 queue | packetio | wireguard-go stock | 450 k | 484 k |
| multi-queue TUN, 4 queues (`internal/mqtun`) | packetio | wireguard-go stock | 1.50 M | 1.65 M |
| multi-queue TUN, 8 queues | packetio | wireguard-go stock | 1.49 M | 1.62 M |
| multi-queue TUN, 4 queues (`cmd/wggo-mq`) | **UDP sockets, no packetio** | wireguard-go stock | 1.50 M | 1.64 M |
| multi-queue TUN, 8 queues (`cmd/wggo-mq`) | UDP sockets, no packetio | wireguard-go stock | 1.60 M | 1.75 M |
| TUN queue per core (`cmd/wggo-fast`) | UDP sockets, no packetio | fast path | 2.5 M | 3.9 M |
| same, 16 cores | UDP sockets, no packetio | fast path | 3.0 M | 3.85 M |
| TUN queue per core (`-kernel-tun`, fast path) | packetio | fast path, 0001 | 5.0 M | 5.75 M |
| same, 0004 | packetio | fast path | 5.0 M | 6.1 M |
| same, 0004, 16 cores | packetio | fast path | 8.0 M | 9.6 M |

The stock pipeline stops at 1.5–1.6 M whichever wire feeds it: wireguard-go's single
`RoutineReadFromTUN` goroutine at ~1.6 M/core. The fast path over sockets stops at the
kernel's UDP receive path; over packetio with a TUN, at one read or write syscall per
packet per core. The kernel-TUN fast-path rows need the NIC's interrupts and the TUN's
RPS kept off the packet cores (`bench/rig3/gw.remote.sh`, `isolate_packet_cores`);
without that they collapse past the knee.

## Backends

From the two-box rig (in-process generator and sink, so higher than the rows above),
peak at 68 B:

| backend | 8 queues | 16 queues |
|---|---:|---:|
| DPDK | 24.1 M | 41.6 M |
| mlx5 Direct Verbs | 24.0 M | — |
| AF_XDP | 17.2 M | 28.3 M |

## Reproducing

`bench/rig3/env.sh` names the boxes; `bench/rig3/grid.sh` runs the grid;
`bench/rig3/run.sh up <mode> [queues] [binary] [flags]` then `run.sh point <pps>
[frame] [repeat]` runs a single point; `bench/rig3/tcp.sh <label>` runs the TCP set
with `SITES=1` gateways. The five wgpio binaries, one per fork state, come from
`bench/build-ladder.sh`.
