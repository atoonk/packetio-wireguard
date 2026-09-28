# The 100G test bed — São Paulo pair (the rig for the redo)

Recorded 2026-09-19 after the DPDK receive path was proven on it. This is the rig every
number in the redo comes from; the earlier Frankfurt and Tokyo pairs were used only to
find the harness bug (see `PACKETIO-NOTES.md` item 5) and are being shut down.

## Machines

| | sao-2 (role A, encrypts in `fwd`) | sao-3 (role B, decrypts in `fwd`) |
|---|---|---|
| management ssh | `ubuntu@103.88.233.93` | `ubuntu@103.88.233.91` |
| host name | `f4-metal-large-sao-2` | `f4-metal-large-sao-3` |
| CPU | AMD EPYC 9275F, 24 cores / 48 threads, **one NUMA node**; SMT siblings are `i` and `i+24` | same |
| memory | 755 GB | same |
| OS / kernel | Ubuntu 24.04, `7.0.0-31-generic` | same |
| NIC | NVIDIA ConnectX-6 Dx (MT2892), 100 Gbit/s, firmware 22.40.1000, `mlx5_core` | same |
| data port | `eno2` = PCI `0000:c1:00.1`, NUMA node 0 | `eno2` = PCI `0000:c1:00.1` |
| eno2 MAC | `7c:c2:55:be:f3:c7` | `7c:c2:55:be:f4:1b` |
| management port | `eno1` (`103.88.233.93/31`) — **never touched** | `eno1` (`103.88.233.91/31`) |

Login is by key (installed) or the lab password; `sudo` needs no password.

## Network

One tagged VLAN, **2049**, on `eno2`, and nothing else: the switch trunk carries only that
VLAN, so untagged frames do not pass. Both underlay and "LAN" traffic live on it.

| purpose | sao-2 | sao-3 |
|---|---|---|
| underlay address (kernel `vlan.2049`, and wgpio `-underlay-ip`) | `10.49.0.1/24` | `10.49.0.2/24` |
| wgpio LAN address (`-lan-ip`, dummy) | `10.154.0.2/24` | `10.154.0.3/24` |
| prefix "behind" the box (generator destinations) | `10.200.2.0/24` | `10.200.3.0/24` |
| WireGuard port | 51820 | 51820 |
| tunnel MTU | 1420 | 1420 |

Verified: kernel ping across the VLAN 0.15–0.24 ms, 0% loss, both directions. Optical
receive power −0.72 dBm and +0.38 dBm (healthy; the old sao-2 had −40 dBm, i.e. a dark
fibre, which is why "is the link up" is the first check on any new box).

## Software installed for the tests

`dpdk` 23.11.4, `dpdk-dev` (provides `/usr/bin/dpdk-testpmd`), `libdpdk-dev`,
`rdma-core`, `ibverbs-providers`, `wireguard-tools`; the kernel WireGuard module is in
the image. Go is not installed on the boxes: everything is cross-built on the control
box and copied. Hugepages: `sysctl vm.nr_hugepages=1024` (2 MB pages).

DPDK on a ConnectX is **bifurcated**: `mlx5_core` keeps the port, nothing is bound to
`vfio-pci`, and the kernel's `vlan.2049` interface is deleted while wgpio owns the
traffic (the kernel would otherwise claim the VLAN first).

## DPDK receive, proven on this pair

Stock `dpdk-testpmd` (promiscuous, no flow rule), tagged VLAN 2049, kernel sender:

| direction | offered | received | port `rx_packets_phy` |
|---|---|---|---|
| sao-3 → sao-2 | 6,706,688 | 5,868,374 | +5,868,381 (all that arrived) |
| sao-2 → sao-3 | 7,826,944 | 7,826,977 | +7,826,988 |

On the identical Frankfurt ConnectX-5 pair, packetio's own DPDK path did 95.9 Mpps
receive and 148.7 Mpps transmit (line rate) — the same numbers packetio's own
benchmarks recorded on this São Paulo hardware earlier.

## Harness rules that cost a day when broken

- Never run the receiver as `dpdk-testpmd -i` over ssh: with no TTY it exits on stdin
  EOF within seconds. Run it without `-i` (`--stats-period`) so it forwards until killed.
- `udpblast -flows N` cycles the **destination address** `.1 … .N`; pin a neighbour
  entry for the whole range or the sender collapses to a few hundred pps.
- Reconcile offered against received on every run, and keep a known-good control.

## Traffic path for the experiments

No third box, so the plaintext side is wgpio's own generator (`-gen`) on the encrypting
peer and its sink (`-sink`) on the decrypting peer; what is measured is the tunnel:
encrypt → wire → decrypt. Kernel and wireguard-go baselines use `udpblast` into `wg0`
on A and the `wg0` receive counter on B.

## Steering: `-steer-vlan` or `-promisc`

Because the port is bifurcated, wgpio must be told how to get the VLAN's frames. Two
ways work, and on this pair they measure the same: with all four patches on four
queues, 68-byte frames, `-steer-vlan 2049` (an rte_flow rule plus isolate mode)
delivered 13.68 Mpps and `-promisc` (no rule, take everything) 13.69 Mpps. Steering is
the default because it does not depend on nothing else being on the segment; set
`STEER=promisc` to use the other. Either way the kernel's `vlan.2049` netdev must be
deleted while wgpio runs: the VLAN is registered with the NIC by creating it, and then
the netdev has to go or the kernel takes the frames first.

## The scripts

`bench/rigsao/` drives everything: `stage.sh` copies the binaries,
`run.sh <mode>` measures one point into `bench/results/blog/results.csv` (the earlier two-box round; the three-box rig is `bench/rig3/`),
`grid.sh <step>` runs a step of the grid three times over, `gate.sh` proves the tunnel
carries traffic before anything is measured, `down.sh` puts both boxes back. The five
binaries come from `bench/build-ladder.sh`, one per state of the wireguard-go fork.

Pinning convention, recorded in every row: N queues take CPUs 2…N+1 and the TUN reader
takes N+2, leaving 0 and 1 for the operating system. There are 24 physical cores, so a
sweep past 22 queues runs onto SMT siblings and the row says so in its notes.
