# Superseded harnesses

`rig100/` drove the first pass on the São Paulo pair. It is kept for reference only and
should not be run: it names a box that no longer exists, addresses the underlay
differently, and defaults to packetio's direct-verbs backend because DPDK was believed
not to receive on that hardware — a belief that turned out to be a bug in the
measurement harness, not in DPDK.

The current São Paulo harness is `bench/rigsao/`. `bench/rig/` is the 10G Intel rig and
is still current.
