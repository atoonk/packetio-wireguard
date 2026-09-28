# Notes for packetio from building wgpio

Things the library did that cost a debugging round here, in the order they
were found. Each is a candidate change in packetio itself; wgpio works
around every one.

1. **`SendFunc` takes fewer frames than asked, silently.** `Alloc` is bounded
   by free ring slots, and ixgbe frees transmit descriptors 32 at a time, so
   `SendFunc(64, …)` builds and sends 32 and returns 32. A caller that treats
   the count it passed as the count that went out loses half of every batch.
   The doc says "takes up to count" and the return value is right, but the
   ergonomics invite the bug: a `SendFunc` that loops `Complete`/`Alloc` until
   it has `count` frames or the pool is truly empty would match what callers
   expect. (wgpio retries the remainder, `internal/gateway/tx.go`.)

2. **ixgbe receive buffers are 1 KB-granular.** The default 2048-byte frame
   leaves 1728 bytes for the packet; the X550 programs a 1024-byte buffer from
   that and drops everything larger with no counter moving. Either round the
   frame size up on this PMD (4096 → 3776 → 3 KB buffers), enable
   `RTE_ETH_RX_OFFLOAD_SCATTER`, or refuse to open with an MTU the buffer
   cannot hold. (wgpio defaults to 4096-byte frames on DPDK.)

3. **`autoPin` pins the first goroutine that touches a queue** — for a
   transmit queue driven from many goroutines that is whichever one got there
   first, permanently `LockOSThread`ed. `WithoutAffinity()` avoids it, but the
   default catches a `conn.Bind`-style caller by surprise.

4. **NIC-level receive drops are a backend-specific call.** When the receive
   pool is short the card drops on the wire; `dpdk.(*Device).PortStats()` has
   it (`Missed`, `NoBuffer`) but `packetio.Device` does not, so a
   backend-neutral caller cannot close its conservation ledger without a type
   switch. `RxStats.Dropped` is documented as that figure "when the backend
   can report it"; wiring the port's missed count into it on DPDK would do.

5. **A day lost to a test harness, not a driver.** On 2026-09-19 a long investigation
   concluded that DPDK's mlx5 PMD could not receive on a ConnectX-6 Dx: stock
   `dpdk-testpmd` reported `RX-total: 0` in every configuration, across two kernels, two
   DPDK versions, both steering modes, both flow engines, isolation on and off, several
   rule shapes, and a clean re-image. **That conclusion was wrong.** The receiver was
   started as `dpdk-testpmd -i --cmdline-file=...` over ssh; `-i` is interactive, a
   non-TTY ssh session gives EOF on stdin, and testpmd ran the command file and exited
   *seconds before the test traffic started*. Every zero was testpmd not being alive.

   The tell was there and was missed: a known-good control — the 10G Intel X550 rig that
   had already run wgpio at line rate — showed the same zero. When a control that must
   work also fails, the harness is the suspect.

   Run a receiver without `-i` so it forwards until killed:

       dpdk-testpmd -l 2-4 -n 4 -a <pci> --file-prefix=r -- \
         --rxq=2 --txq=2 --nb-cores=2 --total-num-mbufs 32768 \
         --forward-mode=rxonly --stats-period 2

   and when flow commands are needed, hold stdin open: `(cat cmds; sleep 30) | testpmd
   ... -i`. With that fix every card received 100% of the offered load on the first
   attempt — Intel X550 4,413,440/4,413,440; ConnectX-5 8,096,768/8,096,768 (and
   8,102,924/8,102,912 in reverse); ConnectX-6 Dx 6,942,230/6,942,208 — promiscuous,
   with no steering rule, with or without a kernel VLAN netdev.

   Two real notes survive the correction. `--total-num-mbufs 32768` is worth passing on
   NUMA-heavy hosts, where testpmd's default pool fails with "Creation of mbuf pool for
   socket N failed: No buffer space available". And DPDK 23.11's `bnxt` PMD does not
   know the BCM57608 (device id `1760`); 24.11 does.

   *For packetio.* `examples/dpdk/drop` already fetches `PortXStatsMap()` but prints only
   ENA keys; printing `rx_packets_phy`, `rx_steer_missed_packets` and the kernel netdev's
   `rx_packets` would make "who took these frames" a one-line answer instead of a day.

The measured fixes are in `docs/DESIGN.md` ("What the 10G rig taught").

## A sentinel for "this device has fewer queues than you asked for"

`dpdk.Open` reports a queue count it cannot satisfy with a plain
`fmt.Errorf` (`dpdk/device.go`: "%s allows %d receive and %d transmit queues,
and %d and %d were asked for"). A caller that wants to react to exactly that
— wgpio asks for one transmit queue more than it has receive queues, and
falls back to sharing one when the device has no spare — cannot, without
matching on the message. We matched on the string for a while, then gave up
and made the fallback "retry with fewer queues, and if that fails too report
the first error", which is robust but blunt: it retries after errors that
have nothing to do with queues.

Wrapping that error in `ErrUnsupported`, or adding an `ErrTooManyQueues`,
would let a caller ask the question directly. The same applies to the
`Capabilities.MaxQueues` route: it is only readable from an open device, so
it cannot answer "how many can I ask for?" before the first `Open`.
