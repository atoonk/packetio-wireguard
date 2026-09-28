# Profiles, one per variant at its best queue count

Taken from the running gateway at its ceiling with `run.sh --profile`, from both peers:
`<variant>-<queues>q-f68-{dec,enc}-{cpu,mutex,block}.pprof`, with a `top` listing
beside each. 68-byte frames throughout. Read them with
`go tool pprof -top bin/wgpio-<variant> <file>`.

These were captured before the measurement clock was corrected, so the *rates* quoted
in the same runs are about 18% low. Where the CPU time went is unaffected.

## What the CPU profiles say

Decrypting peer, share of samples, top entry only:

| variant | queues | cores busy | top cost | share |
|---|---|---|---|---|
| unmodified wireguard-go | 12 | 14.4 | `runtime.cgocall` (DPDK) | 20.7% |
| 0001 fast path | 8 | 7.6 | `chacha20poly1305Open` | 38.3% |
| 0002 batch replay | 16 | 15.4 | `chacha20poly1305Open` | 39.7% |
| 0003 wide window | 16 | 15.3 | `chacha20poly1305Open` | 39.7% |
| 0004 timer throttle | 24 | 18.8 | `chacha20poly1305Open` | 36.8% |

The first row is the finding. With unmodified wireguard-go the decrypting box burns
14.4 cores and the AEAD does not appear in the top eight at all: the time goes to
`runtime.cgocall` and `Rx.Fill`, which is the receive path spinning on DPDK while the
packets queue up behind one `RoutineReadFromTUN` goroutine. It is paying for the NIC
and not for the cryptography.

From patch 0001 on, the AEAD is the largest single cost at 37-40% of samples, which is
the shape a packet processor should have: most of the machine doing the work the
machine exists to do.

## What the mutex profiles say

This is the evidence for patch 0002. Contended-lock delay attributed to `fpFlush`,
which is where the replay window is checked:

| variant | queues | total delay | delay in `fpFlush` |
|---|---|---|---|
| 0001, one lock per packet | 8 | 86.5 s | 7.08 s (8.2%) |
| 0002, one lock per batch | 16 | 375.0 s | below the 1.87 s cutoff |

Twice the queues and far more traffic, and the replay window falls out of the profile
entirely. The remaining delay in both is `runtime.unlock`, the Go runtime's own
scheduler and allocator locks, not ours.
