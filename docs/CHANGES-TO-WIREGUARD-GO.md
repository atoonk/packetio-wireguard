# Changes to wireguard-go

wgpio's Phase 1 ran **upstream wireguard-go, unmodified** (`golang.zx2c4.com/wireguard`
at `ecfc5a8d5446`, 2026-05-22). Phase 2 runs a fork of that commit: the patches in
[`../patches/`](../patches/), applied in order, regenerated with `make patches` and
verified with `make check-patches`. This file is the ledger of every deviation. A change
is only kept if it clears a measured bar (>1–2% on the benchmark it targets, or a
documented prerequisite for one that does), and every entry carries the security
argument and the numbers. Rejected experiments are recorded here too.

## 0001 — expose transport keypairs for an inline fast path

**What it changes.** One new file, `device/fastpath.go` (additive), and five small
edits: a `keypairObserver` slot on `Device`; `shared`/`replayMu` fields on `Keypair`
with `markShared()` called unconditionally in `BeginSymmetricSession` before the
keypair is published to the index table; the sequential receiver's replay check routed
through the guarded `validateCounter`; `notifyKeypair` calls where keypairs are
established (`BeginSymmetricSession`), promoted (`ReceivedWithKeypair`) and retired
(`DeleteKeypair`, `ExpireCurrentKeypairs`). +305 lines of non-test code including
comments (+486 with the tests), 1 upstream line changed; all four patches together
are +365 −5 non-test lines. Nothing in the handshake, cookies, rate limiter,
timers, roaming or configuration is touched.

**Why.** Phase 1 ended at wireguard-go's single `RoutineReadFromTUN` goroutine:
~0.7 µs of per-packet work — allowed-IPs lookup, pool get/put, element and container
bookkeeping, two channel hand-offs — and a copy into a pooled buffer in each
direction, on one goroutine no matter how many receive queues feed it (measured: two
queues and 128-packet batches changed nothing). The fast path does the transport
crypto in the DMA frame on the receive goroutine and transmits from there; the patch
is what it needs from wireguard-go: the negotiated AEADs and indices, a replay check
that is safe against wireguard-go's own receive path, a nonce reservation that cannot
collide with wireguard-go's own sends, and the per-batch liveness calls that keep
rekeying and timers working.

**Security argument.**
- *Key material.* Only constructed `cipher.AEAD`s and indices are exposed; the key
  bytes are zeroed right after the AEADs are built, exactly as upstream, and never
  leave the package.
- *Replay.* The window (`replay.Filter`) is unsynchronised; upstream keeps it safe by
  validating each keypair only from its peer's single sequential receiver. With a fast
  path, the same keypair is validated from two places (punted packets, keepalives and
  handshake-adjacent traffic still take the stock path), and two unsynchronised updates
  to one ring block lose each other's bit, which makes an already-seen counter look
  new. So the window is under a mutex for every keypair that can be reached from
  outside the package, and `markShared` is set *before* the keypair is published, so no
  validator can observe it unshared and race a later shared one. Cost: one uncontended
  mutex per packet on the stock path too. `TestValidateCounterConcurrent` runs two
  validators on one keypair and fails with the lock removed;
  `TestEveryPublishedKeypairIsShared` fails if the mark is ever lost or made
  conditional, which is what an upstream merge would do to it.
- *Nonces.* `ReserveNonces` is a compare-and-swap that never advances the counter past
  `RejectAfterMessages`. An unconditional add would leave only 2^13 counts of headroom
  before the counter wrapped to zero and low nonces were reused under the same key.
  `TestReserveNoncesClamps` retries past exhaustion 16 k times and checks the counter
  never moves; `TestReserveNoncesCannotWrapPastTheLimit` hammers the limit from eight
  goroutines, and `TestReserveNoncesConcurrentRangesNeverOverlap` checks that 28 k
  concurrently reserved nonces are all distinct. The fast path takes every nonce it
  sends from here; wireguard-go still sends on the same keypair (keepalives, staged
  packets).
- *Reordering.* Several goroutines encrypting for one peer interleave the counter on
  the wire; the receiver's window is 131008 wide after 0003 (8128 before it). wgpio
  sends at most 64 per goroutine per turn, one FIFO per goroutine, so displacement
  stays far inside the window. This is reordering *between* inner flows, which
  nothing notices: a flow's own packets stay on one goroutine at each end (the NIC's
  RSS on the way in, and the outer source port chosen per flow on the way out), so
  the flow itself arrives in order. That second half was a bug in wgpio until the
  first TCP test: see "Spray and the order of a flow" in `docs/DESIGN.md`.
- *Lifecycle.* Retirement is announced from `DeleteKeypair`, which every rotation and
  teardown passes through, before the index is deleted; a fast path that missed a
  retirement would keep decrypting on a keypair wireguard-go has forgotten for up to
  `RejectAfterTime`. `TestKeypairObserverLifecycle` checks established/promoted/retired
  on a device pair; `TestRetirementFiresBeforeTheIndexIsRemoved` fails if the two are
  swapped, and `TestEveryEstablishedKeypairIsRetired` forces a rotation and checks no
  keypair is dropped without its retirement being announced.
- *Everything else* — handshake, cookie MAC2, rate limiting, roaming (the fast path
  reports through `FastPathReceived` the endpoint of the batch's last packet that
  passed the replay check — upstream's `validTailPacket` — so `SetEndpointFromPacket`
  runs as before; a review found the gateway first reported the endpoint before the
  check, which let a rejected replay from an attacker's MAC move the peer, fixed in
  the gateway with `TestFastPathReplayDoesNotMoveEndpoint`), timers, rekey, `wg(8)`
  — is wireguard-go's, unchanged.

**Before → after** (one queue, `-cpus 2 -tun-cpu 3`, same rig, same everything;
`bench/results/wgpio-q1*.csv` vs `wgpio-fp-q1*.csv`):

| frame | dir | stock pipeline: clean / peak | fast path: clean / peak | change |
|---|---|---|---|---|
| 68 B | fwd | 1.25 M / 3.76 M | **3.0 M / 3.53 M** | clean rate **+140%** |
| 68 B | rev | 1.25 M / 3.31 M | **3.0 M / 3.42 M** | clean rate **+140%** |
| 512 B | fwd | 2.0 M / 2.09 M (link) | 1.5 M / 1.94 M | **−25%** at the ceiling |
| 1442 B | fwd | 749 k / 821 k (link) | 749 k / 821 k (link) | 0 |

CPU at 3 Mpps of 68-byte frames: 2.0 cores on each peer, i.e. the two dedicated
spinners and nothing else — the stock pipeline used 2.5–2.9 cores to deliver 1.25 M.
At the ceiling the receive core is saturated at ~280 ns per 68-byte packet (decrypt
or encrypt, headers, forward) and ~515 ns per 512-byte packet.

**Verdict: kept, with a caveat that is part of the design, not the patch.** For
minimum-size frames the fast path clears the bar by a wide margin (2.4× the clean
rate on less CPU). For 512-byte frames one queue is *slower* at the ceiling, because
the fast path puts each queue's crypto on that queue's core while the stock pipeline
fanned it out over twelve workers; the remedy is more receive queues (the encrypting
side's LAN flows spread over them by RSS), and the multi-queue rows in BENCHMARKS.md
say whether that recovers it. On a 10G link every frame size from 512 B up was already
at the wire before this patch; the patch's value is the small-packet number here and
every number on a faster link.

**Reviewed.** Two readers, 2026-09-20: [SECURITY-REVIEW-0001.md](SECURITY-REVIEW-0001.md).
No way to break the protocol was found, and each of the four guards was shown to be
load-bearing by removing it and watching a test fail. One medium finding, that the
keypair observer runs under locks two of the new methods take, so an observer calling
them would deadlock the device; fixed by dropping the lock from `PeerPublicKey`, whose
value is written once in `NewPeer`, and by naming the forbidden methods in the
contract. The replay lock was also made unconditional: the `shared` flag it depended on
was dead in production and only offered a future merge a way to displace it. Five
adversarial tests were added here as a result.

## 0002 — `Keypair.ValidateCounters`: the replay window for a batch under one lock

**What it changes.** One additive method in `device/fastpath.go`: the same
`replay.Filter.ValidateCounter` loop, run for a batch of authenticated counters
under a single `replayMu` acquisition. No other line changes.

**Why.** With several receive cores decrypting one keypair, a mutex per packet on
that keypair's window is a serialization point: at 8 queues on the 100G rig the
decrypting side capped at ~8.6 M packets/s however many cores it had. One lock per
64-packet batch is ~60× fewer acquisitions.

**Security argument.** The window is still the same window, still under the same
lock (unconditionally, after the 2026-09-20 review), still updated by one goroutine at a time; the batch is validated in arrival
order exactly as the per-packet loop would validate it. `TestValidateCountersBatch`
checks a batch gives the same verdicts as per-packet validation.

**Before → after.** Decrypt ceiling at 8 queues, 68 B: 8.6 M → 13.3 M packets/s
(with the endpoint cache in the same iteration). **Kept.**

## 0003 — `replay`: a 131008-counter window instead of 8128

**What it changes.** `replay.ringBlocks` from `1<<7` to `1<<11`: the RFC 6479 ring is
2048 blocks of 64 bits, 16 KiB per keypair instead of 1 KiB. Nothing else.

**Why.** The window is a tolerance for reordering. With N receive queues decrypting
one keypair in parallel, the counters a queue sees lag the fastest queue by however
far behind it runs; at 31 M packets/s a window of 8128 counters is 260 µs, and at 12
queues 11.6 M packets/s were being rejected as replays. At 131008 counters the window
is 4 ms at that rate, and the rejections went to zero at 12 and 16 queues.

**Security argument.** The window's width is receiver-local and does not weaken
anti-replay: each counter is still accepted at most once (the bitmap says so), and a
counter more than 131008 behind the highest seen is still rejected. What it relaxes
is only how *late* a legitimate packet may arrive and still be accepted, from 8128
counters to 131008 — a few milliseconds at these rates. The kernel implementation
uses 8192; upstream wireguard-go 8128; RFC 6479 leaves the size to the implementation.
Memory: 16 KiB per keypair, three keypairs per peer.

**Before → after.** 12 queues, 68 B: 16.7 M delivered with 11.6 M/s replays → 27.0 M
delivered, 0 replays; 16 queues: 38.5 M delivered (40.1 M encrypted). **Kept.**

## 0004 — the fast path touches the timers at most every 50 ms per peer

**What it changes.** `FastPathReceived` and `FastPathSent` still count bytes and
promote keypairs on every batch, but `SetEndpointFromPacket`, `keepKeyFresh*` and
the three `timers*` calls run at most once per 50 ms per peer and direction,
claimed with one atomic compare-and-swap. Two `atomic.Int64` fields on `Peer`.

**Why.** Those calls modify Go timers and take the endpoint mutex; at 24 receive
cores × 30 k batches/s that was ~2 M contended operations per second for timers
that fire after 5, 10 or 120 seconds.

**Security argument.** None of the throttled calls is on the security path: they are
liveness bookkeeping (keepalive, rekey-soon, handshake-retry timers and roaming). A
50 ms delay in touching a 10-second keepalive timer or a 120-second rekey timer is
below their own jitter. The risk this patch does carry is that a throttled report
*skips* a rekey rather than delaying it, which would run a session past its nonce
budget; `TestFastPathSentStillRekeys` spends the nonces, checks that a report inside
the interval touches nothing, and then that the first report after it starts the
handshake. It fails if the throttle is made unconditional. Keypair promotion (`ReceivedWithKeypair`) and byte counters
are not throttled. Rekey under load was exercised for minutes at 40 M/s with no
session loss.

**Before → after.** 16 queues: 38.9 M → 42.0 M delivered; 24 queues: 38.6 M → 43.8 M.
**Kept.**
