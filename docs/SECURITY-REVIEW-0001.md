# Security review — patch 0001, the fast-path API

**Status: the findings below are fixed.** F1, F2, F3 and the F5/F7 documentation gaps
were applied on 2026-09-20; F4, F6, F8 and F9 were judged not worth code and are
recorded as they stand. The fork fixes live inside the patches they belong to, so the
series is still four commits and `make check-patches` still rebuilds it. See "What was
applied" at the end.

Reviewed 2026-09-20 by two readers: the author of the patch, and an independent reader
given the same brief and no sight of the author's draft. Both read the fork at commit
`10000a5` (`patches/0001-*.patch`, 305 non-test lines) and the caller that consumes it.
Where they agree the agreement is noted, because two readers finding the same thing
independently is worth more than one reader finding it twice.

**Verdict: no way to break the protocol was found.** Anti-replay, nonce uniqueness,
source validation and keypair lifecycle all hold, and the four guards that enforce them
were each shown to be load-bearing by removing them and watching a test fail. One
medium defect was found, and it is a trap for a future caller rather than an attack:
two methods the patch adds deadlock the device if an observer calls them. Two low
findings, five informational, and one deliberate departure from both reference
implementations that is stated as a limitation rather than fixed.

## What was reviewed

**Fork** (`../wireguard-go-packetio` at `10000a5`): `device/fastpath.go`, and the five
hooks in `device.go`, `keypair.go`, `noise-protocol.go`, `peer.go`, `receive.go`.

**Caller** (this repository): `internal/gateway/fastpath.go`, `replay_*.go`, `rx.go`
`classify`, `internal/ether` parsing, `cmd/wgpio/observer_fastpath.go`. The API's
safety depends on the caller keeping the rules the patch header sets out, so a review
of the patch alone would have been a review of half the system.

Out of scope: patches 0002–0004, packetio, DPDK, the benchmark harness, and the
handshake, cookie and rate-limiter code, which the patch does not touch.

## Threat model

An attacker on the underlay can send any datagram to the 64 accepted ports, replay
captured datagrams from any source address or MAC, and reorder, delay or drop. A host
on the plaintext LAN can send any frame: any source address, malformed headers, any
placement within its buffer. The far peer is honest but concurrent, rekeying and
roaming while its stock-path traffic validates the same keypairs the fast path does.
Sessions age; counters approach their limit; keypairs rotate under load. A compromised
gateway process, side channels beyond upstream's, and volumetric denial of service are
out of scope, though anything the patch makes *cheaper* for an attacker is in.

## Properties

| | property | verdict |
|---|---|---|
| P1 | each counter accepted at most once, whichever path validates it | **holds** |
| P2 | no nonce used twice under one key, by any sender | **holds** |
| P3 | the counter cannot pass the limit or wrap | **holds** |
| P4 | never decrypt with, or send on, a keypair the device would refuse | **holds**, bounded window (F5) |
| P5 | forward only well-formed, source-checked packets; a replay cannot roam the peer | **holds** |
| P6 | rekey, keepalive, roaming and promotion still work | **holds**, nit (F3) |
| P7 | no new key exposure; no new deadlock | **holds for key material; F1 for locks** |

### P1 — anti-replay

One entry point, `Keypair.validateCounter`, taken by both the fast path and upstream's
sequential receiver, holding `replayMu`. `markShared()` runs in `BeginSymmetricSession`
*before* `SwapIndexForKeypair` publishes the keypair, and `new(Keypair)` there is the
only constructor in non-test code, so no validator can reach a keypair before it is
marked. The caller validates only after the AEAD opens, so a forged counter cannot
advance the window.

Both readers confirmed independently. Demonstrated: with `replayMu` removed, the new
`TestReplayWindowAcceptsEachCounterExactlyOnceUnderContention` fails with "counter 34
accepted 2 times", and the pre-existing `TestValidateCounterConcurrent` fails with
"counter 112706 accepted 2 times".

### P2 and P3 — nonces

Two senders share one `atomic.Uint64`: the fast path's compare-and-swap range
reservation, and upstream's `sendNonce.Add(1)-1` followed by a park at the limit. Both
are atomic read-modify-writes on one word, so an interleaving `Add` makes a CAS retry
and two CASes cannot succeed from the same value; every issued nonce is distinct. The
fast path never advances past `RejectAfterMessages`; upstream's transient overshoots
are each parked immediately, so the 2^13 headroom before wrap is unreachable.

Demonstrated: `TestNoncesUniqueAcrossFastAndStockSenders` runs six CAS reservers
against four upstream-style adders on one keypair starting 20,000 below the limit. No
duplicate, none at or past the limit, counter parked. Replacing the CAS with a plain
`Add` fails it immediately with "nonce 18446744073709543423 at or past the limit".

### P4 — keypair lifecycle

`FastPathSendKeypair` is `SendStagedPackets`' guard plus `isRunning`/`isUp`, and
returns `Current()` only, so a responder's `next` keypair can never be sent on before
promotion. `ReserveNonces` re-checks expiry and budget, so even a stale pointer held
across `ExpireCurrentKeypairs` cannot send. `KeypairRetired` fires *before*
`indexTable.Delete`, which is what makes index reuse safe. See F5 for the one window.

### P5 — forwarding and roaming

Checked against upstream's sequential receiver line for line: counter, promotion,
keepalive, IPv4 header and total length, source in allowed IPs equal to the
authenticating peer, IPv6, else drop. `ether.ParseIPv4` is stricter than upstream: it
also rejects a header length below five words. The endpoint is recorded per packet and
adopted only for a packet the replay check accepted. The ICMP echo answer for the
gateway's own address is reached only after the source check, is one-for-one, and goes
back to the authenticating peer, so it cannot reflect or amplify to a third party. The
seal's bounds are checked before any byte is written, at both the front and the back
of the frame.

Demonstrated by four new caller tests. Removing the source check fails the forgery
test ("0 packets dropped as unallowed, want 3"); removing the room check fails the
placement test.

### P6 — liveness

`FastPathReceived` performs, per batch, exactly the bookkeeping upstream's sequential
receiver performs per batch, in the same order, and `FastPathSent` mirrors the
sequential sender. Responder promotion happens on the fast path. See F3.

### P7 — key material and locks

No key bytes leave the package: the accessors return the AEAD objects upstream already
holds, and the raw keys are zeroed on the same line as upstream. What widens is reach,
from `package device` to any holder of a `*Keypair`. That is the point of the patch and
should be understood as such. For locks, see F1.

## Findings

### F1 — medium — an observer that calls `PeerPublicKey` or `FastPathSendKeypair` deadlocks the device. Introduced.

Found independently by both readers.

The observer runs with the peer's `keypairs` lock held at every call site, and with the
`handshake` mutex write-locked from `BeginSymmetricSession`. Measured, not assumed:
`TestObserverRunsUnderTheHandshakeAndKeypairLocks` reports "3 events: handshake mutex
held during 2, keypairs lock held during 3". `PeerPublicKey` takes the handshake mutex
for reading; `FastPathSendKeypair` takes the keypairs lock through `Current()`. Go's
`RWMutex` does not grant a read lock to a goroutine already holding the write lock, so
either call from the callback blocks forever, holding the peer's locks, stalling that
peer's handshakes and its receive path.

No attacker can trigger this and the shipped caller is safe: `Observe` calls only
`LocalIndex`, `ReceiveCipher` and its own leaf-mutex table. It is a trap for the next
caller, and a well-baited one. `PeerPublicKey` was added "for tables and logs", and a
table keyed by public key filled from the observer is its obvious use. The independent
reader added the sharper point: `KeypairEstablished` does not say whether the keypair
landed in `current` or `next`, and `isInitiator` is unexported, so
`FastPathSendKeypair` is precisely what an observer author would reach for to find out.

Demonstrated: `TestObserverMayCallPeerPublicKey` hangs, with the stack
`PeerPublicKey → RWMutex.RLock` under `BeginSymmetricSession`.

**Fix.** `handshake.remoteStatic` is written once, in `NewPeer`, before the peer is
published, so `PeerPublicKey` needs no lock at all; deleting it makes the demonstrating
test pass. The observer's contract should then name exactly which locks are held and
which methods are therefore forbidden. Optionally, export `Keypair.IsInitiator()` or
carry the slot in the event, so an observer never needs `FastPathSendKeypair`.

### F2 — low — the caller's cryptokey-routing cache can serve a stale answer briefly after a configuration change. Pre-existing in the caller; surfaced by this review.

Found by the independent reader, verified by the author.

`peerFor` caches allowed-IP answers per queue, keyed by a generation counter bumped by
`ConfigChanged`. That is called from the UAPI hook only when the response containing
`errno=` is written, which is *after* `IpcSet` has already applied the change. For the
remainder of the request, a cached entry from before the change is still served.

Concretely: an operator moves a prefix from peer A to peer B; during that window a
packet authenticated by A carrying that source address is still accepted, where
upstream would drop it, and LAN traffic for it is still sealed to A. The window is
sub-millisecond and operator-triggered, which is why it is low and not high. Peer
removal is not affected: the peer's keypairs are retired first.

**Fix.** Bump the generation from inside the device when allowed IPs change, or bump
both before and after each UAPI request.

### F3 — low, liveness — `anyData` is set after the source check; upstream sets it before. Introduced (caller).

Found by the independent reader, verified by the author.

Upstream marks a batch as carrying data for any non-keepalive packet, before parsing
and the source check. The caller marks it only after the source check passes. A peer
all of whose data packets are malformed or disallowed therefore gets no
`timersDataReceived`, so no keepalive is scheduled back, and the far side re-handshakes
on its own timer. Not a security issue. One line: move the assignment above the parse.

### F4 — low — a reservation that does not fit whole burns the tail of the nonce space. Introduced.

`ReserveNonces` refuses a range that would cross the limit and parks the counter, so up
to 63 nonces below the limit are never issued (measured between 0 and 40). The receiver
tolerates a gap and the rekey arrives a few packets early on a budget of 2^60. Worth
knowing, not worth API surface to fix; the new test bounds it so a regression that
starts burning more is caught.

### F5 — info — a retired keypair can decrypt for the remainder of one receive turn.

The caller's index table is copy-on-write, so a receive goroutine that loaded the map
just before a retirement finishes its turn with the old keypair: at most one batch,
microseconds. Upstream holds `elem.keypair` across two queues, an equal or longer
window; the kernel has an RCU grace period. Both readers judged it acceptable. It
should be said in the `KeypairRetired` comment rather than left implicit.

### F6 — low, liveness — a rekey can start on a polling receive core.

`FastPathReceived`/`FastPathSent` call `keepKeyFresh*` and `SendStagedPackets`
synchronously, which can reach `SendHandshakeInitiation` and then `Bind.Send`, which in
this gateway waits up to about 20 ms for an unresolved neighbour. Upstream makes these
calls from goroutines that are not on a packet path. Rate-limited by `RekeyTimeout`,
and absent entirely with a static `-neighbor`, which is how the rig runs.

### F7 — info — `KeypairRetired` may carry a nil peer.

The peer is resolved from the index table, which could in principle already be empty.
Neither reader could construct the path, and the caller ignores the peer on retirement.
The contract should say it may be nil.

### F8 — info — transmit-ring accounting after a full ring.

Raised by the independent reader. When the transmit ring refuses frames, the batch
takes them back from whichever peer sent the most, a heuristic that is exact with one
peer, and still reports them as sent. It only happens when the ring is full and it
affects a counter and a keepalive timer, not correctness.

### F9 — stated limitation, not a defect — the fast path abandons wire order.

Both reference implementations reserialise: the kernel through padata's ordered
completion, wireguard-go through its per-peer sequential sender. This design does not.
Packets leave interleaved by up to cores times batch size, which is why patch 0003
widens the replay window. The protocol permits it and anti-replay is unaffected. The
cost falls on a single TCP flow inside the tunnel, whose far receiver sees reordering,
and that was not measured. The remedy, out of scope here, is to spray by inner flow
rather than per packet: hash the plaintext five-tuple to the source port, and each flow
stays on one decrypting core and leaves in order while many flows still spread.

## Fail-open paths checked and found closed

Unknown, retired or expired receiver index punts to the stock path. Authentication
failure drops rather than punts, so a forged datagram cannot be retried. Replay-failed
frames are returned and leave the endpoint untouched. Underlay frames cannot reach the
encryptor and LAN frames cannot reach the decryptor. Frames with our own source MAC are
dropped. Handshakes, cookies and junk take the stock path. The listen-port range check
is unsigned-wrap safe at both ends. `FastPathSendKeypair` returns nil for a stopped
peer, a down device, no keypair, an exhausted budget or an expired keypair.
`ReserveNonces` refuses zero, oversized, expired and exhausted. Every established
keypair is eventually retired, including on device down and peer removal. The observer
is installed before any peer is configured. Padding is stripped by forwarding the IP
total length. Nothing is cheaper for an attacker than upstream: one AEAD open per
datagram with a known index.

## Not proven

- **More than one peer.** Every test and every measurement in this project is a single
  pair. The cryptokey-routing checks are per peer and were tested with a second peer
  configured, but no multi-peer load was run.
- **Long duration.** The suites run for seconds under the race detector. A soak of
  hours through forced rekey churn, with the fast path and stock path validating
  concurrently throughout, has not been done and is the single best next investment.
- **The effect of F9's reordering** on a TCP flow inside the tunnel.
- **F5 by construction.** It is bounded by argument and by the batch size, not by a
  proof.
- **Whether F7's nil-peer path is reachable at all.**
- The independent reader also could not determine the real DPDK headroom values on the
  rig, or whether the three later patches preserve P1 and P6, having only run their
  tests.

## What was applied

| finding | what changed | where |
|---|---|---|
| F1 | `PeerPublicKey` takes no lock; the observer contract names which locks are held and which methods are therefore forbidden | patch 0001 |
| F3 (fork) | the replay lock is unconditional; the `shared` flag, `markShared` and the dead branch are gone, in both `validateCounter` and `ValidateCounters` | patches 0001 and 0002 |
| F5, F7 | the retirement window and the possible nil peer are stated in the API comments | patch 0001 |
| F2 | the cryptokey-routing generation is bumped when a UAPI request *arrives* carrying a key that can move an address, as well as when it completes | `cmd/wgpio/main.go` |
| F3 (caller) | `anyData` is set before the header checks, as upstream sets `dataPacketReceived` | `internal/gateway/fastpath.go` |
| tests | the five adversarial tests are folded into patch 0001, where they belong; the deadlock test is no longer skipped, because it now passes | patch 0001 |

Deliberately not changed: **F4** (a partial final nonce batch is refused whole; a test
bounds it), **F6** (a rekey can start on a receive core; bounded and absent with a
static neighbour), **F8** (transmit-ring accounting when the ring is full), and **F9**
(wire order), which is a design decision with a stated remedy rather than a defect.

Removing the `shared` flag is worth a note. It was not wrong; it was *conditional*, and
what it made conditional was the single most security-critical line in the fork. Every
keypair the index table can hand out was marked, so the unlocked branch was already
dead in production, and the only thing the flag really bought was a way for a future
upstream merge to move the marking and silently re-open the race. The lock is now taken
always, at no measured cost.

## Reproducing

```bash
# the fork's suite, including the five adversarial tests
cd ../wireguard-go-packetio && go test -race -count=3 ./device/ ./replay/

# the caller's suite, including the six new adversarial tests
cd ../packetio-wireguard && go test -race -count=3 ./internal/gateway/
```

Each guard was shown to be load-bearing by removing it in a scratch copy and watching
the corresponding test fail: the replay mutex, the nonce compare-and-swap, the inner
source check, and the frame-room check.
