# Design

wgpio is WireGuard as a two-VLAN gateway on one NIC port that packetio owns.
The protocol is upstream wireguard-go, plus the four patches recorded in
[CHANGES-TO-WIREGUARD-GO.md](CHANGES-TO-WIREGUARD-GO.md). This document is
about the part that is ours: how the port is turned into the two things
wireguard-go plugs into, the fast path that later grew beside them, and why
each is shaped the way it is. The first sections describe the phase 1
pipeline, which `-fastpath=false` still runs; the fast path section says what
the default mode changes.

## The two interfaces

wireguard-go's `device.Device` talks to the world through exactly two
interfaces, both designed to be replaced:

- `conn.Bind` is its UDP socket. `Open` returns a set of `ReceiveFunc`s and the
  device starts one goroutine per function, each looping on it forever. `Send`
  is called from every peer's sender goroutine and from handshake timers.
- `tun.Device` is its network interface. `Read` is called by one goroutine
  (`RoutineReadFromTUN`), `Write` by each peer's sequential receiver.

wgpio's `Bind` is the tunnel VLAN and its `TUN` is the LAN VLAN, both on the
same port. Datagrams and packets are copied between packetio frames and
wireguard-go's own buffers, once in each direction; that is what the interfaces
require (wireguard-go owns its buffers and swaps them out of its pools), and it
is what keeps the gateway independent of the backend: nothing here needs a
shared frame region or the ability to move a frame between queues, so the same
code runs on AF_XDP, where those do not exist.

## Who drives which queue

packetio's rule is one goroutine per queue, with `Recycle` and `Fill` coming
from that goroutine. wireguard-go's rule is one goroutine per `ReceiveFunc`.
The two line up: `Open` returns one `ReceiveFunc` per receive queue, and the
goroutine wireguard-go starts for it becomes that queue's owner. It pins itself
to a CPU on its first call. So `-queues N` means N receive goroutines, N RSS
buckets on the port, and N pinned cores — with no change to wireguard-go.

One receive call is: recycle what the TUN reader has finished with (and, with
the fast path, reclaim what our transmit queue has finished with), `Fill`,
`Receive` a burst, classify each frame, then flush the fast path's batch:

| frame | what happens |
|---|---|
| tunnel VLAN, UDP to our port (or the `-spray` port range) | payload copied into wireguard-go's buffer, endpoint recorded (IP, port, **and source MAC**); with the fast path, a transport message is decrypted in place instead |
| LAN VLAN, unicast to our MAC, ≤ MTU | **parked** in this queue's ring for `tun.Read`; not recycled yet |
| ARP | learn (replies to us, requests for us); answer requests for our address |
| ICMP echo to one of our addresses | answered, so the rig can be pinged |
| anything else | counted, recycled |

Parking is the one place a frame outlives the receive call. The ring is
single-producer (the queue's goroutine) single-consumer (`tun.Read`), with a
third, producer-private index: `recycled ≤ consumed ≤ produced`. The consumer
advances `consumed` only after it has copied the packet out, and the producer
recycles up to `consumed` at the start of its next call, so no frame is
recycled while it is being read. The ring is 512 deep per queue and drops the
newest frame when full: the receive goroutine is also the tunnel's intake and
must never wait on the TUN reader.

Transmit queues have no natural owner — `Bind.Send` is called by whichever
goroutine wireguard-go is on — so each sits behind a mutex and the whole
complete-allocate-build-transmit cycle (`SendFunc`) is one critical section.
In this pipeline a transmit queue only ever carries frames it allocated
itself: a received frame is never handed to a transmit queue, even for an ARP
or ICMP reply, because a shared transmit queue's `Reclaim` could return it to
the wrong receive pool. (The fast path forwards received frames, and owns
transmit queues to make that safe; see below.) The device is opened with
packetio's affinity placement off, so a wireguard-go goroutine that happens to
touch a transmit queue is not locked to an OS thread.

## What the 10G rig taught the first version

The first build delivered 120 kpps at one queue, a third of the kernel, with
the machine idle. None of it was crypto or copies; all of it was scheduling,
and each cause was found by counting where packets went, not by guessing:

- **A timer sleep is a millisecond.** `tun.Read` backed off with
  `time.Sleep(50µs)` when the rings were empty. On this kernel that sleeps
  1.05 ms, i.e. 250–500 arrivals, more than a ring. The reader now blocks on a
  wake channel the receive path signals, or better, spins on a core of its own
  (`-tun-cpu`).
- **The transmit queue takes what it can.** packetio's `SendFunc` allocates
  frames bounded by free ring slots, and ixgbe frees transmit descriptors 32 at
  a time, so a 64-frame batch got 32 and the other 32 were dropped without
  a counter moving. Sends now retry the remainder and count what is refused.
- **Go's threads must stay off the spinning cores.** A goroutine that never
  yields owns its core; any other thread the kernel places there gets a CFS
  time-slice against it — milliseconds — and a paused encryption worker or
  TUN reader is a full ring lost. `-cpus` now removes those cores from the
  process's affinity mask before anything else starts; every thread the
  runtime creates inherits it.
- **Waking through the scheduler is slow behind a producer that never
  yields.** Even with a wake channel the TUN reader was sampled waiting or
  runnable-but-not-running most of the time while the ring overflowed. Pinning
  it to its own core and letting it spin took one queue from 480 to 995 kpps at
  1 M offered, and to 1.27 Mpps at 1.5 M.
- **A ring with three indices must measure fullness against the slowest
  one.** The parking ring's producer recycles up to `recycled`, the consumer
  advances `consumed`, and `push` tested fullness against `consumed`. In a
  burst with the reader running concurrently, `produced − consumed` stayed
  under the ring size while `produced − recycled` did not, so the producer
  overwrote slots it had not recycled, the next drain recycled a frame that
  was still parked, and the NIC reused it under the reader. After any
  line-rate burst a fixed fraction of frames stayed corrupted for the life
  of the process — 60 % loss at every rate for large frames, 94 % in one
  direction — and no counter moved, because the damage was to frames, not
  queues. A fresh process was always clean; that was the tell. The test
  `TestRingNeverOverwritesUndrained` fails on the old check.
- **ixgbe receive buffers are 1 KB-granular.** packetio's default 2048-byte
  frame leaves 1728 bytes for the packet, which the X550 rounds down to a
  1024-byte buffer; anything larger vanished. The DPDK backend now defaults to
  4096-byte frames.

What was left with one queue was wireguard-go's single `RoutineReadFromTUN`:
its per-batch cost is 40–50 µs for 64 packets, about 1.3 Mpps, and it is the
same goroutine however many queues feed it. That is the wall the phase 1
benchmarks put a number on, and the reason for the fast path.

## The fast path

`fastpath.go`. A transport message whose receiver index names a keypair the
gateway has been told about (the fork's `KeypairObserver`) is decrypted in
the NIC's frame on the receive goroutine, checked against the session's replay
window in a batch, source-checked against cryptokey routing, given a LAN link
header in front of the plaintext and transmitted. A LAN frame whose
destination a peer owns is encrypted in place — the outer headers go where
the old link header and the backend's headroom were, padding and the tag
behind — after the batch's nonces are reserved in one go. Handshakes,
cookies, keepalives from the stock path, unknown or expired keypairs, and
anything without room all go the phase 1 way. Each batch is reported to the
peer once (`FastPathReceived`/`FastPathSent`) so rekeying, timers and roaming
keep working; roaming follows the last packet of a batch that passed the
replay check, as upstream.

Forwarding a received frame means transmitting it and recycling it later, and
only the receive goroutine may recycle, so each receive goroutine wants a
transmit queue of its own: the device is opened with N+1 transmit queues, one
per receive goroutine and one for wireguard-go (`Bind.Send`, ARP, echo). When
the backend cannot give a spare queue (DPDK's `net_af_packet` vdev, so the
veth test) the fast path shares queue *i* with the stock path under its
mutex, an ownership bitmap says which completed frames came from the receive
pool, and the stock path's own sends sort completions the same way rather
than letting `SendFunc` push receive-pool frames into the transmit pool
(`txQueue.send`). Cryptokey-routing answers are cached per queue and keyed
by a configuration generation that every `wg set` bumps. Counters are per
queue on their own cache lines (see Counters below).

## Spray and the order of a flow

One tunnel is one outer 5-tuple, so a peer's NIC puts all of it on one
receive queue and one core decrypts everything: 3.2 M packets/s at 68 B on
this hardware, however many cores the peer has. Upstream wireguard-go and the
kernel live with that. wgpio does not: `-spray N` sends from N consecutive
source ports (`ListenPort..+N-1`, which the bind also accepts), so the peer's
RSS hash, which covers the UDP ports, spreads the tunnel over its queues.
The peer does not care which port a packet came from; its endpoint for us
follows the last authenticated packet, as WireGuard specifies. Measured at
16 queues: `-spray 0` 3.2 M, `-spray 16` 26.5 M (16 ports collide in 16
buckets: five queues idle, four doubled), `-spray 64` 40.9 M.

**Which port a packet takes decides whether an inner flow stays in order.**
On the encrypting side nothing reorders a flow: the NIC's RSS puts a flow's
plaintext on one receive goroutine, which reserves nonces, seals and
transmits in arrival order. Counters *between* flows interleave on the wire,
which is what the wide replay window (fork patch 0003) is for, and which
nothing above WireGuard can see. The decrypting side is where it can go
wrong. The first version rotated the spray port per packet, so consecutive
packets of one TCP connection arrived at the peer with different outer
tuples, landed on different queues, and were forwarded by different
goroutines in whatever order they got to them. The packet-rate benchmarks
never noticed (64 UDP flows blasted at line rate showed zero out-of-order
datagrams: the skew between goroutines is small against a flow's own
spacing). Real TCP noticed at once: one stream through the tunnel saw 1.6 M
reordering events (`TcpExtTCPSACKReorder` at the sender) and 28 k
retransmits in ten seconds; eight streams ran anywhere between 16 and
46 Gbit/s from run to run.

`-spray-mode flow`, the default, picks the port from a hash of the inner
5-tuple (`sprayPort`, `flowHash`: two multiplications and a fold, taken
*before* the seal, which encrypts the packet in place). A flow then keeps one
outer tuple for its life, so one queue and one goroutine at the peer, in
order. Same test: 27 reordering events and 211 retransmits on one stream,
12 / 66 / 89 Gbit/s for 1 / 8 / 32 streams, 64 Gbit/s in reverse, against
kernel WireGuard's 7–8 Gbit/s at its packet ceiling. The one thing that still
reorders a flow is the handoff to wireguard-go's own pipeline before the
first keypair and briefly at rekey, a handful of packets each time.

**What it costs.** Balance becomes per flow instead of per packet: an
elephant flow stays on one of the peer's queues and is capped at that core's
decrypt rate (about 3 M packets/s: 3–4 Gbit/s at 130-byte packets, line rate
at 1442). With 64 UDP flows over 64 ports the peer's busiest queue carried
twice its lightest, and the peak at 16 queues was 38.2 M against 40.8 M for
rotation; the clean rate, 34 M, was the same. That is the trade every kernel
already makes with RSS and RPS. `-spray-mode rotate` is kept for the
benchmark that shows the difference, not for use.

Two lessons from finding this, for whoever measures next. `TcpExtTCPOFOQueue`
on the receiver counts segments queued out of order for any reason, loss
included, and was in the millions either way; only the sender's
`TcpExtTCPSACKReorder` separates reordering from loss. And the first fix
hashed the packet after sealing it, a hash of ciphertext, so every packet
still took a random port and reordered exactly as badly; a unit test of the
hash passed, and only a test through `fpSeal` caught it
(`TestSprayByFlowReadsThePlaintextNotTheCiphertext`).

## Endpoints and roaming

A tunnel datagram's endpoint carries the MAC it arrived from. wireguard-go
replaces a peer's endpoint with the one from every authenticated packet, so
replies always go to the MAC the peer last used and roaming across IPs, ports
or MACs needs no ARP. `DstToBytes` (cookie MAC2 input) is IP and port only, as
in the standard bind, so a peer whose L2 path changes keeps its cookies.
Endpoints from configuration have no MAC; sends to them resolve through the
neighbor table and trigger ARP, and wireguard-go's own handshake retry covers
the gap.

## Framing

Outer packets are Ethernet + 802.1Q + IPv4 + UDP built in software. The IPv4
header checksum is computed; the UDP checksum is zero, which IPv4 permits, since
the WireGuard payload authenticates itself. Frames are padded to 60 bytes. The
largest outer frame is 18 + 20 + 8 + 16 + 1420 + 16 = 1498 bytes, inside the
1522 the VLAN link carries and the 4096-byte frames the DPDK backend defaults
to (the X550 needs that; see above).

Plaintext packets from the tunnel go out on the LAN VLAN to the MAC of their
next hop: the destination itself when it is on the LAN prefix, otherwise the
next hop of the matching `-route`. A ping to the gateway's own LAN address
through the tunnel is answered back through it. Packets larger than the
tunnel MTU arriving on the LAN are dropped and counted; there is no
fragmentation and no PMTUD, so hosts behind the gateway need an MTU of 1420
or MSS clamping. Peers must be on the underlay VLAN's own segment: there is
no underlay routing.

## Counters

Every counter exists twice: once shared (`Gateway.Stats`), which the stock
path and the control paths bump, and once per receive goroutine (`qStats`,
the same fields behind cache-line padding), which the fast path bumps. That
split is not tidiness: one shared atomic incremented per packet from
twenty-four cores was half of each core, measured on the first 10G rig.
`Counters()` sums the two, and the stats line prints the sum.

Two things follow that a reader of the stats line needs to know. The
`*_slow` counters — `rx_tunnel_slow`, `rx_lan_slow`, `tx_tunnel_slow`,
`tx_lan_slow` — count only what went through wireguard-go's own pipeline;
with the fast path on, the traffic is in `fp_dec` and `fp_enc`, and a busy
tunnel shows single digits there. And the two gap maxima are maxima since
the last snapshot, not totals: reading them resets them.

## What is deliberately not here

IPv6, fragmentation, NAT, dynamic routing, underlay routing, kernel
coexistence on the same port, and any change to wireguard-go beyond the four
recorded patches. Everything in the first sections is the cost of running
WireGuard on a raw port, and it is small; the fast path is what the phase 1
benchmarks motivated, and every change to wireguard-go it needed is in
[CHANGES-TO-WIREGUARD-GO.md](CHANGES-TO-WIREGUARD-GO.md) with its security
argument and its numbers.
