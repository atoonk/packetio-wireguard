# Ideas for later

Things the measurements pointed at that are out of scope for now. Each one says
what number it would move and why we think so, so the next person (probably me)
can decide whether it is worth the rig time.

## vhost-net / virtio-user instead of the TUN

**The problem it solves.** With a kernel TUN on the plaintext side, wgpio's fast
path is capped at about 0.6 M packets/s per core: 5 M on 8 cores, 8 M on 16
(`bench/results/rig3`, `wgpio-tun` p1..p4, isolated). The whole cost is the TUN
itself: it moves exactly one packet per `read` or `write` system call, and
nothing in wireguard-go or the patches touches that. Patches 2–4 measured as no
change with a TUN, for that reason.

**The idea.** Replace the TUN queues with a `virtio-user` device backed by the
kernel's `vhost-net`. The kernel sees an ordinary netdev (a tap); userspace fills
shared-memory rings and kicks once per batch, so 64 packets cost one notification
instead of 64 syscalls. It is how DPDK applications have always handed packets to
the kernel at rate. It would sit exactly where the TUN queues sit now
(`internal/gateway/ktun.go`: one queue per receive core, read → fpEncrypt, fpDecrypt
→ write), so the fast path does not change.

**What to expect.** Somewhere between the 5 M of the TUN and the 20 M of the
all-userspace gateway on 8 cores. The kernel's forwarding of each packet still has
to happen, which the kernel-forwarding baseline puts at ~15–20 M on this box, so
that becomes the next wall.

**Caveats.** packetio's DPDK backend would have to open a second device (a
`net_virtio_user` vdev) alongside the NIC, and the mlx5/AF_XDP backends have no
equivalent, so this is DPDK-only. The kernel side needs `vhost-net` loaded and a
tap; multi-queue is supported. Worth a day to prototype, and it should be
measured on the same three-box loop as everything else.

## Also noted

- **Multi-queue TUN for upstream wireguard-go.** `cmd/wggo-mq` shows 4× (350 k →
  1.5 M) with no protocol change and no packetio, just N TUN queues and a reader
  per queue. The reader goroutine (`RoutineReadFromTUN`) is the next wall at
  ~1.6 M/core; upstream would need N of them. Upstreamable in principle.
- **Batched TUN I/O on the sockets side.** `cmd/wggo-fast` is limited by the
  kernel's UDP receive path (2.5 M clean on 8 cores, no gain at 16). AF_XDP on the
  encrypted side would remove that path while keeping the TUN, which is a
  different, kernel-only design: the multi-queue TUN plus an AF_XDP socket per
  queue. packetio's afxdp backend already exists, so this is mostly wiring.
