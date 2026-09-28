// Package gateway turns one packetio device into the two halves wireguard-go
// plugs into: a conn.Bind for the tunnel's UDP on one VLAN and a tun.Device
// for the plaintext LAN on another. The gateway owns the NIC, the
// Ethernet/IP/UDP framing, ARP and ICMP echo; wireguard-go owns the
// protocol. With -fastpath (the default) transport packets are decrypted and
// encrypted in the NIC's frames on the receive goroutines (fastpath.go),
// through a small API the fork adds to wireguard-go; everything else, and
// with -fastpath=false everything, goes through wireguard-go's own pipeline.
//
// Threading follows packetio's rules. Each receive queue is driven by
// exactly one goroutine: the wireguard-go RoutineReceiveIncoming that calls
// our ReceiveFunc for that queue. Frames the tunnel does not want (LAN
// traffic) are parked in a per-queue ring for the single tun.Read goroutine
// to copy out, and are recycled by the owning goroutine afterwards, or with
// the fast path on, encrypted in place. Transmit queues that wireguard-go
// sends on are shared behind a mutex; the fast path prefers one of its own
// per receive goroutine (N+1 queues) and shares under the mutex otherwise.
package gateway

import (
	"fmt"
	"log/slog"
	"math/bits"
	"net/netip"
	"sync/atomic"

	"github.com/atoonk/packetio"
	"golang.zx2c4.com/wireguard/device"

	"github.com/atoonk/packetio-wireguard/internal/ether"
	"github.com/atoonk/packetio-wireguard/internal/neigh"
)

// Batch is how many frames a receive call takes and a send call carries.
// It is what wireguard-go sizes its per-receiver buffers from, and the unit
// of its per-batch work: a larger batch amortises RoutineReadFromTUN's
// fixed cost over more packets. Set once at startup (SetBatch), before any
// queue is opened; wireguard-go's conn.IdealBatchSize (128) is its ceiling.
var Batch = 64

// MaxBatch is wireguard-go's conn.IdealBatchSize: the most it will hand a
// Bind or take from a TUN in one call.
const MaxBatch = 128

// SetBatch changes Batch. It must be called before New.
func SetBatch(n int) {
	if n < 1 {
		n = 1
	}
	if n > MaxBatch {
		n = MaxBatch
	}
	Batch = n
}

// Route sends a destination prefix to a next hop on the LAN VLAN.
type Route struct {
	Prefix  netip.Prefix
	NextHop netip.Addr
}

// Config describes the gateway.
type Config struct {
	Device packetio.Device
	MAC    ether.MAC // the port's address, what neighbors ARP for

	UnderlayVLAN uint16       // 0 for untagged
	UnderlayIP   netip.Prefix // our address and prefix on the underlay
	ListenPort   uint16       // WireGuard's UDP port

	LANVLAN uint16
	LANIP   netip.Prefix
	Routes  []Route // beyond the LAN prefix itself, which is connected

	MTU  int   // the tunnel's MTU; larger LAN packets are dropped
	CPUs []int // CPUs[i] pins the goroutine driving receive queue i; short or empty = unpinned
	// TUNCPU pins the TUN reader to a core of its own, where it spins on the
	// rings instead of waiting to be woken through the scheduler. -1 leaves it
	// unpinned and woken.
	TUNCPU int

	Neighbors *neigh.Table // may hold static entries; nil for a fresh table
	Log       *slog.Logger

	// FastPath decrypts and encrypts in the DMA frame on the receive
	// goroutine (see fastpath.go). It needs one transmit queue per receive
	// queue plus one shared, and SetDevice plus the device's keypair
	// observer installed before the device is configured.
	FastPath bool

	// Diagnostics samples the clock on every receive call and TUN read to
	// record scheduling gaps; a few percent of a saturated core.
	Diagnostics bool

	// Name is what tun.Device.Name reports; wireguard-go logs it and the
	// UAPI socket is named after it.
	Name string

	// Spray > 0 makes the fast path send tunnel packets from Spray different
	// UDP source ports, ListenPort..ListenPort+Spray-1, rotating per packet,
	// and accept that range as ours, so the far side's RSS spreads what is
	// otherwise one 5-tuple over its receive queues (with only as many ports
	// as queues, hash collisions leave queues idle and overload others).
	// WireGuard does not care which port a peer sends from; the peer's
	// endpoint just follows the last authenticated packet. 0 = ListenPort only.
	Spray int
	// SprayByFlow chooses a packet's spray port by a hash of its inner flow
	// instead of rotating per packet. Rotation spreads one inner flow over
	// every receive queue of the peer, which then forwards its packets from
	// several goroutines in whatever order they get to them: one TCP stream
	// through the tunnel saw a million reordering events and 28k
	// retransmits in ten seconds, and eight streams ran at a third of the
	// speed. A hash keeps a flow on one outer 5-tuple, so one queue and one
	// goroutine at the peer, in order (27 events, 211 retransmits). The cost
	// is balance: an elephant flow stays on one queue, and with 64 UDP flows
	// the peak packet rate was 6% lower (38.2 vs 40.8 M at 16 queues). The
	// default; rotate is kept for the benchmark that shows the difference.
	SprayByFlow bool

	// Gen, when set, makes each receive goroutine also generate plaintext
	// packets into the tunnel (see gen.go). Sink makes decrypted packets be
	// counted and dropped instead of forwarded to the LAN.
	Gen  *Gen
	Sink bool

	// KernelTUN, when set, is one non-blocking TUN queue descriptor per
	// receive goroutine (mqtun.OpenQueues). The plaintext side is then the
	// kernel's: each receive goroutine reads its queue and encrypts what it
	// finds through the fast path, and writes what it decrypts back to it,
	// instead of the LAN VLAN. See ktun.go.
	KernelTUN []int

	// MinOffset is the backend's rule for how far into a frame a
	// descriptor may start (DPDK: 192, past its mbuf; verbs: 0).
	MinOffset int
}

// Gateway is the device with its queues and tables.
type Gateway struct {
	cfg   Config
	dev   packetio.Device
	log   *slog.Logger
	mac   ether.MAC
	nb    *neigh.Table
	rx    []*rxQueue
	tx    []*txQueue // mutex-shared, for the stock path; with FastPath only the last one
	wg    *device.Device
	fp    *fpTable
	ports uint16 // UDP ports ListenPort..ListenPort+ports-1 are ours
	// gen counts configuration changes; per-queue lookup caches carry the
	// generation they were filled at and miss after any change.
	gen    atomic.Uint32
	arp    *resolver
	uIP    [4]byte // underlay address
	lIP    [4]byte // LAN address
	rts    []route
	closed atomic.Bool

	// wake is signalled by a receive goroutine that parks a LAN frame into an
	// empty ring, so tun.Read can block instead of sleeping: a timer sleep on
	// Linux is a millisecond or more, long enough for a ring to overflow.
	wake chan struct{}

	Stats Stats
}

type route struct {
	prefix netip.Prefix
	next   [4]byte
	direct bool // connected: the destination itself is the next hop
}

// Stats are the gateway's counters, all atomic, read by the stats printer.
type Stats struct {
	RxFrames, RxTunnel, RxLAN, RxARP, RxICMP, RxOther atomic.Uint64
	LANRingFull, LANOversize, RxTruncated             atomic.Uint64
	TxTunnel, TxLAN, TxNoNeighbor, TxNoRoute, TxShort atomic.Uint64
	TxRingFull                                        atomic.Uint64 // frames the transmit ring would not take
	TxError                                           atomic.Uint64 // send calls the backend refused outright
	TxARP, TxICMP                                     atomic.Uint64
	TUNReads, TUNEmpty, TUNWakes, TUNTimeouts         atomic.Uint64 // the TUN reader's behaviour
	// Scheduling gaps: the longest pause between consecutive receive calls
	// and between consecutive TUN reads, and how many exceeded 200us.
	RxMaxGapNs, RxGaps, TUNMaxGapNs, TUNGaps atomic.Uint64
	// The fast path's own accounting.
	FPDecrypted, FPEncrypted, FPPunted, FPAuthFail, FPReplay, FPUnallowed atomic.Uint64
	FPKeepalive, FPNoPeer, FPNoKeypair, FPNoRoom                          atomic.Uint64
	// Why a frame was \"other\", for debugging a rig.
	OtherSelf, OtherType, OtherUnderlayDst, OtherLANNotOurs, OtherVLAN atomic.Uint64
	// The built-in generator and sink.
	GenPackets, GenDropped, SinkPackets atomic.Uint64
	// The kernel TUN queues driven by the receive goroutines (ktun.go).
	KTUNRead, KTUNReadDropped, KTUNWrite, KTUNWriteDropped atomic.Uint64
}

// qStats are one receive goroutine's counters, on cache lines of their own:
// a shared atomic bumped per packet from every core was half of each core.
// The fields are Stats' own, so a counter is declared once and a receive
// goroutine's copy of it never needs to be kept in step by hand.
type qStats struct {
	_ [64]byte
	Stats
	_ [64]byte
}

// Counters is a snapshot of every counter, per-queue ones summed.
type Counters struct {
	RxFrames         uint64
	RxTunnel         uint64
	RxLAN            uint64
	RxARP            uint64
	RxICMP           uint64
	RxOther          uint64
	LANRingFull      uint64
	LANOversize      uint64
	RxTruncated      uint64
	TxTunnel         uint64
	TxLAN            uint64
	TxNoNeighbor     uint64
	TxNoRoute        uint64
	TxShort          uint64
	TxRingFull       uint64
	TxError          uint64
	TxARP            uint64
	TxICMP           uint64
	TUNReads         uint64
	TUNEmpty         uint64
	TUNWakes         uint64
	TUNTimeouts      uint64
	RxMaxGapNs       uint64
	RxGaps           uint64
	TUNMaxGapNs      uint64
	TUNGaps          uint64
	FPDecrypted      uint64
	FPEncrypted      uint64
	FPPunted         uint64
	FPAuthFail       uint64
	FPReplay         uint64
	FPUnallowed      uint64
	FPKeepalive      uint64
	FPNoPeer         uint64
	FPNoKeypair      uint64
	FPNoRoom         uint64
	OtherSelf        uint64
	OtherType        uint64
	OtherUnderlayDst uint64
	OtherLANNotOurs  uint64
	OtherVLAN        uint64
	GenPackets       uint64
	GenDropped       uint64
	SinkPackets      uint64
	KTUNRead         uint64
	KTUNReadDropped  uint64
	KTUNWrite        uint64
	KTUNWriteDropped uint64
}

// Counters sums the shared counters with every queue's. The two maximum
// gap fields are maxima, not sums, and reading them resets them: they are
// "the longest pause since the last snapshot", which is what a stats line
// printed every few seconds wants to say.
func (g *Gateway) Counters() Counters {
	var c Counters
	g.Stats.addTo(&c)
	for _, rq := range g.rx {
		rq.st.addTo(&c)
	}
	return c
}

// addTo accumulates one set of counters into a snapshot.
func (s *Stats) addTo(c *Counters) {
	c.RxFrames += s.RxFrames.Load()
	c.RxTunnel += s.RxTunnel.Load()
	c.RxLAN += s.RxLAN.Load()
	c.RxARP += s.RxARP.Load()
	c.RxICMP += s.RxICMP.Load()
	c.RxOther += s.RxOther.Load()
	c.LANRingFull += s.LANRingFull.Load()
	c.LANOversize += s.LANOversize.Load()
	c.RxTruncated += s.RxTruncated.Load()
	c.TxTunnel += s.TxTunnel.Load()
	c.TxLAN += s.TxLAN.Load()
	c.TxNoNeighbor += s.TxNoNeighbor.Load()
	c.TxNoRoute += s.TxNoRoute.Load()
	c.TxShort += s.TxShort.Load()
	c.TxRingFull += s.TxRingFull.Load()
	c.TxError += s.TxError.Load()
	c.TxARP += s.TxARP.Load()
	c.TxICMP += s.TxICMP.Load()
	c.TUNReads += s.TUNReads.Load()
	c.TUNEmpty += s.TUNEmpty.Load()
	c.TUNWakes += s.TUNWakes.Load()
	c.TUNTimeouts += s.TUNTimeouts.Load()
	c.RxGaps += s.RxGaps.Load()
	c.TUNGaps += s.TUNGaps.Load()
	c.FPDecrypted += s.FPDecrypted.Load()
	c.FPEncrypted += s.FPEncrypted.Load()
	c.FPPunted += s.FPPunted.Load()
	c.FPAuthFail += s.FPAuthFail.Load()
	c.FPReplay += s.FPReplay.Load()
	c.FPUnallowed += s.FPUnallowed.Load()
	c.FPKeepalive += s.FPKeepalive.Load()
	c.FPNoPeer += s.FPNoPeer.Load()
	c.FPNoKeypair += s.FPNoKeypair.Load()
	c.FPNoRoom += s.FPNoRoom.Load()
	c.OtherSelf += s.OtherSelf.Load()
	c.OtherType += s.OtherType.Load()
	c.OtherUnderlayDst += s.OtherUnderlayDst.Load()
	c.OtherLANNotOurs += s.OtherLANNotOurs.Load()
	c.OtherVLAN += s.OtherVLAN.Load()
	c.GenPackets += s.GenPackets.Load()
	c.GenDropped += s.GenDropped.Load()
	c.SinkPackets += s.SinkPackets.Load()
	c.KTUNRead += s.KTUNRead.Load()
	c.KTUNReadDropped += s.KTUNReadDropped.Load()
	c.KTUNWrite += s.KTUNWrite.Load()
	c.KTUNWriteDropped += s.KTUNWriteDropped.Load()
	if v := s.RxMaxGapNs.Swap(0); v > c.RxMaxGapNs {
		c.RxMaxGapNs = v
	}
	if v := s.TUNMaxGapNs.Swap(0); v > c.TUNMaxGapNs {
		c.TUNMaxGapNs = v
	}
}

// New wires the queues up. The device must have been opened with at least
// as many transmit queues as receive queues (one more, when the fast path
// is to have a queue of its own), at least one of each, and without
// packetio's own affinity placement (the gateway pins receive goroutines
// itself, and transmit calls come from goroutines that must not be pinned).
func New(cfg Config) (*Gateway, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Neighbors == nil {
		cfg.Neighbors = neigh.New()
	}
	d := cfg.Device
	if d.NumRxQueues() < 1 || d.NumTxQueues() < 1 {
		return nil, fmt.Errorf("gateway: device has %d rx and %d tx queues; need at least one of each", d.NumRxQueues(), d.NumTxQueues())
	}
	if !cfg.UnderlayIP.Addr().Is4() || !cfg.LANIP.Addr().Is4() {
		return nil, fmt.Errorf("gateway: IPv4 addresses only")
	}
	maxFrame := d.Capabilities().MaxFrameSize
	if need := ether.LinkLen(cfg.LANVLAN) + 1500; maxFrame < need {
		return nil, fmt.Errorf("gateway: frames hold %d bytes, a full LAN frame needs %d", maxFrame, need)
	}
	g := &Gateway{cfg: cfg, dev: d, log: cfg.Log, mac: cfg.MAC, nb: cfg.Neighbors,
		uIP: cfg.UnderlayIP.Addr().As4(), lIP: cfg.LANIP.Addr().As4(), wake: make(chan struct{}, 1)}
	g.rts = append(g.rts, route{prefix: cfg.LANIP.Masked(), direct: true})
	for _, r := range cfg.Routes {
		if !r.NextHop.Is4() || !r.Prefix.Addr().Is4() {
			return nil, fmt.Errorf("gateway: route %v via %v: IPv4 only", r.Prefix, r.NextHop)
		}
		if !cfg.LANIP.Masked().Contains(r.NextHop) {
			return nil, fmt.Errorf("gateway: route %v via %v: next hop is not on the LAN %v", r.Prefix, r.NextHop, cfg.LANIP.Masked())
		}
		g.rts = append(g.rts, route{prefix: r.Prefix.Masked(), next: r.NextHop.As4()})
	}
	g.fp = newFPTable()
	g.ports = 1
	if cfg.Spray > 1 {
		g.ports = uint16(cfg.Spray)
	}
	nrx := d.NumRxQueues()
	// A receive goroutine needs a transmit queue of its own for the fast
	// path, and also for the generator, which allocates its frames there
	// whether or not the fast path is on.
	perQueueTx := cfg.FastPath || cfg.Gen != nil
	if perQueueTx && d.NumTxQueues() < nrx {
		what := "the generator"
		if cfg.FastPath {
			what = "the fast path"
		}
		return nil, fmt.Errorf("gateway: %s needs a transmit queue per receive queue: %d receive, %d transmit", what, nrx, d.NumTxQueues())
	}
	// With a transmit queue to spare, each receive goroutine owns one
	// outright and the stock path takes the rest. Without (a virtual device
	// with one queue pair), it shares its queue with the stock path under
	// that queue's mutex, and sorts reclaimed frames by owner.
	dedicated := perQueueTx && d.NumTxQueues() >= nrx+1
	for i := 0; i < d.NumTxQueues(); i++ {
		g.tx = append(g.tx, newTxQueue(d.TxQueue(i), g))
	}
	for i := 0; i < nrx; i++ {
		q := d.RxQueue(i)
		cpu := -1
		if i < len(cfg.CPUs) {
			cpu = cfg.CPUs[i]
		}
		rq := newRxQueue(q, cpu, cfg.ListenPort)
		// Each queue starts at a port of its own and steps by the number of
		// queues, so the ports are spread evenly. With fewer ports than
		// queues the start wraps, and queues share ports; starting outside
		// the range would send from a port the far side does not accept.
		from := uint16(i) % g.ports
		rq.sprayFrom, rq.sprayN, rq.sprayAt = from, uint16(nrx), from
		g.genInit(rq, i, nrx)
		g.ktunInit(rq, i)
		rq.fpOn = cfg.FastPath
		if perQueueTx {
			rq.tx = d.TxQueue(i)
			if !dedicated {
				rq.txShared = g.tx[i]
				g.tx[i].owner = rq
			}
			rq.owned = make([]uint64, (q.Region().NumFrames()+63)/64)
		}
		g.rx = append(g.rx, rq)
	}
	if dedicated {
		g.tx = g.tx[nrx:] // the stock path never touches the owned ones
	}
	g.arp = newResolver(g)
	return g, nil
}

// ConfigChanged invalidates every lookup cache. Call it after anything that
// may have changed the peers or their allowed IPs: IpcSet, and every UAPI
// request handled by IpcHandle.
func (g *Gateway) ConfigChanged() { g.gen.Add(1) }

// SetDevice gives the gateway the wireguard-go device it serves, which the
// fast path consults for cryptokey routing and padding. Call it right after
// device.NewDevice, then install g.Observe with dev.SetKeypairObserver
// before configuring peers.
func (g *Gateway) SetDevice(dev *device.Device) { g.wg = dev }

// Close stops the resolver and closes the device. The Bind and TUN must
// have been closed (through wireguard-go) first.
func (g *Gateway) Close() error {
	if g.closed.Swap(true) {
		return nil
	}
	g.arp.stop()
	return g.dev.Close()
}

// QueuePackets is what each receive queue has received, for the stats line:
// how RSS spread the traffic.
func (g *Gateway) QueuePackets() []uint64 {
	out := make([]uint64, len(g.rx))
	for i, rq := range g.rx {
		if st, err := rq.q.Stats(); err == nil {
			out[i] = st.Packets
		}
	}
	return out
}

// QueueDrops sums what the receive queues themselves report dropped or
// starved, for the stats line; these are packetio's counters, not ours.
func (g *Gateway) QueueDrops() (dropped, poolEmpty uint64) {
	for _, rq := range g.rx {
		if st, err := rq.q.Stats(); err == nil {
			dropped += st.Dropped
			poolEmpty += st.PoolEmpty
		}
	}
	return
}

// nextHop resolves a destination on the LAN side to the address to ARP for.
func (g *Gateway) nextHop(dst [4]byte) ([4]byte, bool) {
	a := netip.AddrFrom4(dst)
	best := -1
	for i, r := range g.rts {
		if r.prefix.Contains(a) && (best < 0 || r.prefix.Bits() > g.rts[best].prefix.Bits()) {
			best = i
		}
	}
	if best < 0 {
		return dst, false
	}
	if g.rts[best].direct {
		return dst, true
	}
	return g.rts[best].next, true
}

// vlanFor says which VLAN an IP address lives on: the underlay, the LAN, or
// neither.
func (g *Gateway) vlanFor(ip [4]byte) (vlan uint16, ok bool) {
	a := netip.AddrFrom4(ip)
	switch {
	case g.cfg.UnderlayIP.Masked().Contains(a):
		return g.cfg.UnderlayVLAN, true
	case g.cfg.LANIP.Masked().Contains(a):
		return g.cfg.LANVLAN, true
	}
	return 0, false
}

// gap records a pause between two consecutive calls on a hot path.
func gap(last *int64, maxNs, count *atomic.Uint64) {
	now := nanotime()
	if *last != 0 && now > *last {
		d := uint64(now - *last)
		if d > 200_000 {
			count.Add(1)
		}
		for {
			m := maxNs.Load()
			if d <= m || maxNs.CompareAndSwap(m, d) {
				break
			}
		}
	}
	*last = now
}

// frameOf is the fast form of Region.Frame: the frame's bytes from the
// packet start to the end of the frame, so a builder may grow a packet in
// place. Frames are a power of two in size.
type frames struct {
	mem   []byte
	shift uint
	size  int
}

func newFrames(r packetio.Region) frames {
	return frames{mem: r.Bytes(), shift: uint(bits.TrailingZeros(uint(r.FrameSize()))), size: r.FrameSize()}
}

func (f frames) packet(d packetio.Desc) []byte {
	return f.mem[d.Addr : d.Addr+uint64(d.Len)]
}

// tailroom is how many bytes lie between the packet start and the end of
// its frame: what an in-place rewrite may grow into.
func (f frames) tailroom(d packetio.Desc) int {
	return f.size - int(d.Addr&uint64(f.size-1))
}
