package gateway

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/atoonk/packetio"

	"github.com/atoonk/packetio-wireguard/internal/ether"
	"github.com/atoonk/packetio-wireguard/internal/neigh"
)

// A region and a transmit queue over plain memory: enough for the
// generator, which only allocates frames, and for the accounting that
// brings them home.
type testRegion struct {
	mem   []byte
	size  int
	nfram int
}

func (r *testRegion) Bytes() []byte                   { return r.mem }
func (r *testRegion) Frame(d packetio.Desc) []byte    { return r.mem[d.Addr : d.Addr+uint64(d.Len)] }
func (r *testRegion) Writable(d packetio.Desc) []byte { return r.mem[d.Addr:] }
func (r *testRegion) FrameSize() int                  { return r.size }
func (r *testRegion) NumFrames() int                  { return r.nfram }

// testTx is a transmit queue whose pool is a free list of whole frames. It
// records every frame freed to it, which is what the generator's frames must
// come home to: they were never the receive pool's.
type testTx struct {
	r    *testRegion
	pool []packetio.Desc // frames not handed out
	out  []packetio.Desc // scratch returned by Alloc
	back map[uint64]int  // frame index -> times freed here
}

func newTestTx(r *testRegion, first, n int) *testTx {
	t := &testTx{r: r, back: map[uint64]int{}}
	for i := first; i < first+n; i++ {
		t.pool = append(t.pool, packetio.Desc{Addr: uint64(i * r.size)})
	}
	return t
}

func (t *testTx) Region() packetio.Region { return t.r }
func (t *testTx) Alloc(n int) []packetio.Desc {
	if n > len(t.pool) {
		n = len(t.pool)
	}
	t.out = append(t.out[:0], t.pool[len(t.pool)-n:]...)
	t.pool = t.pool[:len(t.pool)-n]
	return t.out
}
func (t *testTx) Free(ds []packetio.Desc) {
	for _, d := range ds {
		ix := d.Addr / uint64(t.r.size)
		t.back[ix]++
		t.pool = append(t.pool, packetio.Desc{Addr: ix * uint64(t.r.size)})
	}
}
func (t *testTx) Transmit([]packetio.Desc) int { return 0 }
func (t *testTx) Err() error                   { return nil }
func (t *testTx) Complete(int) int             { return 0 }
func (t *testTx) Reclaim(_ int, out []packetio.Desc) []packetio.Desc {
	return out
}
func (t *testTx) NumCompleted() int                                { return 0 }
func (t *testTx) NumInFlight() int                                 { return 0 }
func (t *testTx) NumFreeSlots() int                                { return len(t.pool) }
func (t *testTx) NumFreeFrames() int                               { return len(t.pool) }
func (t *testTx) SendFunc(int, func(int, []byte) int) (int, error) { return 0, nil }
func (t *testTx) Stats() (packetio.TxStats, error)                 { return packetio.TxStats{}, nil }
func (t *testTx) Close() error                                     { return nil }

// genRig is a gateway with one receive queue, the generator on, and the fast
// path off: the arrangement the stock step of the benchmark ladder runs.
func genRig(t *testing.T, frames int) (*Gateway, *rxQueue, *testTx) {
	t.Helper()
	const frameSize = 4096
	r := &testRegion{mem: make([]byte, frames*frameSize), size: frameSize, nfram: frames}
	tx := newTestTx(r, 0, frames)
	g := &Gateway{
		cfg: Config{MTU: 1420, LANVLAN: 2049, Gen: &Gen{Size: 68, Flows: 4, Port: 9000,
			Src: netip.MustParseAddr("10.154.0.1"), Dst: netip.MustParsePrefix("10.200.3.0/24")}},
		nb: neigh.New(), log: slog.Default(), wake: make(chan struct{}, 1),
	}
	rq := &rxQueue{fr: newFrames(r), tx: tx, owned: make([]uint64, (frames+63)/64)}
	g.rx = []*rxQueue{rq}
	g.genInit(rq, 0, 1)
	return g, rq, tx
}

// Without the fast path the generator parks its packets in the LAN ring for
// wireguard-go's own pipeline. The frames come from the transmit pool, and
// the ring's drain must send them back there: recycling them into the
// receive pool would hand the NIC frames it does not own, and lose the
// transmit pool a frame on every packet generated.
func TestGeneratorWithoutFastPathReturnsFramesToTheTransmitPool(t *testing.T) {
	g, rq, tx := genRig(t, 1024)
	before := tx.NumFreeFrames()

	g.generate(rq)
	made := rq.st.GenPackets.Load()
	if made == 0 {
		t.Fatal("the generator made nothing")
	}
	if got := rq.lan.pending(); uint64(got) != made {
		t.Fatalf("%d packets parked in the ring, %d generated", got, made)
	}
	if tx.NumFreeFrames() != before-int(made) {
		t.Fatalf("pool has %d frames, want %d: the parked ones are still out", tx.NumFreeFrames(), before-int(made))
	}

	// What the parked frames hold is a LAN frame the TUN reader can copy
	// out: the link header the ring records, then the IPv4 packet.
	p, ok := rq.lan.peek()
	if !ok {
		t.Fatal("nothing to read")
	}
	f := rq.fr.mem[p.d.Addr : p.d.Addr+uint64(p.d.Len)]
	l, ok := ether.ParseLink(f)
	if !ok || l.VLAN != g.cfg.LANVLAN || int(p.off) != l.Len {
		t.Fatalf("parked frame's link header: vlan %d off %d, want %d %d", l.VLAN, p.off, g.cfg.LANVLAN, l.Len)
	}
	h, ok := ether.ParseIPv4(f[l.Len:])
	if !ok || int(p.n) != h.TotalLen || !netip.MustParsePrefix("10.200.3.0/24").Contains(netip.AddrFrom4(h.Dst)) {
		t.Fatalf("parked frame's IPv4 header: %+v len %d", h, p.n)
	}

	// The reader consumes them; the receive goroutine drains, as receive does.
	for {
		if _, ok := rq.lan.peek(); !ok {
			break
		}
		rq.lan.done()
	}
	rq.drained = rq.lan.drain(rq.drained[:0])
	rq.giveBackAll(rq.drained)

	if len(rq.recycle) != 0 {
		t.Fatalf("%d generated frames were headed for the receive pool", len(rq.recycle))
	}
	if tx.NumFreeFrames() != before {
		t.Fatalf("pool has %d frames, want %d back", tx.NumFreeFrames(), before)
	}
	for ix, n := range tx.back {
		if n != 1 {
			t.Fatalf("frame %d freed %d times", ix, n)
		}
	}
	if uint64(len(tx.back)) != made {
		t.Fatalf("%d distinct frames came home, %d generated", len(tx.back), made)
	}
}

// A received frame goes the other way: the receive pool's bitmap says so,
// and it must be recycled there even though it travelled with generated
// frames through the same ring and the same drain.
func TestDrainSortsReceivedFramesFromGeneratedOnes(t *testing.T) {
	g, rq, tx := genRig(t, 1024)
	// Frame 900 is one Receive handed us: mark it owned and park it.
	const rxFrame = 900
	ix := uint64(rxFrame)
	rq.owned[ix/64] |= 1 << (ix % 64)
	d := packetio.Desc{Addr: ix * 4096, Len: 64}
	if !rq.lan.push(parked{d: d, off: 18, n: 46}) {
		t.Fatal("ring refused the received frame")
	}
	g.generate(rq)
	for {
		if _, ok := rq.lan.peek(); !ok {
			break
		}
		rq.lan.done()
	}
	rq.drained = rq.lan.drain(rq.drained[:0])
	rq.giveBackAll(rq.drained)

	if len(rq.recycle) != 1 || rq.recycle[0].Addr != d.Addr {
		t.Fatalf("receive pool got %v, want just the received frame at %d", rq.recycle, d.Addr)
	}
	if _, ok := tx.back[ix]; ok {
		t.Fatal("a received frame was freed to the transmit pool")
	}
}

// The ring is the generator's backpressure: it must never park more than the
// ring holds, and every frame it cannot park goes straight back to the pool
// rather than being lost.
func TestGeneratorStopsAtAFullRing(t *testing.T) {
	g, rq, tx := genRig(t, 4096)
	before := tx.NumFreeFrames()
	deadline := time.Now().Add(5 * time.Second)
	for rq.lan.room() > 0 && time.Now().Before(deadline) {
		g.generate(rq)
	}
	if rq.lan.room() != 0 {
		t.Fatalf("ring still has room for %d after filling it", rq.lan.room())
	}
	g.generate(rq) // nothing to do: it must not take frames it cannot park
	if got := rq.lan.pending(); got != ringSize {
		t.Fatalf("%d frames parked, the ring holds %d", got, ringSize)
	}
	if want := before - ringSize; tx.NumFreeFrames() != want {
		t.Fatalf("pool has %d frames, want %d: %d leaked", tx.NumFreeFrames(), want, want-tx.NumFreeFrames())
	}
}
