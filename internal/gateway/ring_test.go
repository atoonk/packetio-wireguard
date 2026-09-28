package gateway

import (
	"testing"

	"github.com/atoonk/packetio"
)

func TestRing(t *testing.T) {
	var r ring
	for i := 0; i < ringSize; i++ {
		if !r.push(parked{d: packetio.Desc{Addr: uint64(i)}}) {
			t.Fatalf("push %d refused", i)
		}
	}
	if r.push(parked{}) {
		t.Fatal("full ring accepted a frame")
	}
	if len(r.drain(nil)) != 0 {
		t.Fatal("drained frames nobody consumed")
	}
	for i := 0; i < 10; i++ {
		p, ok := r.peek()
		if !ok || p.d.Addr != uint64(i) {
			t.Fatalf("peek %d: %+v ok=%v", i, p, ok)
		}
		r.done()
	}
	out := r.drain(nil)
	if len(out) != 10 || out[9].Addr != 9 {
		t.Fatalf("drained %v", out)
	}
	if len(r.drain(nil)) != 0 || !r.push(parked{}) || r.pending() != ringSize-9 {
		t.Fatal("ring did not free the drained slots")
	}
}

// TestRingNeverOverwritesUndrained models the receive goroutine and the TUN
// reader running concurrently: the producer must never hand back a frame
// the consumer has not finished with, and must never hand one back twice,
// however the two interleave.
func TestRingNeverOverwritesUndrained(t *testing.T) {
	var r ring
	const total = 200000
	seen := make(map[uint64]int)
	done := make(chan struct{})
	go func() { // consumer
		for n := 0; n < total; {
			if _, ok := r.peek(); ok {
				r.done()
				n++
			}
		}
		close(done)
	}()
	var next uint64
	var out []packetio.Desc
	for next < total {
		if r.push(parked{d: packetio.Desc{Addr: next}}) {
			next++
		}
		out = r.drain(out[:0])
		for _, d := range out {
			seen[d.Addr]++
		}
	}
	<-done
	for _, d := range r.drain(nil) {
		seen[d.Addr]++
	}
	if len(seen) != total {
		t.Fatalf("recycled %d distinct frames of %d", len(seen), total)
	}
	for a, c := range seen {
		if c != 1 {
			t.Fatalf("frame %d recycled %d times", a, c)
		}
	}
}
