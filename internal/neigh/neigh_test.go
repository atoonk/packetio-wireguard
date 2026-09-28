package neigh

import (
	"testing"

	"github.com/atoonk/packetio-wireguard/internal/ether"
)

func TestLearnAndStatic(t *testing.T) {
	tb := New()
	ip := [4]byte{10, 154, 0, 1}
	m1, m2 := ether.MAC{1, 1, 1, 1, 1, 1}, ether.MAC{2, 2, 2, 2, 2, 2}
	if _, ok := tb.Lookup(ip); ok {
		t.Fatal("empty table knows something")
	}
	if !tb.Learn(ip, m1) || tb.Learn(ip, m1) {
		t.Fatal("first learn must change, repeat must not")
	}
	if !tb.Learn(ip, m2) {
		t.Fatal("a changed MAC must be learned")
	}
	if got, _ := tb.Lookup(ip); got != m2 {
		t.Fatal("lookup returns the old MAC")
	}
	tb.Set(ip, m1)
	if tb.Learn(ip, m2) {
		t.Fatal("learning overrode a static entry")
	}
	if got, _ := tb.Lookup(ip); got != m1 || tb.Len() != 1 {
		t.Fatal("static entry lost")
	}
}

func TestBound(t *testing.T) {
	tb := New()
	for i := 0; i < Max+10; i++ {
		tb.Learn([4]byte{10, 0, byte(i >> 8), byte(i)}, ether.MAC{1})
	}
	if tb.Len() != Max {
		t.Fatalf("table grew to %d", tb.Len())
	}
}

// A flood of forged senders must not leave the table unable to learn a real
// neighbor ever again: past Max the oldest learned entry makes room.
func TestFullTableEvictsOldest(t *testing.T) {
	tb := New()
	tb.Set([4]byte{10, 0, 0, 1}, ether.MAC{1, 1, 1, 1, 1, 1}) // static: never evicted
	var mac ether.MAC
	for i := 0; i < Max+500; i++ {
		tb.Learn([4]byte{byte(i >> 16), byte(i >> 8), byte(i), 9}, mac)
	}
	if got := tb.Len(); got > Max {
		t.Fatalf("table grew to %d, past Max %d", got, Max)
	}
	if _, ok := tb.Lookup([4]byte{10, 0, 0, 1}); !ok {
		t.Error("the static entry was evicted")
	}
	real := [4]byte{192, 168, 1, 1}
	want := ether.MAC{2, 2, 2, 2, 2, 2}
	if !tb.Learn(real, want) {
		t.Fatal("a full table refused to learn a new neighbor")
	}
	if got, ok := tb.Lookup(real); !ok || got != want {
		t.Errorf("Lookup after eviction = %v, %v; want %v", got, ok, want)
	}
}

// Learning the same MAC again is free: it must not copy the table.
func TestRelearnIsFree(t *testing.T) {
	tb := New()
	ip, mac := [4]byte{10, 0, 0, 2}, ether.MAC{3, 3, 3, 3, 3, 3}
	if !tb.Learn(ip, mac) {
		t.Fatal("first Learn did not write")
	}
	for i := 0; i < 100; i++ {
		if tb.Learn(ip, mac) {
			t.Fatal("a repeated Learn wrote the table")
		}
	}
	if tb.Learn(ip, ether.MAC{4, 4, 4, 4, 4, 4}) == false {
		t.Fatal("a changed MAC did not write")
	}
}
