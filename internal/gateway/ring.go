package gateway

import (
	"sync/atomic"

	"github.com/atoonk/packetio"
)

// ringSize is how many LAN frames one receive queue may hold parked for the
// TUN reader. Frames parked here are out of the receive pool, so this must
// stay well under the queue's share of frames (2048 at packetio's defaults
// for a 1024-deep ring). 512 is about a millisecond at 500 kpps.
const ringSize = 512

// parked is one LAN frame waiting for tun.Read: its descriptor, and where
// in the frame the IP packet starts and ends, so the reader need not parse.
type parked struct {
	d   packetio.Desc
	off uint16 // link header length
	n   uint16 // IP packet length
}

// ring is a single-producer, single-consumer queue of parked frames with a
// third, producer-private index for recycling:
//
//	recycled <= consumed <= produced
//
// The producer (the receive goroutine) appends at produced and, on its next
// pass, recycles everything the consumer has finished with. The consumer
// (tun.Read) copies a frame out and then advances consumed, so a frame is
// never recycled while it is being read.
type ring struct {
	buf      [ringSize]parked
	produced atomic.Uint64
	consumed atomic.Uint64
	recycled uint64 // producer only
}

// push parks a frame. It reports false, and does nothing, when the ring is
// full: the caller drops the frame rather than waiting on the reader.
//
// Full is measured against recycled, not consumed. A slot the consumer has
// finished with still holds a descriptor the producer has not recycled yet;
// overwriting it would lose that frame from the pool, and the next drain
// would recycle the NEW occupant instead -- a frame still parked, which the
// NIC then reuses under the reader and which comes back to the pool a second
// time. (That was a real bug: a line-rate burst left a fixed fraction of
// frames corrupted for the life of the process.)
func (r *ring) push(p parked) bool {
	head := r.produced.Load()
	if head-r.recycled >= ringSize {
		return false
	}
	r.buf[head%ringSize] = p
	r.produced.Store(head + 1)
	return true
}

// peek returns the oldest unconsumed frame without consuming it; the caller
// copies it and then calls done.
func (r *ring) peek() (parked, bool) {
	tail := r.consumed.Load()
	if tail == r.produced.Load() {
		return parked{}, false
	}
	return r.buf[tail%ringSize], true
}

// done releases the frame peek returned.
func (r *ring) done() { r.consumed.Store(r.consumed.Load() + 1) }

// drain hands the producer every frame the consumer has finished with, to be
// recycled, appended to out.
func (r *ring) drain(out []packetio.Desc) []packetio.Desc {
	tail := r.consumed.Load()
	for ; r.recycled < tail; r.recycled++ {
		out = append(out, r.buf[r.recycled%ringSize].d)
	}
	return out
}

// room is how many frames the producer may still push, measured as push
// measures it: against recycled, not consumed.
func (r *ring) room() int { return ringSize - int(r.produced.Load()-r.recycled) }

// pending is how many frames wait for the consumer.
func (r *ring) pending() int { return int(r.produced.Load() - r.consumed.Load()) }
