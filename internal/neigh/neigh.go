// Package neigh is the gateway's IPv4-to-MAC table. It is read on every
// transmitted frame from every queue and written only when ARP says
// something new, so it is copy-on-write: readers load one pointer to an
// immutable map, writers copy under a mutex and publish. (The pattern is
// packetio's netstack neighbor table, cut down to what a two-VLAN gateway
// with a handful of neighbors needs.)
//
// Entries come from two places: static ones given on the command line,
// which nothing overrides, and ones learned from ARP -- replies to our own
// requests and requests that name us as target, the same two events a
// kernel learns from. Data frames never teach the table anything.
package neigh

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/atoonk/packetio-wireguard/internal/ether"
)

const (
	// Max bounds the table. A gateway has a peer, a next hop, and whatever
	// else is on its two VLANs; a flood of forged ARP cannot grow it past
	// this. Past it the least recently confirmed learned entry is evicted,
	// so a flood costs the table's oldest entries rather than the ability
	// to learn anything new ever again.
	Max = 1024

	// refreshAfter is how often a learned entry that keeps being confirmed
	// is written again, to keep its age current. Confirmations in between
	// are free: the table is copy-on-write and a write copies it.
	refreshAfter = 30 * time.Second
)

// Table maps IPv4 addresses to MACs.
type Table struct {
	m  atomic.Pointer[map[[4]byte]entry]
	mu sync.Mutex // writers only
}

type entry struct {
	mac    ether.MAC
	static bool
	at     int64 // when last written, for aging out a flood of forged senders
}

// New returns an empty table.
func New() *Table {
	t := &Table{}
	m := make(map[[4]byte]entry)
	t.m.Store(&m)
	return t
}

// Lookup returns the MAC for ip, if known.
func (t *Table) Lookup(ip [4]byte) (ether.MAC, bool) {
	e, ok := (*t.m.Load())[ip]
	return e.mac, ok
}

// Set records a static entry that learning never changes.
func (t *Table) Set(ip [4]byte, mac ether.MAC) { t.write(ip, entry{mac: mac, static: true}) }

// Learn records what ARP said, unless a static entry exists for ip. It
// reports whether the table changed.
func (t *Table) Learn(ip [4]byte, mac ether.MAC) bool {
	now := time.Now().UnixNano()
	if e, ok := (*t.m.Load())[ip]; ok && (e.static || (e.mac == mac && now-e.at < int64(refreshAfter))) {
		return false // the common case, and lock-free: nothing to change
	}
	return t.write(ip, entry{mac: mac, at: now})
}

func (t *Table) write(ip [4]byte, e entry) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	old := *t.m.Load()
	have, known := old[ip]
	if known {
		if have.static && !e.static {
			return false
		}
		if have.mac == e.mac && have.static == e.static && !e.static && e.at-have.at < int64(refreshAfter) {
			return false // another goroutine refreshed it first
		}
	}
	m := make(map[[4]byte]entry, len(old)+1)
	for k, v := range old {
		m[k] = v
	}
	if !known && len(m) >= Max {
		// Full: make room by dropping the learned entry that has gone
		// longest without confirmation. Everything here was learned from
		// ARP, so the oldest is the one least likely to be in use, and a
		// peer that is still there is relearned from its next reply.
		var oldest [4]byte
		var found bool
		for k, v := range m {
			if v.static {
				continue
			}
			if !found || v.at < m[oldest].at {
				oldest, found = k, true
			}
		}
		if !found {
			return false // every entry is static; nothing may be evicted
		}
		delete(m, oldest)
	}
	m[ip] = e
	t.m.Store(&m)
	return true
}

// Len is the number of entries.
func (t *Table) Len() int { return len(*t.m.Load()) }
