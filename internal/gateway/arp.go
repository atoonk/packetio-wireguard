package gateway

import (
	"sync"
	"time"

	"github.com/atoonk/packetio-wireguard/internal/ether"
)

// resolver sends ARP requests for addresses the transmit path needed and
// did not know: at once when first asked, then once a second until the
// neighbor table learns them. It is the only thing that transmits from its
// own goroutine; it uses queue 0 under the lock like everyone else. The
// transmit path cannot send the request itself, since it may already hold
// that lock (buildLAN runs inside it).
type resolver struct {
	g    *Gateway
	mu   sync.Mutex
	need map[[4]byte]time.Time // when each was last asked for; zero = never
	kick chan struct{}
	done chan struct{}
	once sync.Once
}

// askAgainAfter bounds how often a kick may re-ask for one address, so a
// burst of packets to an unresolved neighbor is one request, not a storm.
const askAgainAfter = 200 * time.Millisecond

func newResolver(g *Gateway) *resolver {
	r := &resolver{g: g, need: map[[4]byte]time.Time{}, kick: make(chan struct{}, 1), done: make(chan struct{})}
	go r.run()
	return r
}

// want asks for ip to be resolved. It is called on the transmit path, so
// it is cheap when the address is already wanted.
func (r *resolver) want(ip [4]byte) {
	r.mu.Lock()
	_, known := r.need[ip]
	if !known {
		r.need[ip] = time.Time{}
	}
	r.mu.Unlock()
	if !known {
		select {
		case r.kick <- struct{}{}:
		default:
		}
	}
}

func (r *resolver) run() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-tick.C:
		case <-r.kick:
		}
		now := time.Now()
		r.mu.Lock()
		var ask [][4]byte
		for ip, at := range r.need {
			if _, ok := r.g.nb.Lookup(ip); ok {
				delete(r.need, ip)
				continue
			}
			if now.Sub(at) < askAgainAfter {
				continue
			}
			r.need[ip] = now
			ask = append(ask, ip)
		}
		r.mu.Unlock()
		for _, ip := range ask {
			vlan, ok := r.g.vlanFor(ip)
			if !ok {
				r.g.log.Warn("cannot ARP: address on neither VLAN", "ip", ip)
				r.mu.Lock()
				delete(r.need, ip)
				r.mu.Unlock()
				continue
			}
			mine, _ := r.g.addrOn(vlan)
			r.g.sendARP(vlan, ether.ARP{Op: ether.ARPRequest, SenderMAC: r.g.mac, SenderIP: mine, TargetIP: ip}, ether.Broadcast)
		}
	}
}

func (r *resolver) stop() { r.once.Do(func() { close(r.done) }) }
