package gateway

import (
	"errors"
	"net"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Bind is the conn.Bind: WireGuard's UDP socket, made of the underlay VLAN.
//
// Open hands wireguard-go one ReceiveFunc per receive queue, and the
// goroutine wireguard-go starts for each one becomes that queue's owner. So
// the number of receive queues is the number of tunnel receivers, with no
// change to wireguard-go.
type Bind struct {
	g      *Gateway
	closed atomic.Bool
	open   atomic.Bool
}

var _ conn.Bind = (*Bind)(nil)

// Bind returns the gateway's conn.Bind.
func (g *Gateway) Bind() *Bind { return &Bind{g: g} }

// Open starts receiving. wireguard-go calls it on every Up, after Close on
// the previous Down, so it must work more than once; the device stays open
// throughout and the queues keep their frames.
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	if b.open.Swap(true) {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if port != 0 && port != b.g.cfg.ListenPort {
		// The port is a property of the classifier, the ARP state and the
		// peers' endpoints, fixed when the gateway was built. wireguard-go
		// has already closed the previous bind by the time it asks, so
		// refusing here would leave the device with no bind at all and the
		// tunnel dead until someone set the old port back. Keep ours, say
		// so, and report it: `wg show` then shows the port truthfully.
		b.g.log.Warn("ignoring a listen-port change: the port is fixed at startup",
			"asked", port, "keeping", b.g.cfg.ListenPort)
	}
	b.closed.Store(false)
	fns := make([]conn.ReceiveFunc, len(b.g.rx))
	for i, rq := range b.g.rx {
		rq := rq
		fns[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			if b.closed.Load() {
				return 0, net.ErrClosed
			}
			return b.g.receive(rq, packets, sizes, eps), nil
		}
	}
	return fns, b.g.cfg.ListenPort, nil
}

// Close makes every ReceiveFunc return net.ErrClosed on its next call. The
// device is not closed; Open may follow.
func (b *Bind) Close() error {
	b.closed.Store(true)
	b.open.Store(false)
	return nil
}

// SetMark is a socket concept; there is no socket.
func (b *Bind) SetMark(uint32) error { return nil }

// BatchSize is what one receive call may deliver and one send may carry.
func (b *Bind) BatchSize() int { return Batch }

// ParseEndpoint accepts "ip:port".
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) { return parseEndpoint(s) }

// Send transmits datagrams to a peer. It is called from wireguard-go's
// per-peer sender goroutine and from handshake timers, concurrently.
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.closed.Load() {
		return net.ErrClosed
	}
	e, ok := ep.(*Endpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	g := b.g
	dst := e.mac
	if dst.IsZero() {
		// Configured, never heard from: the neighbor table must know it.
		// If it does not, ask and wait a little: this is a handshake from
		// one of wireguard-go's own goroutines, not the packet path, and
		// an ARP reply on the segment takes well under a millisecond,
		// whereas a dropped initiation costs the peer's 5-second retry.
		mac, ok := g.nb.Lookup(e.ip)
		for try := 0; !ok && try < neighborWaitPolls; try++ {
			g.arp.want(e.ip)
			time.Sleep(time.Millisecond)
			mac, ok = g.nb.Lookup(e.ip)
		}
		if !ok {
			g.Stats.TxNoNeighbor.Add(uint64(len(bufs)))
			return errNoNeighbor
		}
		dst = mac
	}
	tq := g.txForEndpoint(e)
	n := tq.sendTunnel(bufs, dst, e.ip, e.port)
	g.Stats.TxTunnel.Add(uint64(n))
	return nil
}

// neighborWaitPolls bounds how long Send waits for ARP: about 20 ms of
// millisecond sleeps (a timer sleep on Linux is a millisecond or more).
const neighborWaitPolls = 20

var errNoNeighbor = errors.New("gateway: endpoint's MAC not yet resolved, ARP in progress")
