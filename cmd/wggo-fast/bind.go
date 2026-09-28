package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
)

// udpEndpoint is a peer's address as this bind knows it.
type udpEndpoint struct{ ap netip.AddrPort }

func (e *udpEndpoint) ClearSrc()           {}
func (e *udpEndpoint) SrcToString() string { return "" }
func (e *udpEndpoint) DstToString() string { return e.ap.String() }
func (e *udpEndpoint) DstIP() netip.Addr   { return e.ap.Addr() }
func (e *udpEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *udpEndpoint) DstToBytes() []byte {
	b, _ := e.ap.MarshalBinary()
	return b
}

// sockBind is the conn.Bind: N UDP sockets on consecutive ports. Its receive
// functions run the decrypting fast path inline and return only what they
// punted; Send is the stock path's (handshakes, and data before the fast
// path has a keypair), on socket 0.
type sockBind struct {
	fp     *fastPath
	port   uint16
	n      int
	conns  []*net.UDPConn
	pcs    []*ipv4.PacketConn
	closed atomic.Bool
	open   atomic.Bool
	once   sync.Once
}

var _ conn.Bind = (*sockBind)(nil)

func newBind(fp *fastPath, port uint16, n int) (*sockBind, error) {
	return &sockBind{fp: fp, port: port, n: n}, nil
}

// Open creates the sockets. wireguard-go closes and reopens the bind on
// every listen-port change (BindUpdate), including the one in the initial
// configuration, so the sockets belong to Open, not to the constructor. The
// port asked for is ignored: this bind's ports are fixed at startup.
func (b *sockBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	if b.open.Swap(true) {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	b.closed.Store(false)
	b.conns, b.pcs = b.conns[:0], b.pcs[:0]
	// Two sockets per queue. The peer's data all arrives at our one listen
	// port, so N sockets share it with SO_REUSEPORT and the kernel spreads
	// the datagrams across them by 4-tuple: that is what the peer's sprayed
	// source ports are for, and it is the socket equivalent of RSS picking a
	// packetio queue. Sending goes out of a socket with a source port of its
	// own, port+1+i, so the peer's kernel can do the same to us; replies to
	// those ports (a roaming peer's) are read too.
	listen := func(port int, reuse bool) (*net.UDPConn, error) {
		lc := net.ListenConfig{}
		if reuse {
			// SO_REUSEPORT to share the port; UDP_GRO so the kernel hands
			// consecutive datagrams of one flow up as one buffer with a
			// segment size, as upstream's StdNetBind asks for. Per-packet
			// softirq work is where the receiving side spends its cores.
			lc.Control = func(_, _ string, c syscall.RawConn) error {
				var serr error
				c.Control(func(fd uintptr) {
					serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
					if serr == nil {
						serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
					}
				})
				return serr
			}
		}
		pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", port))
		if err != nil {
			return nil, fmt.Errorf("listen udp %d: %w", port, err)
		}
		c := pc.(*net.UDPConn)
		// The receive buffer is kept to a few milliseconds of traffic on
		// purpose. N receivers share one replay window; a receiver that lags
		// with a large buffer delivers packets to the window a quarter of a
		// second late, past its far edge, and they are rejected as replays
		// (20% of them at 2 Mpps with 64 MB). Small buffers turn that lag
		// into socket drops, which is what a drop should look like.
		c.SetReadBuffer(512 << 10)
		c.SetWriteBuffer(16 << 20)
		return c, nil
	}
	// Send sockets: sprayPorts source ports in all, shared out among the
	// queues, so the peer's reuseport hash (or RSS) has enough distinct
	// 4-tuples to spread evenly; with one port per queue the collisions
	// left some of the peer's receivers idle and overflowed others.
	var rx []*rxState
	per := max(sprayPorts/b.n, 1)
	next := int(b.port) + 1
	for i := 0; i < b.n; i++ {
		q := b.fp.q[i]
		recv, err := listen(int(b.port), true)
		if err != nil {
			b.Close()
			return nil, 0, err
		}
		b.conns = append(b.conns, recv)
		rpc := ipv4.NewPacketConn(recv)
		b.pcs = append(b.pcs, rpc)
		rx = append(rx, newRxState(rpc, q.tunFD, 1+i))
		q.pcs = q.pcs[:0]
		for j := 0; j < per; j++ {
			send, err := listen(next, false)
			if err != nil {
				b.Close()
				return nil, 0, err
			}
			next++
			b.conns = append(b.conns, send)
			spc := ipv4.NewPacketConn(send)
			b.pcs = append(b.pcs, spc)
			q.pcs = append(q.pcs, spc)
			rx = append(rx, newRxState(spc, q.tunFD, -1)) // a roaming peer's replies land here
		}
	}
	b.once.Do(b.fp.start)
	fns := make([]conn.ReceiveFunc, len(rx))
	for i := range rx {
		r := rx[i]
		fns[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			if b.closed.Load() {
				return 0, net.ErrClosed
			}
			return b.fp.receive(r, packets, sizes, eps)
		}
	}
	return fns, b.port, nil
}

func (b *sockBind) Close() error {
	b.closed.Store(true)
	b.open.Store(false)
	var first error
	for _, c := range b.conns {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	b.conns, b.pcs = nil, nil // Close is called again before every Open
	return first
}

func (b *sockBind) SetMark(uint32) error { return nil }
func (b *sockBind) BatchSize() int       { return batch }

func (b *sockBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	if !ap.Addr().Is4() {
		return nil, errors.New("wggo-fast: IPv4 endpoints only")
	}
	return &udpEndpoint{ap: ap}, nil
}

// Send is the stock path's transmit: one sendmmsg on socket 0.
func (b *sockBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.closed.Load() {
		return net.ErrClosed
	}
	e, ok := ep.(*udpEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	addr := net.UDPAddrFromAddrPort(e.ap)
	msgs := make([]ipv4.Message, len(bufs))
	for i, buf := range bufs {
		msgs[i].Buffers = [][]byte{buf}
		msgs[i].Addr = addr
	}
	for len(msgs) > 0 {
		n, err := b.pcs[0].WriteBatch(msgs, 0)
		if err != nil {
			return err
		}
		msgs = msgs[n:]
	}
	b.fp.stockSent.Add(uint64(len(bufs)))
	return nil
}
