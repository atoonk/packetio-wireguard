package main

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/atoonk/packetio-wireguard/internal/affinity"
)

const (
	batch        = 128 // wireguard-go's own ceiling per read and write
	msgTransport = 4
	hdrLen       = 16 // type, receiver index, counter
	tagLen       = chacha20poly1305.Overhead
	sprayPorts   = 64 // source ports in all, as wgpio's -spray 64
	gsoSegments  = 64 // the kernel's UDP_MAX_SEGMENTS
)

// fpKeypair is one entry of the receiver-index table.
type fpKeypair struct {
	kp   *device.Keypair
	peer *device.Peer
	recv cipher.AEAD
}

// queue is one TUN queue, the socket its encrypting goroutine sends on, and
// that goroutine's buffers.
type queue struct {
	i     int
	tunFD int
	pcs   []*ipv4.PacketConn // this queue's send sockets, rotated per message
	pcAt  int
	tbufs [][]byte // each: hdrLen in front, room for padding and the tag behind
	tlens []int
	smsgs []ipv4.Message
	gso   []byte // this turn's datagrams laid end to end, for UDP_SEGMENT
	oob   []byte
}

// rxState is one receiving socket and the buffers of the bind receive
// function that drains it; what it decrypts goes to tunFD.
type rxState struct {
	pc     *ipv4.PacketConn
	tunFD  int
	cpu    int // pin the goroutine that drains this socket here; -1 = leave it
	pinned bool
	rmsgs  []ipv4.Message
	rbufs  [][]byte
	racct  []rxAcct
}

func newRxState(pc *ipv4.PacketConn, tunFD, cpu int) *rxState {
	r := &rxState{pc: pc, tunFD: tunFD, cpu: cpu, rmsgs: make([]ipv4.Message, batch), rbufs: make([][]byte, batch)}
	for k := range r.rbufs {
		// With UDP_GRO one message may carry up to 64 KB of coalesced
		// datagrams and a control message naming the segment size.
		r.rbufs[k] = make([]byte, 65535)
		r.rmsgs[k].Buffers = [][]byte{r.rbufs[k]}
		r.rmsgs[k].OOB = make([]byte, unix.CmsgSpace(4))
	}
	return r
}

type rxAcct struct {
	e       *fpKeypair
	packets int
	bytes   uint64
	src     netip.AddrPort
}

type fastPath struct {
	dev *device.Device
	q   []*queue
	tun *stubTUN
	mtu int

	table atomic.Pointer[map[uint32]*fpKeypair]
	tmu   sync.Mutex

	enc, dec, punt, authFail, replay, noKeypair, noPeer atomic.Uint64
	tunRead, tunWrite, tunWriteDrop, sendErr, stockSent atomic.Uint64
}

func newFastPath(fds []int, mtu int) *fastPath {
	fp := &fastPath{mtu: mtu}
	m := map[uint32]*fpKeypair{}
	fp.table.Store(&m)
	for i, fd := range fds {
		q := &queue{i: i, tunFD: fd}
		q.tbufs = make([][]byte, batch)
		q.tlens = make([]int, batch)
		for k := range q.tbufs {
			q.tbufs[k] = make([]byte, hdrLen+mtu+16+tagLen)
		}
		q.smsgs = make([]ipv4.Message, batch)
		q.gso = make([]byte, batch*(hdrLen+mtu+16+tagLen))
		q.oob = make([]byte, unix.CmsgSpace(2))
		fp.q = append(fp.q, q)
	}
	fp.tun = &stubTUN{fp: fp, punt: make(chan []byte, 1024), events: make(chan tun.Event, 4), done: make(chan struct{})}
	return fp
}

// start runs the TUN readers, from the bind's first Open: they need the
// sockets, and the sockets exist once the device is up. The decrypting side
// is the bind's receive functions.
func (fp *fastPath) start() {
	for i := range fp.q {
		go fp.encryptLoop(fp.q[i])
	}
}

// up tells wireguard-go the interface is up, which is what makes it open
// the bind. Not from start: the device opens the bind only once it is up.
func (fp *fastPath) up() { fp.tun.events <- tun.EventUp }

func (fp *fastPath) lookup(idx uint32) *fpKeypair { return (*fp.table.Load())[idx] }

// observe is the KeypairObserver, as wgpio's: copy-on-write into the table.
func (fp *fastPath) observe(peer *device.Peer, kp *device.Keypair, ev device.KeypairEvent) {
	fp.tmu.Lock()
	defer fp.tmu.Unlock()
	old := *fp.table.Load()
	m := make(map[uint32]*fpKeypair, len(old)+1)
	for k, v := range old {
		m[k] = v
	}
	switch ev {
	case device.KeypairEstablished, device.KeypairPromoted:
		m[kp.LocalIndex()] = &fpKeypair{kp: kp, peer: peer, recv: kp.ReceiveCipher()}
	case device.KeypairRetired:
		delete(m, kp.LocalIndex())
	}
	fp.table.Store(&m)
}

// receive is the bind's receive function for queue q: one recvmmsg, the
// data packets decrypted, replay-checked and written to the TUN queue here,
// everything else handed back to wireguard-go.
func (fp *fastPath) receive(q *rxState, packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if !q.pinned {
		// The goroutine wireguard-go runs this on is ours for good; give it a
		// core of its own, as a wgpio receive goroutine has.
		q.pinned = true
		if q.cpu >= 0 {
			runtime.LockOSThread()
			affinity.Pin(q.cpu)
		}
	}
	n, err := q.pc.ReadBatch(q.rmsgs, 0)
	if err != nil {
		return 0, err
	}
	out := 0
	q.racct = q.racct[:0]
	for k := 0; k < n; k++ {
		m := &q.rmsgs[k]
		src := m.Addr.(*net.UDPAddr).AddrPort()
		// A GRO'd message is several datagrams of gso bytes each, the last
		// possibly shorter; otherwise it is one datagram.
		gso := m.N
		if m.NN > 0 {
			gso = groSize(m.OOB[:m.NN], m.N)
		}
		for off := 0; off < m.N; off += gso {
			end := min(off+gso, m.N)
			out = fp.one(q, q.rbufs[k][off:end], src, packets, sizes, eps, out)
		}
	}
	for i := range q.racct {
		a := &q.racct[i]
		a.e.peer.FastPathReceived(a.e.kp, &udpEndpoint{ap: a.src}, a.packets, a.bytes, true)
	}
	return out, nil
}

// groSize reads the UDP_GRO control message: the segment size the kernel
// coalesced by, or the whole length when there is none.
func groSize(oob []byte, whole int) int {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return whole
	}
	for _, c := range msgs {
		if c.Header.Level == unix.IPPROTO_UDP && c.Header.Type == unix.UDP_GRO && len(c.Data) >= 4 {
			if sz := int(binary.NativeEndian.Uint32(c.Data)); sz > 0 {
				return sz
			}
		}
	}
	return whole
}

// one handles a single datagram: the fast path if it is a transport
// message for a keypair we hold, else it is copied out for wireguard-go.
func (fp *fastPath) one(q *rxState, payload []byte, src netip.AddrPort, packets [][]byte, sizes []int, eps []conn.Endpoint, out int) int {
	{
		var e *fpKeypair
		if len(payload) >= hdrLen+tagLen && binary.LittleEndian.Uint32(payload[0:4]) == msgTransport {
			e = fp.lookup(binary.LittleEndian.Uint32(payload[4:8]))
			if e != nil && e.kp.Expired() {
				e = nil
			}
		}
		if e == nil {
			// Handshake, cookie, unknown or expired keypair: the stock path.
			if out < len(packets) {
				sizes[out] = copy(packets[out], payload)
				eps[out] = &udpEndpoint{ap: src}
				out++
			}
			fp.punt.Add(1)
			return out
		}
		counter := binary.LittleEndian.Uint64(payload[8:16])
		var nonce [chacha20poly1305.NonceSize]byte
		binary.LittleEndian.PutUint64(nonce[4:], counter)
		content := payload[hdrLen:]
		plain, err := e.recv.Open(content[:0], nonce[:], content, nil)
		if err != nil {
			fp.authFail.Add(1)
			return out
		}
		if !e.kp.ValidateCounter(counter) {
			fp.replay.Add(1)
			return out
		}
		a := q.acct(e)
		a.packets++
		a.src = src
		if len(plain) == 0 {
			return out // keepalive
		}
		a.bytes += uint64(len(plain))
		if _, err := unix.Write(q.tunFD, plain); err != nil {
			fp.tunWriteDrop.Add(1)
		} else {
			fp.tunWrite.Add(1)
		}
		fp.dec.Add(1)
	}
	return out
}

func (q *rxState) acct(e *fpKeypair) *rxAcct {
	for i := range q.racct {
		if q.racct[i].e == e {
			return &q.racct[i]
		}
	}
	q.racct = append(q.racct, rxAcct{e: e})
	return &q.racct[len(q.racct)-1]
}

// encryptLoop reads TUN queue q, encrypts through the fork API and sends on
// socket q. Packets for a peer with no keypair yet go to wireguard-go's
// pipeline through the stub TUN, which stages them and handshakes.
func (fp *fastPath) encryptLoop(q *queue) {
	runtime.LockOSThread()
	affinity.Pin(1 + q.i) // the rig's packet cores, 1..N, as wgpio's
	pfd := []unix.PollFd{{Fd: int32(q.tunFD), Events: unix.POLLIN}}
	type peerBatch struct {
		peer *device.Peer
		kp   *device.Keypair
		send cipher.AEAD
		addr *net.UDPAddr
		idx  []int
	}
	var batches []peerBatch
	var lastPeer *device.Peer
	var lastDst [4]byte
	for {
		// Everything the queue has, up to a batch; wait only when empty.
		got := 0
		for got < batch {
			n, err := unix.Read(q.tunFD, q.tbufs[got][hdrLen:hdrLen+fp.mtu])
			if err == unix.EAGAIN {
				if got == 0 {
					unix.Poll(pfd, -1)
					continue
				}
				break
			}
			if err != nil || n < 20 {
				if err == unix.EBADF {
					return
				}
				continue
			}
			q.tlens[got] = n
			got++
		}
		fp.tunRead.Add(uint64(got))
		batches = batches[:0]
		for k := 0; k < got; k++ {
			p := q.tbufs[k][hdrLen : hdrLen+q.tlens[k]]
			if p[0]>>4 != 4 {
				fp.noPeer.Add(1)
				continue
			}
			var dst [4]byte
			copy(dst[:], p[16:20])
			peer := lastPeer
			if peer == nil || dst != lastDst {
				peer = fp.dev.LookupPeerByIP(netip.AddrFrom4(dst))
				lastPeer, lastDst = peer, dst
			}
			if peer == nil {
				fp.noPeer.Add(1)
				continue
			}
			var b *peerBatch
			for i := range batches {
				if batches[i].peer == peer {
					b = &batches[i]
				}
			}
			if b == nil {
				kp := peer.FastPathSendKeypair()
				ep, _ := peer.FastPathEndpoint().(*udpEndpoint)
				if kp == nil || ep == nil {
					fp.noKeypair.Add(1)
					fp.tun.puntIn(p) // the stock path stages it and handshakes
					continue
				}
				batches = append(batches, peerBatch{peer: peer, kp: kp, send: kp.SendCipher(), addr: net.UDPAddrFromAddrPort(ep.ap)})
				b = &batches[len(batches)-1]
			}
			b.idx = append(b.idx, k)
		}
		for i := range batches {
			b := &batches[i]
			nonce, ok := b.kp.ReserveNonces(uint64(len(b.idx)))
			if !ok {
				fp.noKeypair.Add(uint64(len(b.idx)))
				continue
			}
			// Seal each packet in its own buffer, then lay the datagrams end
			// to end: a run of equal-sized ones (all but possibly the last)
			// is one UDP_SEGMENT message, up to gsoSegments of them, and the
			// kernel splits it once instead of taking each through the whole
			// UDP send path. What upstream's StdNetBind does; without it
			// sendmmsg was 62% of the encrypting core.
			msgs := q.smsgs[:0]
			gso := q.gso[:0]
			var wire uint64
			segStart, segSize, segN, total := 0, 0, 0, 0
			flush := func() {
				if segN == 0 {
					return
				}
				m := ipv4.Message{Buffers: [][]byte{gso[segStart:len(gso)]}, Addr: b.addr}
				if segN > 1 {
					m.OOB = q.oob
					putGSO(q.oob, uint16(segSize))
				}
				msgs = append(msgs, m)
				total += segN
				segStart, segN = len(gso), 0
			}
			for _, k := range b.idx {
				buf := q.tbufs[k]
				n := q.tlens[k]
				pad := fp.dev.PaddingSize(n)
				for j := 0; j < pad; j++ {
					buf[hdrLen+n+j] = 0
				}
				var nb [chacha20poly1305.NonceSize]byte
				binary.LittleEndian.PutUint64(nb[4:], nonce)
				plain := buf[hdrLen : hdrLen+n+pad : hdrLen+n+pad+tagLen]
				sealed := b.send.Seal(plain[:0], nb[:], plain, nil)
				binary.LittleEndian.PutUint32(buf[0:4], msgTransport)
				binary.LittleEndian.PutUint32(buf[4:8], b.kp.RemoteIndex())
				binary.LittleEndian.PutUint64(buf[8:16], nonce)
				nonce++
				msg := buf[:hdrLen+len(sealed)]
				wire += uint64(len(msg))
				// A shorter datagram may end a segment run; a longer one, or
				// a full run, starts a new message.
				if segN > 0 && (len(msg) > segSize || segN == gsoSegments) {
					flush()
				}
				if segN == 0 {
					segSize = len(msg)
				}
				gso = append(gso, msg...)
				segN++
				if len(msg) < segSize {
					flush() // the short one closes its run
				}
			}
			flush()
			for len(msgs) > 0 {
				pc := q.pcs[q.pcAt]
				q.pcAt = (q.pcAt + 1) % len(q.pcs)
				n, err := pc.WriteBatch(msgs[:1], 0)
				if err != nil || n == 0 {
					fp.sendErr.Add(uint64(len(msgs)))
					break
				}
				msgs = msgs[1:]
			}
			fp.enc.Add(uint64(total))
			b.peer.FastPathSent(total, wire, true)
			b.idx = b.idx[:0]
		}
	}
}

// putGSO fills a UDP_SEGMENT control message: split this datagram every
// size bytes on the way out.
func putGSO(oob []byte, size uint16) {
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(oob[unix.CmsgLen(0):], size)
}

func (fp *fastPath) statsLine() string {
	return fmt.Sprintf("tun_read=%d fp_enc=%d fp_dec=%d tun_write=%d tun_write_drop=%d punt=%d authfail=%d replay=%d nokey=%d nopeer=%d senderr=%d stock_sent=%d",
		fp.tunRead.Load(), fp.enc.Load(), fp.dec.Load(), fp.tunWrite.Load(), fp.tunWriteDrop.Load(), fp.punt.Load(),
		fp.authFail.Load(), fp.replay.Load(), fp.noKeypair.Load(), fp.noPeer.Load(), fp.sendErr.Load(), fp.stockSent.Load())
}

// stubTUN is the tun.Device wireguard-go's pipeline sees: Read serves only
// what the fast path punted (plaintext for a peer without a keypair), Write
// puts the stock path's decrypted packets into the kernel through queue 0.
type stubTUN struct {
	fp     *fastPath
	punt   chan []byte
	events chan tun.Event
	closed atomic.Bool
	done   chan struct{}
}

var _ tun.Device = (*stubTUN)(nil)

func (t *stubTUN) puntIn(p []byte) {
	c := make([]byte, len(p))
	copy(c, p)
	select {
	case t.punt <- c:
	default:
	}
}

func (t *stubTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var p []byte
	select {
	case p = <-t.punt:
	case <-t.done:
		return 0, os.ErrClosed
	}
	n := 0
	for {
		sizes[n] = copy(bufs[n][offset:], p)
		n++
		if n == len(bufs) {
			return n, nil
		}
		select {
		case p = <-t.punt:
		default:
			return n, nil
		}
	}
}

func (t *stubTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		if len(b) <= offset {
			continue
		}
		if _, err := unix.Write(t.fp.q[0].tunFD, b[offset:]); err != nil {
			t.fp.tunWriteDrop.Add(1)
		} else {
			t.fp.tunWrite.Add(1)
		}
	}
	return len(bufs), nil
}

func (t *stubTUN) File() *os.File           { return nil }
func (t *stubTUN) MTU() (int, error)        { return t.fp.mtu, nil }
func (t *stubTUN) Name() (string, error)    { return "wggo-fast", nil }
func (t *stubTUN) Events() <-chan tun.Event { return t.events }
func (t *stubTUN) BatchSize() int           { return batch }
func (t *stubTUN) Close() error {
	if !t.closed.Swap(true) {
		close(t.done)
		close(t.events)
	}
	return nil
}
