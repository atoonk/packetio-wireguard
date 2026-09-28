// Package mqtun is a multi-queue kernel TUN device behind wireguard-go's
// tun.Device interface.
//
// wireguard-go opens a TUN as one file descriptor over one kernel queue,
// and reads it from one goroutine, one packet per read system call. Every
// kernel core forwarding into the device takes that queue's lock, and one
// core pays every syscall; together they cap the device at a few hundred
// thousand packets a second, whatever the rest of the machine is doing.
//
// This device opens the same interface IFF_MULTI_QUEUE, N times. The kernel
// hashes flows across the N queues, each with its own lock, and N reader
// goroutines each pay the syscalls for one of them. What they read is
// fanned in to wireguard-go's single Read; what wireguard-go writes is
// hashed by flow and fanned out to N writer goroutines, so packets of one
// flow stay in order. It is an experiment in where the TUN's limit is, not
// a finished thing: every packet is copied once on each side, and one
// channel carries them all.
package mqtun

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// batchSize is what Read hands wireguard-go at most in one call, which is
// its own ceiling (conn.IdealBatchSize). readBatch is how many packets a
// reader takes off its queue before handing them on: one channel operation
// per batch, not per packet, since N readers contend for the one channel
// wireguard-go's single Read goroutine drains.
const (
	batchSize = 128
	readBatch = 64
)

// Device is the tun.Device.
type Device struct {
	name  string
	mtu   int
	files []*os.File

	in      chan [][]byte   // batches read from any queue, waiting for Read
	pending [][]byte        // the rest of the last batch Read did not have room for
	out     []chan [][]byte // one per writer goroutine
	events  chan tun.Event
	pool    sync.Pool

	mu     sync.RWMutex // Write holds it for reading; Close for writing
	closed bool
	done   chan struct{}
	wg     sync.WaitGroup

	// Counters, for the stats line.
	ReadPackets  atomic.Uint64
	WritePackets atomic.Uint64
	WriteErrors  atomic.Uint64
	Short        atomic.Uint64 // packets longer than the buffer, truncated by the kernel
}

var _ tun.Device = (*Device)(nil)

// Open creates (or attaches to) the TUN interface name with queues kernel
// queues and starts a reader and a writer goroutine per queue. The
// interface is left down; bring it up and address it as usual.
func Open(name string, mtu, queues int) (*Device, error) {
	if queues < 1 {
		return nil, errors.New("mqtun: at least one queue")
	}
	if len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("mqtun: %q: name too long", name)
	}
	bufSize := mtu + 64 // the kernel truncates a longer packet; Short counts it
	d := &Device{name: name, mtu: mtu, in: make(chan [][]byte, 256), events: make(chan tun.Event, 4), done: make(chan struct{})}
	d.pool.New = func() any { return make([]byte, bufSize) }
	fds, err := OpenQueues(name, mtu, queues)
	if err != nil {
		return nil, err
	}
	for i, fd := range fds {
		// Through os.File the reads go through Go's poller: a goroutine
		// blocked in read is parked, not a thread, and Close wakes it.
		d.files = append(d.files, os.NewFile(uintptr(fd), fmt.Sprintf("%s/q%d", name, i)))
	}
	d.out = make([]chan [][]byte, queues)
	for i := range d.files {
		d.out[i] = make(chan [][]byte, 64)
		d.wg.Add(2)
		go d.reader(d.files[i])
		go d.writer(d.files[i], d.out[i])
	}
	d.events <- tun.EventUp
	return d, nil
}

// OpenQueues creates (or attaches to) the TUN interface name with n kernel
// queues and returns their descriptors, non-blocking, for a caller that
// wants to drive them itself: one per packet core, read and written with
// plain syscalls on that core. The interface is left down.
func OpenQueues(name string, mtu, n int) ([]int, error) {
	if n < 1 {
		return nil, errors.New("mqtun: at least one queue")
	}
	if len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("mqtun: %q: name too long", name)
	}
	var fds []int
	fail := func(err error) ([]int, error) {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return nil, err
	}
	for i := 0; i < n; i++ {
		fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return fail(fmt.Errorf("mqtun: open /dev/net/tun: %w", err))
		}
		fds = append(fds, fd)
		ifr, err := unix.NewIfreq(name)
		if err != nil {
			return fail(err)
		}
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)
		if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
			return fail(fmt.Errorf("mqtun: TUNSETIFF %s queue %d: %w", name, i, err))
		}
		if err := unix.SetNonblock(fd, true); err != nil {
			return fail(err)
		}
	}
	if err := setMTU(name, mtu); err != nil {
		return fail(err)
	}
	return fds, nil
}

func setMTU(name string, mtu int) error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(s)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	ifr.SetUint32(uint32(mtu))
	if err := unix.IoctlIfreq(s, unix.SIOCSIFMTU, ifr); err != nil {
		return fmt.Errorf("mqtun: set mtu %d on %s: %w", mtu, name, err)
	}
	return nil
}

// reader takes packets off one kernel queue and hands them to Read in
// batches: everything the queue has, up to readBatch, then one channel
// send. It blocks when Read falls behind, so the queue fills and the kernel
// counts the drops in the interface's tx_dropped, where they were counted
// before.
func (d *Device) reader(f *os.File) {
	defer d.wg.Done()
	rc, err := f.SyscallConn()
	if err != nil {
		return
	}
	for {
		batch := make([][]byte, 0, readBatch)
		var rerr error
		// The callback runs again after the poller says readable when it
		// returns false; so: drain until EAGAIN, and wait only when the
		// batch is empty.
		err := rc.Read(func(fd uintptr) bool {
			for len(batch) < readBatch {
				b := d.pool.Get().([]byte)
				n, err := unix.Read(int(fd), b)
				if err != nil {
					d.pool.Put(b)
					if err == unix.EAGAIN {
						break
					}
					if err == unix.EINTR {
						continue
					}
					rerr = err
					return true
				}
				if n == len(b) {
					d.Short.Add(1)
				}
				batch = append(batch, b[:n])
			}
			return len(batch) > 0 || rerr != nil
		})
		if err != nil || rerr != nil {
			for _, b := range batch {
				d.pool.Put(b[:cap(b)])
			}
			select {
			case <-d.done:
				return
			default:
			}
			if errors.Is(err, os.ErrClosed) || rerr == unix.EBADF {
				return
			}
			continue
		}
		select {
		case d.in <- batch:
		case <-d.done:
			return
		}
	}
}

// writer drains one fan-out channel onto one kernel queue, a write per
// packet (a TUN takes exactly one packet per write).
func (d *Device) writer(f *os.File, ch chan [][]byte) {
	defer d.wg.Done()
	for batch := range ch {
		for _, b := range batch {
			if _, err := f.Write(b); err != nil {
				d.WriteErrors.Add(1)
			} else {
				d.WritePackets.Add(1)
			}
			d.pool.Put(b[:cap(b)])
		}
	}
}

// Read blocks for one batch, then takes as many more as are ready and fit.
// What does not fit waits for the next call.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	take := func(batch [][]byte) [][]byte {
		for len(batch) > 0 && n < len(bufs) {
			p := batch[0]
			sizes[n] = copy(bufs[n][offset:], p)
			d.pool.Put(p[:cap(p)])
			batch = batch[1:]
			n++
		}
		return batch
	}
	if len(d.pending) > 0 {
		d.pending = take(d.pending)
	} else {
		select {
		case batch := <-d.in:
			d.pending = take(batch)
		case <-d.done:
			return 0, os.ErrClosed
		}
	}
	for n < len(bufs) && len(d.pending) == 0 {
		select {
		case batch := <-d.in:
			d.pending = take(batch)
		default:
			d.ReadPackets.Add(uint64(n))
			return n, nil
		}
	}
	d.ReadPackets.Add(uint64(n))
	return n, nil
}

// Write copies each packet and queues it, with the rest of the call's
// packets for the same queue, for the writer its flow hashes to. It blocks
// when that writer is behind rather than dropping.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return 0, os.ErrClosed
	}
	var perQueue [][][]byte
	if len(d.out) == 1 {
		perQueue = [][][]byte{make([][]byte, 0, len(bufs))}
	} else {
		perQueue = make([][][]byte, len(d.out))
	}
	for _, buf := range bufs {
		pkt := buf[offset:]
		b := d.pool.Get().([]byte)
		if len(pkt) > cap(b) {
			d.WriteErrors.Add(1)
			d.pool.Put(b)
			continue
		}
		b = b[:len(pkt)]
		copy(b, pkt)
		q := 0
		if len(d.out) > 1 {
			q = int(flowHash(pkt) % uint32(len(d.out)))
		}
		perQueue[q] = append(perQueue[q], b)
	}
	for q, batch := range perQueue {
		if len(batch) > 0 {
			d.out[q] <- batch
		}
	}
	return len(bufs), nil
}

// flowHash is FNV-1a over the fields that identify a flow: for IPv4 the
// addresses, protocol and, for TCP/UDP, the ports; for IPv6 the addresses.
// Anything else hashes to queue 0.
func flowHash(p []byte) uint32 {
	const offset32, prime32 = 2166136261, 16777619
	h := uint32(offset32)
	mix := func(b []byte) {
		for _, c := range b {
			h ^= uint32(c)
			h *= prime32
		}
	}
	if len(p) < 1 {
		return 0
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return 0
		}
		mix(p[12:20])
		mix(p[9:10])
		ihl := int(p[0]&0xf) * 4
		if (p[9] == 6 || p[9] == 17) && len(p) >= ihl+4 && p[6]&0x1f == 0 && p[7] == 0 {
			mix(p[ihl : ihl+4])
		}
	case 6:
		if len(p) < 40 {
			return 0
		}
		mix(p[8:40])
	}
	return h
}

func (d *Device) File() *os.File           { return d.files[0] }
func (d *Device) MTU() (int, error)        { return d.mtu, nil }
func (d *Device) Name() (string, error)    { return d.name, nil }
func (d *Device) Events() <-chan tun.Event { return d.events }
func (d *Device) BatchSize() int           { return batchSize }

// Queues is how many kernel queues the device has.
func (d *Device) Queues() int { return len(d.files) }

// Close stops the readers and writers and closes every queue. Closing the
// last queue removes the interface, as with any TUN.
func (d *Device) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	close(d.done)
	for _, ch := range d.out {
		close(ch)
	}
	d.mu.Unlock()
	var first error
	for _, f := range d.files {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	d.wg.Wait()
	close(d.events)
	return first
}
