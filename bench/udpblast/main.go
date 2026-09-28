// Command udpblast sends UDP packets from several threads with sendmmsg, to a
// range of destinations. It is the plaintext source for the kernel and
// wireguard-go baselines on a two-box rig: it runs on the encrypting box and
// sends into wg0.
//
//	udpblast -threads 8 -dst 10.200.3.0 -flows 64 -port 9000 -size 18 -duration 20s
//	udpblast -pps 400000 ...   # offer a set rate rather than everything possible
//
// -pps matters more than it looks. Offering twenty times what a tunnel can carry
// does not measure the tunnel: it measures what happens to a userspace reader when
// the sender monopolises the machine. Measured here, wireguard-go carried 231 kpps
// when offered 2.2 Mpps and 1.2 kpps when offered 4.9 Mpps. A rate ladder finds the
// knee; a flood finds the collapse.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// mmsghdr is struct mmsghdr from <sys/socket.h>: a msghdr and the bytes sent.
type mmsghdr struct {
	hdr unix.Msghdr
	len uint32
	_   [4]byte
}

func main() {
	threads := flag.Int("threads", 4, "sender threads (sockets)")
	dst := flag.String("dst", "10.200.3.0", "first destination address; flows cycle the last octet")
	flows := flag.Int("flows", 64, "destinations to cycle")
	port := flag.Int("port", 9000, "destination port")
	size := flag.Int("size", 18, "UDP payload bytes (18 = 46-byte IP packet = 68-byte frame with VLAN and FCS)")
	dur := flag.Duration("duration", 20*time.Second, "how long")
	batch := flag.Int("batch", 512, "packets per sendmmsg")
	rate := flag.Uint64("pps", 0, "offer this many packets per second in total (0 = as fast as the socket path allows)")
	flag.Parse()

	base := net.ParseIP(*dst).To4()
	if base == nil {
		fmt.Fprintln(os.Stderr, "dst must be IPv4")
		os.Exit(2)
	}
	var sent atomic.Uint64
	var wg sync.WaitGroup
	deadline := time.Now().Add(*dur)
	for t := 0; t < *threads; t++ {
		wg.Add(1)
		go func(t int) {
			defer wg.Done()
			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return
			}
			defer unix.Close(fd)
			payload := make([]byte, *size)
			// One message per flow, reused; sendmmsg takes a batch of them.
			msgs := make([]mmsghdr, *batch)
			addrs := make([]unix.RawSockaddrInet4, *batch)
			iovs := make([]unix.Iovec, *batch)
			for i := range msgs {
				f := (t*(*batch) + i) % *flows
				addrs[i] = unix.RawSockaddrInet4{Family: unix.AF_INET, Port: uint16(*port>>8) | uint16(*port&0xff)<<8}
				copy(addrs[i].Addr[:], base)
				addrs[i].Addr[3] = base[3] + byte(f)
				iovs[i].Base = &payload[0]
				iovs[i].SetLen(len(payload))
				msgs[i].hdr.Name = (*byte)(unsafe.Pointer(&addrs[i]))
				msgs[i].hdr.Namelen = uint32(unix.SizeofSockaddrInet4)
				msgs[i].hdr.Iov = &iovs[i]
				msgs[i].hdr.SetIovlen(1)
			}
			// Rate limiting is per thread, paced by the wall clock rather than a
			// ticker: a ticker at these rates costs more than the sending does.
			//
			// The batch shrinks with the rate. A 512-packet sendmmsg every 41 ms is
			// the same average as 12 packets every millisecond and nothing like the
			// same offered load: the first arrives as bursts that overflow a queue
			// sized for the average. Aim at a millisecond of traffic per batch.
			var perThread float64
			msgn := len(msgs)
			if *rate > 0 {
				perThread = float64(*rate) / float64(*threads)
				if n := int(perThread / 1000); n < msgn {
					msgn = n
				}
				if msgn < 1 {
					msgn = 1
				}
			}
			start := time.Now()
			var mine uint64
			for time.Now().Before(deadline) {
				if perThread > 0 {
					// How many this thread should have sent by now. Ahead of the
					// schedule, wait; the sleep is coarse, so the debt is carried
					// rather than dropped.
					due := perThread * time.Since(start).Seconds()
					if float64(mine) >= due {
						over := (float64(mine) - due) / perThread
						if over > 0.0005 {
							time.Sleep(time.Duration(over * float64(time.Second)))
						}
						continue
					}
				}
				n, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgs[0])), uintptr(msgn), 0, 0, 0)
				if errno != 0 {
					if errno == unix.ENOBUFS || errno == unix.EAGAIN || errno == unix.EINTR {
						continue
					}
					fmt.Fprintln(os.Stderr, "sendmmsg:", errno)
					return
				}
				sent.Add(uint64(n))
				mine += uint64(n)
			}
		}(t)
	}
	wg.Wait()
	fmt.Printf("sent=%d secs=%d pps=%d\n", sent.Load(), int(dur.Seconds()), sent.Load()/uint64(dur.Seconds()))
}
