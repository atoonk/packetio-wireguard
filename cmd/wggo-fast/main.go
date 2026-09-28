// wggo-fast is the socket twin of wgpio's fast path: the same bypass of
// wireguard-go's pipeline, through the same fork API (patch 0001), with the
// I/O done the ordinary way. No packetio anywhere.
//
// N queues, each a kernel TUN queue and a UDP socket on port+i, driven by
// two goroutines:
//
//	TUN queue i --read--> encrypt in place (ReserveNonces, SendCipher) --sendmmsg--> socket i
//	socket i --recvmmsg--> decrypt in place (ReceiveCipher, ValidateCounter) --write--> TUN queue i
//
// wireguard-go's own pipeline handles what the fast path cannot: handshakes,
// cookies, packets before the first keypair. It gets them through a conn.Bind
// whose receive functions ARE the decrypting goroutines (they hand back only
// what they punted) and a tun.Device that serves only punted plaintext.
//
// It answers one question: of the step from wireguard-go's 1.5 M to wgpio's
// 5 M with a kernel TUN, how much is the patches and how much is packetio?
//
//	wggo-fast -name wg0 -queues 8 -port 51820
//	wg setconf wg0 ...
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"

	"github.com/atoonk/packetio-wireguard/internal/mqtun"
)

func main() {
	name := flag.String("name", "wg0", "interface name")
	queues := flag.Int("queues", 4, "queues: a TUN queue, a UDP socket and two goroutines each")
	port := flag.Int("port", 51820, "first UDP port; queue i uses port+i (the peer's RSS spreads on the source port)")
	mtu := flag.Int("mtu", device.DefaultMTU, "interface MTU")
	stats := flag.Duration("stats", 0, "print counters this often (0 = never)")
	pprofAddr := flag.String("pprof", "", "serve pprof on this address")
	verbose := flag.Bool("v", false, "verbose wireguard-go logging")
	flag.Parse()
	if *pprofAddr != "" {
		go func() { log.Println("pprof:", http.ListenAndServe(*pprofAddr, nil)) }()
	}

	fds, err := mqtun.OpenQueues(*name, *mtu, *queues)
	if err != nil {
		log.Fatal("wggo-fast: ", err)
	}
	fp := newFastPath(fds, *mtu)
	bind, err := newBind(fp, uint16(*port), *queues)
	if err != nil {
		log.Fatal("wggo-fast: ", err)
	}
	level := device.LogLevelError
	if *verbose {
		level = device.LogLevelVerbose
	}
	dev := device.NewDevice(fp.tun, bind, device.NewLogger(level, fmt.Sprintf("(%s) ", *name)))
	fp.dev = dev
	dev.SetKeypairObserver(fp.observe) // before any configuration: it does not replay keypairs
	fp.up()

	fileUAPI, err := ipc.UAPIOpen(*name)
	if err != nil {
		log.Fatal("wggo-fast: uapi: ", err)
	}
	uapi, err := ipc.UAPIListen(*name, fileUAPI)
	if err != nil {
		log.Fatal("wggo-fast: uapi listen: ", err)
	}
	go func() {
		for {
			c, err := uapi.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()
	log.Printf("wggo-fast: %s up, %d queues, udp ports %d-%d", *name, *queues, *port, *port+*queues-1)

	var tick <-chan time.Time
	if *stats > 0 {
		t := time.NewTicker(*stats)
		defer t.Stop()
		tick = t.C
	}
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)
	for {
		select {
		case <-term:
			uapi.Close()
			dev.Close()
			return
		case <-dev.Wait():
			return
		case <-tick:
			log.Println("stats", fp.statsLine())
		}
	}
}
