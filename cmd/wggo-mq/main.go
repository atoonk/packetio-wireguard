// wggo-mq is wireguard-go with one thing swapped: the TUN device is opened
// multi-queue (internal/mqtun) instead of upstream's single-queue tun.CreateTUN.
// Everything else is upstream as it ships -- the device, its UDP sockets, the
// UAPI -- and packetio is nowhere in it. It exists to answer one question:
// how far does stock wireguard-go get once its TUN reader is no longer the
// limit? Configure it as you would wireguard-go: wg setconf <name> ...
//
//	wggo-mq -name wg0 -queues 4 [-mtu 1420]
package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"

	"github.com/atoonk/packetio-wireguard/internal/mqtun"
)

func main() {
	name := flag.String("name", "wg0", "interface name")
	queues := flag.Int("queues", 1, "TUN queues: a kernel queue, a reader and a writer goroutine each")
	mtu := flag.Int("mtu", device.DefaultMTU, "interface MTU")
	verbose := flag.Bool("v", false, "verbose wireguard-go logging")
	pprofAddr := flag.String("pprof", "", "serve pprof on this address, e.g. 127.0.0.1:6060")
	flag.Parse()
	if *pprofAddr != "" {
		go func() { fmt.Fprintln(os.Stderr, "pprof:", http.ListenAndServe(*pprofAddr, nil)) }()
	}

	level := device.LogLevelError
	if *verbose {
		level = device.LogLevelVerbose
	}
	logger := device.NewLogger(level, fmt.Sprintf("(%s) ", *name))

	tdev, err := mqtun.Open(*name, *mtu, *queues)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wggo-mq:", err)
		os.Exit(1)
	}
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	logger.Verbosef("device started, %d TUN queues", *queues)

	fileUAPI, err := ipc.UAPIOpen(*name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wggo-mq: uapi:", err)
		os.Exit(1)
	}
	uapi, err := ipc.UAPIListen(*name, fileUAPI)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wggo-mq: uapi listen:", err)
		os.Exit(1)
	}
	errs := make(chan error)
	go func() {
		for {
			c, err := uapi.Accept()
			if err != nil {
				errs <- err
				return
			}
			go dev.IpcHandle(c)
		}
	}()

	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-term:
	case <-errs:
	case <-dev.Wait():
	}
	uapi.Close()
	dev.Close()
}
