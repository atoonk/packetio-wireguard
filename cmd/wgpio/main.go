// Command wgpio runs WireGuard as a two-VLAN gateway on one NIC port owned
// by packetio: the tunnel's UDP on one VLAN, the plaintext LAN on another.
// wireguard-go does the protocol; wgpio does the wire, and with the fast
// path on, the transport crypto in the NIC's frames.
//
//	sudo wgpio -i 0000:01:00.0 -queues 4 -cpus 2-5 \
//	    -underlay-vlan 2131 -underlay-ip 10.131.0.2/24 \
//	    -lan-vlan 2154 -lan-ip 10.154.0.2/24 -route 10.200.2.0/24=10.154.0.1 \
//	    -config /etc/wireguard/wgpio0.conf
//
// The configuration file is what wg setconf reads. While running, wg(8)
// works as usual: wg show wgpio0.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/atoonk/packetio"

	"github.com/atoonk/packetio-wireguard/internal/affinity"
	"github.com/atoonk/packetio-wireguard/internal/backend"
	"github.com/atoonk/packetio-wireguard/internal/ether"
	"github.com/atoonk/packetio-wireguard/internal/gateway"
	"github.com/atoonk/packetio-wireguard/internal/mqtun"
	"github.com/atoonk/packetio-wireguard/internal/neigh"
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

// options is every flag. run takes it whole, so the checks that used to be
// impossible to put anywhere -- a CPU that does not exist, an MTU the port
// cannot carry, a generator with nothing to generate onto -- have one place
// to live, and a new flag is one field rather than one more positional
// parameter in a list of thirty.
type options struct {
	dev        string
	queues     int
	cpuList    string
	genSpec    string
	sink       bool
	spray      int
	sprayMode  string
	diag       bool
	fastPath   bool
	batch      int
	tunCPU     int
	portMTU    int
	frameSize  int
	frames     int
	rxDepth    int
	noHuge     int
	promisc    bool
	macFlag    string
	devArgs    string
	steerVLAN  uint16
	uVLAN      uint16
	uIPs       string
	port       uint16
	lVLAN      uint16
	lIPs       string
	mtu        int
	routes     []string
	neighbors  []string
	conf       string
	name       string
	kernelTUN  string
	tunQueues  int
	noUAPI     bool
	statsEvery time.Duration
	pprofAddr  string
	verbose    bool
}

func main() {
	var o options
	flag.StringVar(&o.dev, "i", "", "device: PCI address (0000:01:00.0), interface name, or DPDK vdev spec")
	flag.IntVar(&o.queues, "queues", 1, "receive/transmit queue pairs; one receive goroutine each")
	flag.StringVar(&o.cpuList, "cpus", "", "CPUs to pin the receive goroutines to, e.g. 2-5 (default: unpinned)")
	flag.StringVar(&o.genSpec, "gen", "", "built-in generator: pps=N,size=S,flows=F,src=IP,dst=PREFIX,port=P (pps 0 = unlimited)")
	flag.BoolVar(&o.sink, "sink", false, "count and drop decrypted packets instead of forwarding them to the LAN")
	flag.IntVar(&o.spray, "spray", 0, "send tunnel packets from this many UDP source ports (listen-port..+N-1) so the peer's RSS spreads them over its queues; accept that range (0 = off, 64 is a good number)")
	flag.StringVar(&o.sprayMode, "spray-mode", "flow", "how the fast path picks a packet's spray port: flow (by inner 5-tuple hash, so a flow keeps one outer tuple and arrives in order at the peer) or rotate (per packet: a few percent more peak packet rate, and TCP through the tunnel reordered so badly it ran at a third of the speed)")
	flag.BoolVar(&o.diag, "diag", false, "sample scheduling gaps on the hot path (costs a few percent)")
	flag.BoolVar(&o.fastPath, "fastpath", true, "decrypt and encrypt in the DMA frame on the receive goroutine (needs the packetio fork of wireguard-go)")
	flag.IntVar(&o.batch, "batch", 64, "packets per receive/send batch (1..128, wireguard-go's ceiling)")
	flag.IntVar(&o.tunCPU, "tun-cpu", -1, "pin the TUN reader to this CPU; with -fastpath=false it spins there (default: unpinned, woken by the receive path)")
	flag.IntVar(&o.portMTU, "port-mtu", 1500, "largest untagged payload the port accepts")
	flag.IntVar(&o.frameSize, "frame-size", 0, "packetio frame size (0 = backend default; 4096 for net_af_packet vdevs)")
	flag.IntVar(&o.frames, "frames", 0, "packetio frame count (0 = backend default)")
	flag.IntVar(&o.rxDepth, "rx-depth", 0, "buffers posted per receive queue (0 = backend default; mlx5 only)")
	flag.IntVar(&o.noHuge, "no-huge", 0, "run without hugepages on this many MB (virtual devices only)")
	flag.BoolVar(&o.promisc, "promisc", false, "receive every frame, not just ours")
	flag.StringVar(&o.macFlag, "mac", "", "use this MAC instead of the port's own (implies -promisc)")
	flag.StringVar(&o.devArgs, "devargs", "", "backend device arguments")
	steerVLAN := flag.Uint("steer-vlan", 0, "steer this VLAN to our queues (needed on a bifurcated port the kernel keeps, e.g. a ConnectX)")
	uVLAN := flag.Uint("underlay-vlan", 0, "802.1Q tag of the tunnel side (0 = untagged)")
	flag.StringVar(&o.uIPs, "underlay-ip", "", "our address/prefix on the tunnel side, e.g. 10.131.0.2/24")
	port := flag.Uint("listen-port", 51820, "WireGuard UDP port (a ListenPort in -config overrides)")
	lVLAN := flag.Uint("lan-vlan", 0, "802.1Q tag of the plaintext side (0 = untagged)")
	flag.StringVar(&o.lIPs, "lan-ip", "", "our address/prefix on the plaintext side, e.g. 10.154.0.2/24")
	flag.IntVar(&o.mtu, "mtu", 1420, "tunnel MTU; larger plaintext packets are dropped")
	flag.StringVar(&o.conf, "config", "", "WireGuard configuration file (wg setconf format)")
	flag.StringVar(&o.kernelTUN, "kernel-tun", "", "hand the plaintext to the kernel through a TUN device of this name, instead of forwarding it on the LAN VLAN; the kernel routes it. Steers only frames for -underlay-ip to packetio. With the fast path on, each receive goroutine drives one TUN queue")
	flag.IntVar(&o.tunQueues, "kernel-tun-queues", 0, "with -kernel-tun: open the TUN multi-queue with this many kernel queues, a reader and a writer goroutine each (0 = wireguard-go's own single-queue TUN)")
	flag.StringVar(&o.name, "name", "wgpio0", "interface name for the UAPI socket (wg show <name>)")
	flag.BoolVar(&o.noUAPI, "no-uapi", false, "do not open the UAPI socket")
	flag.DurationVar(&o.statsEvery, "stats", 5*time.Second, "print counters this often (0 = never)")
	flag.StringVar(&o.pprofAddr, "pprof", "", "serve pprof on this address, e.g. 127.0.0.1:6060")
	flag.BoolVar(&o.verbose, "v", false, "verbose wireguard-go logging")
	var routes, neighbors listFlag
	flag.Var(&routes, "route", "prefix=next-hop on the LAN, repeatable, e.g. 10.200.2.0/24=10.154.0.1")
	flag.Var(&neighbors, "neighbor", "ip=mac static neighbor, repeatable (skips ARP for it)")
	flag.Parse()
	o.steerVLAN, o.uVLAN, o.lVLAN, o.port = uint16(*steerVLAN), uint16(*uVLAN), uint16(*lVLAN), uint16(*port)
	o.routes, o.neighbors = routes, neighbors
	if *uVLAN > 4095 || *lVLAN > 4095 || *steerVLAN > 4095 || *port > 65535 {
		fmt.Fprintln(os.Stderr, "wgpio: a VLAN id is 0..4094 and a port is 1..65535")
		os.Exit(1)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log, o); err != nil {
		log.Error("wgpio", "err", err)
		os.Exit(1)
	}
}

// outerOverhead is what wgpio puts around a plaintext packet, excluding the
// VLAN tag (which is outside the port MTU): IPv4 + UDP + the WireGuard
// transport header + the Poly1305 tag.
const outerOverhead = 20 + 8 + 16 + 16

// validate rejects the flag combinations that would otherwise start a
// gateway that quietly forwards nothing, or one whose packet cores are not
// the cores the operator asked for.
func (o *options) validate(cpus []int) error {
	if o.dev == "" || o.uIPs == "" || o.lIPs == "" {
		return errors.New("-i, -underlay-ip and -lan-ip are required")
	}
	if o.queues < 1 {
		return fmt.Errorf("-queues %d: at least one", o.queues)
	}
	if o.batch < 1 || o.batch > gateway.MaxBatch {
		return fmt.Errorf("-batch %d: 1..%d", o.batch, gateway.MaxBatch)
	}
	ncpu := runtime.NumCPU()
	for _, c := range cpus {
		if c < 0 || c >= ncpu {
			return fmt.Errorf("-cpus: cpu %d does not exist (this machine has %d)", c, ncpu)
		}
		if c == o.tunCPU {
			return fmt.Errorf("-tun-cpu %d is also in -cpus; the reader and a receive goroutine would fight for the core", c)
		}
	}
	if o.tunCPU >= ncpu {
		return fmt.Errorf("-tun-cpu %d does not exist (this machine has %d)", o.tunCPU, ncpu)
	}
	if len(cpus) > 0 && len(cpus) < o.queues {
		return fmt.Errorf("-queues %d needs %d cpus in -cpus, which names %d; every receive goroutine wants one of its own",
			o.queues, o.queues, len(cpus))
	}
	if o.mtu < 576 {
		return fmt.Errorf("-mtu %d: too small to carry anything useful", o.mtu)
	}
	if o.mtu+outerOverhead > o.portMTU {
		return fmt.Errorf("-mtu %d needs %d bytes on the wire, more than -port-mtu %d; lower the tunnel MTU or raise the port's",
			o.mtu, o.mtu+outerOverhead, o.portMTU)
	}
	if o.spray < 0 {
		return fmt.Errorf("-spray %d: not negative", o.spray)
	}
	switch o.sprayMode {
	case "":
		o.sprayMode = "flow" // the default, for callers that build options by hand
	case "flow", "rotate":
	default:
		return fmt.Errorf("-spray-mode %q: flow or rotate", o.sprayMode)
	}
	if o.spray > 0 && int(o.port)+o.spray-1 > 65535 {
		return fmt.Errorf("-spray %d from port %d runs past 65535", o.spray, o.port)
	}
	if o.kernelTUN != "" && o.fastPath && o.tunQueues > 0 {
		return errors.New("-kernel-tun-queues is for -fastpath=false; with the fast path on, every receive goroutine drives a TUN queue of its own (-queues of them)")
	}
	if o.kernelTUN != "" && o.steerVLAN == 0 {
		return errors.New("-kernel-tun needs -steer-vlan: without a steering rule packetio takes the whole port and the kernel never sees the plaintext it is meant to route")
	}
	if o.fastPath && !fastPathAvailable {
		return errors.New("-fastpath: this binary was built with -tags stockwg, against unmodified wireguard-go; run it with -fastpath=false")
	}
	return nil
}

func run(log *slog.Logger, o options) error {
	cpus, err := affinity.Parse(o.cpuList)
	if err != nil {
		return err
	}
	if err := o.validate(cpus); err != nil {
		return err
	}
	gateway.SetBatch(o.batch)

	uIP, err := netip.ParsePrefix(o.uIPs)
	if err != nil {
		return fmt.Errorf("-underlay-ip: %w", err)
	}
	lIP, err := netip.ParsePrefix(o.lIPs)
	if err != nil {
		return fmt.Errorf("-lan-ip: %w", err)
	}
	// Keep every other thread off the packet cores before anything else starts.
	exclude := cpus
	if o.tunCPU >= 0 {
		exclude = append(append([]int{}, cpus...), o.tunCPU)
	}
	if err := affinity.Exclude(exclude); err != nil {
		return err
	}
	var mac ether.MAC
	if o.macFlag != "" {
		hw, err := net.ParseMAC(o.macFlag)
		if err != nil || len(hw) != 6 {
			return fmt.Errorf("-mac %q: not an Ethernet address", o.macFlag)
		}
		copy(mac[:], hw)
	}
	var rts []gateway.Route
	for _, r := range o.routes {
		p, nh, ok := strings.Cut(r, "=")
		if !ok {
			return fmt.Errorf("-route %q: want prefix=next-hop", r)
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return fmt.Errorf("-route %q: %w", r, err)
		}
		next, err := netip.ParseAddr(nh)
		if err != nil {
			return fmt.Errorf("-route %q: %w", r, err)
		}
		rts = append(rts, gateway.Route{Prefix: prefix, NextHop: next})
	}
	nb := neigh.New()
	for _, n := range o.neighbors {
		ip, m, ok := strings.Cut(n, "=")
		hw, err := net.ParseMAC(m)
		a, err2 := netip.ParseAddr(ip)
		if !ok || err != nil || err2 != nil || !a.Is4() || len(hw) != 6 {
			return fmt.Errorf("-neighbor %q: want ipv4=mac", n)
		}
		var mm ether.MAC
		copy(mm[:], hw)
		nb.Set(a.As4(), mm)
	}

	uapi := ""
	port := o.port
	if o.conf != "" {
		f, err := os.Open(o.conf)
		if err != nil {
			return err
		}
		var lp uint16
		uapi, lp, err = wgConfToUAPI(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", o.conf, err)
		}
		if lp != 0 {
			port = lp
		}
	}

	if o.pprofAddr != "" {
		runtime.SetMutexProfileFraction(100)
		runtime.SetBlockProfileRate(100000)
		go func() { log.Error("pprof", "err", http.ListenAndServe(o.pprofAddr, nil)) }()
	}

	var genCfg *gateway.Gen
	if o.genSpec != "" {
		var err error
		if genCfg, err = parseGen(o.genSpec); err != nil {
			return fmt.Errorf("-gen: %w", err)
		}
	}
	txQueues := o.queues
	if o.fastPath || genCfg != nil {
		// One per receive goroutine -- the fast path transmits on it, the
		// generator allocates from it -- and one shared for the stock path.
		txQueues = o.queues + 1
	}
	var steerDst netip.Prefix
	if o.kernelTUN != "" {
		// Take the tunnel and nothing else: the plaintext on the same VLAN
		// is the kernel's to route.
		steerDst = netip.PrefixFrom(uIP.Addr(), uIP.Addr().BitLen())
	}
	open := func() (packetio.Device, backend.Info, error) {
		return backend.Open(backend.Options{Name: o.dev, Queues: o.queues, TxQueues: txQueues, MTU: o.portMTU, FrameSize: o.frameSize,
			Frames: o.frames, RxDepth: o.rxDepth, NoHugeMB: o.noHuge, Promisc: o.promisc, MAC: mac, DevArgs: o.devArgs, SteerVLAN: o.steerVLAN, SteerDstIP: steerDst})
	}
	d, info, err := open()
	if err != nil && txQueues > o.queues {
		// Perhaps the device has no queue to spare -- a virtual one with a
		// single queue pair -- in which case the receive goroutines can
		// share a transmit queue with the stock path. Only try; if that
		// fails too the spare queue was not the problem, so report the
		// first error.
		txQueues = o.queues
		if d2, info2, err2 := open(); err2 == nil {
			log.Warn("no spare transmit queue; sharing one with the stock path", "err", err)
			d, info, err = d2, info2, nil
		}
	}
	if err != nil {
		return err
	}
	defer d.Close()
	log.Info("device open", "backend", info.Backend, "mac", info.MAC, "queues", info.Queues, "max_frame", info.MaxFrame)

	var ktunFDs []int
	if o.kernelTUN != "" && o.fastPath {
		if ktunFDs, err = mqtun.OpenQueues(o.kernelTUN, o.mtu, o.queues); err != nil {
			return fmt.Errorf("-kernel-tun: %w", err)
		}
	}
	g, err := gateway.New(gateway.Config{Device: d, MAC: info.MAC, UnderlayVLAN: o.uVLAN, UnderlayIP: uIP,
		ListenPort: port, LANVLAN: o.lVLAN, LANIP: lIP, Routes: rts, MTU: o.mtu, CPUs: cpus, TUNCPU: o.tunCPU,
		Neighbors: nb, Log: log, Name: o.name, FastPath: o.fastPath, Diagnostics: o.diag, Spray: o.spray, SprayByFlow: o.sprayMode == "flow",
		Gen: genCfg, Sink: o.sink, MinOffset: info.MinOffset, KernelTUN: ktunFDs})
	if err != nil {
		return err
	}

	level := device.LogLevelError
	if o.verbose {
		level = device.LogLevelVerbose
	}
	var tdev tun.Device = g.TUN()
	var mq *mqtun.Device
	if o.kernelTUN != "" && o.fastPath {
		log.Info("plaintext through the kernel", "tun", o.kernelTUN, "queues", o.queues, "driver", "receive goroutines", "steer", steerDst)
	} else if o.kernelTUN != "" {
		if o.tunQueues > 0 {
			if mq, err = mqtun.Open(o.kernelTUN, o.mtu, o.tunQueues); err != nil {
				return fmt.Errorf("-kernel-tun: %w", err)
			}
			tdev = mq
		} else if tdev, err = tun.CreateTUN(o.kernelTUN, o.mtu); err != nil {
			return fmt.Errorf("-kernel-tun: %w", err)
		}
		log.Info("plaintext through the kernel", "tun", o.kernelTUN, "queues", max(o.tunQueues, 1), "steer", steerDst)
	}
	wg := device.NewDevice(tdev, g.Bind(), device.NewLogger(level, "["+o.name+"] "))
	g.SetDevice(wg)
	if o.fastPath {
		// Before IpcSet: the observer does not replay existing keypairs.
		installKeypairObserver(wg, g)
	}
	if uapi != "" {
		if err := wg.IpcSet(uapi); err != nil {
			return fmt.Errorf("configuring device: %w", err)
		}
		g.ConfigChanged()
	}
	if err := wg.Up(); err != nil {
		return fmt.Errorf("device up: %w", err)
	}

	var listener net.Listener
	if !o.noUAPI {
		f, err := ipc.UAPIOpen(o.name)
		if err != nil {
			return fmt.Errorf("uapi socket: %w", err)
		}
		listener, err = ipc.UAPIListen(o.name, f)
		if err != nil {
			return fmt.Errorf("uapi listen: %w", err)
		}
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				// Each request on the connection gets its own generation
				// bump, not just the connection as a whole: a client that
				// holds it open would otherwise leave the cryptokey-routing
				// caches serving what the configuration used to say.
				go wg.IpcHandle(&uapiConn{Conn: c, done: g.ConfigChanged})
			}
		}()
		log.Info("uapi ready", "cmd", "wg show "+o.name)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	var stats <-chan time.Time
	if o.statsEvery > 0 {
		ticker := time.NewTicker(o.statsEvery)
		defer ticker.Stop()
		stats = ticker.C
	}
	log.Info("running", "underlay", fmt.Sprintf("vlan %d %s udp/%d", o.uVLAN, uIP, port), "lan", fmt.Sprintf("vlan %d %s mtu %d", o.lVLAN, lIP, o.mtu))
	for {
		select {
		case <-stop:
			log.Info("stopping")
			if listener != nil {
				listener.Close()
			}
			wg.Close()
			return g.Close()
		case <-wg.Wait():
			return errors.New("wireguard device closed")
		case <-stats:
			s := g.Counters()
			var missed, rxErr, txErr uint64
			if info.PortStats != nil {
				missed, rxErr, txErr, _ = info.PortStats()
			}
			qDropped, qPoolEmpty := g.QueueDrops()
			var perQ []string
			for _, n := range g.QueuePackets() {
				perQ = append(perQ, fmt.Sprint(n))
			}
			if mq != nil {
				log.Info("mqtun", "read", mq.ReadPackets.Load(), "write", mq.WritePackets.Load(), "write_err", mq.WriteErrors.Load(), "short", mq.Short.Load())
			}
			log.Info("stats",
				"nic_missed", missed, "nic_rx_err", rxErr, "nic_tx_err", txErr, "rxq_dropped", qDropped, "rxq_pool_empty", qPoolEmpty, "rxq", strings.Join(perQ, "/"),
				"rx", s.RxFrames, "rx_tunnel_slow", s.RxTunnel, "rx_lan_slow", s.RxLAN,
				"tx_tunnel_slow", s.TxTunnel, "tx_lan_slow", s.TxLAN,
				"lan_ring_full", s.LANRingFull, "tx_ring_full", s.TxRingFull, "tx_error", s.TxError, "lan_oversize", s.LANOversize,
				"no_neighbor", s.TxNoNeighbor, "no_route", s.TxNoRoute,
				"arp", s.RxARP, "icmp", s.RxICMP, "other", s.RxOther, "o_self", s.OtherSelf, "o_type", s.OtherType, "o_udst", s.OtherUnderlayDst, "o_lanmac", s.OtherLANNotOurs, "o_vlan", s.OtherVLAN,
				"fp_dec", s.FPDecrypted, "fp_enc", s.FPEncrypted, "fp_punt", s.FPPunted, "fp_authfail", s.FPAuthFail, "fp_replay", s.FPReplay, "fp_unallowed", s.FPUnallowed, "fp_nokey", s.FPNoKeypair, "fp_noroom", s.FPNoRoom, "fp_nopeer", s.FPNoPeer, "fp_keepalive", s.FPKeepalive, "gen", s.GenPackets, "gen_dropped", s.GenDropped, "sink", s.SinkPackets,
				"ktun_read", s.KTUNRead, "ktun_read_drop", s.KTUNReadDropped, "ktun_write", s.KTUNWrite, "ktun_write_drop", s.KTUNWriteDropped,
				"tun_reads", s.TUNReads, "tun_empty", s.TUNEmpty, "tun_wakes", s.TUNWakes, "tun_timeouts", s.TUNTimeouts,
				"rx_gaps", s.RxGaps, "rx_max_gap_us", s.RxMaxGapNs/1000, "tun_gaps", s.TUNGaps, "tun_max_gap_us", s.TUNMaxGapNs/1000)
		}
	}
}

// uapiConn is the UAPI connection with a hook at both ends of each request.
// wireguard-go writes "errno=<n>\n\n" when it has finished one, which is
// where the configuration it may have changed becomes visible to us -- but
// it applies a request line by line as it reads, so by then the change has
// been live for the length of the request while our cryptokey-routing
// caches still held the old answer. During that window a packet whose
// source had just been moved to another peer would still be accepted from
// the old one. So the generation is bumped on the way in as well, when the
// request contains something that can move an address between peers, and
// again on the way out.
type uapiConn struct {
	net.Conn
	done func()
}

// routingKeys are the UAPI keys that can change which peer owns an address.
var routingKeys = [][]byte{
	[]byte("allowed_ip="), []byte("public_key="), []byte("remove="), []byte("replace_peers="),
	[]byte("replace_allowed_ips="),
}

func (c *uapiConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	for _, k := range routingKeys {
		if bytes.Contains(b[:n], k) {
			c.done()
			break
		}
	}
	return n, err
}

func (c *uapiConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if bytes.Contains(b, []byte("errno=")) {
		c.done()
	}
	return n, err
}

// parseGen reads "pps=N,size=S,flows=F,src=IP,dst=PREFIX,port=P".
func parseGen(spec string) (*gateway.Gen, error) {
	g := &gateway.Gen{Size: 68, Flows: 64, Port: 9000, Src: netip.MustParseAddr("10.154.0.1"), Dst: netip.MustParsePrefix("10.200.3.0/24")}
	for _, kv := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("%q: want key=value", kv)
		}
		var err error
		switch k {
		case "pps":
			g.PPS, err = parseRate(v)
		case "size":
			_, err = fmt.Sscanf(v, "%d", &g.Size)
		case "flows":
			_, err = fmt.Sscanf(v, "%d", &g.Flows)
		case "port":
			var p int
			_, err = fmt.Sscanf(v, "%d", &p)
			g.Port = uint16(p)
		case "src":
			g.Src, err = netip.ParseAddr(v)
		case "dst":
			g.Dst, err = netip.ParsePrefix(v)
		default:
			return nil, fmt.Errorf("unknown key %q", k)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
	}
	if g.Flows < 1 {
		g.Flows = 1
	}
	return g, nil
}

// parseRate accepts 250000, 250k, 2.5M, or 0/unlimited.
func parseRate(v string) (uint64, error) {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "0" || v == "unlimited" || v == "" {
		return 0, nil
	}
	mult := 1.0
	switch v[len(v)-1] {
	case 'k':
		mult, v = 1e3, v[:len(v)-1]
	case 'm':
		mult, v = 1e6, v[:len(v)-1]
	}
	var f float64
	if _, err := fmt.Sscanf(v, "%g", &f); err != nil {
		return 0, err
	}
	return uint64(f * mult), nil
}
