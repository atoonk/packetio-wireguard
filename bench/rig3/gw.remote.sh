# Runs ON a gateway (sao-2 = A, sao-4 = B) as root. Tears down whatever ran before,
# then brings up one gateway mode:
#
#   kernel      kernel WireGuard (wg0); the kernel forwards the plaintext
#   wggo        wireguard-go on a kernel TUN (wg0); the kernel forwards the plaintext
#   wggo-mq     the same, with a multi-queue TUN (<queues> TUN queues); no packetio
#   wggo-fast   the fork's fast path over UDP sockets + multi-queue TUN; no packetio
#   wgpio       wgpio, all userspace: packetio on the tunnel AND the LAN side    (Design A)
#   wgpio-tun   wgpio for the tunnel, a kernel TUN for the plaintext; the kernel
#               routes it (Design B). Pass -fastpath=false [-kernel-tun-queues N]
#               for the stock pipeline; with the fast path each receive core drives
#               a TUN queue
#   down        just the teardown
#
#   gw.remote.sh <mode> <A|B> <privkey> <peer pubkey> <peer mac> <src mac> <queues> <cpus> <binary> <site next hop|-> [extra wgpio flags...]
set -euo pipefail
mode=$1 role=$2 key=$3 peerpub=$4 peermac=$5 srcmac=$6 queues=$7 cpus=$8 bin=$9 sitenh=${10}; shift 10
case $role in
  # MYSITE is what is behind us (it lives on sao-3); PEERSITE is behind the peer.
  A) MY=10.49.0.12; PEER=10.49.0.14; MYLAN=10.154.0.12; MYSITE=10.200.2.0/24; PEERSITE=10.200.3.0/24;;
  B) MY=10.49.0.14; PEER=10.49.0.12; MYLAN=10.154.0.14; MYSITE=10.200.3.0/24; PEERSITE=10.200.2.0/24;;
esac
SRC_LAN=10.154.0.13
NS_A_LAN=10.154.0.21; NS_A_MAC=02:53:49:54:45:0a; NS_B_LAN=10.154.0.22; NS_B_MAC=02:53:49:54:45:0b  # sites.remote.sh
[ -n "$sitenh" ] && [ "$sitenh" != - ] || sitenh=$SRC_LAN   # where our site's hosts are: the sink, or a namespace on sao-3
PORT=51820

# --- teardown: leave nothing of the previous mode behind ---
systemctl stop wgpio wireguard-go 2>/dev/null || true
systemctl reset-failed wgpio wireguard-go 2>/dev/null || true
for i in $(seq 50); do pgrep -x wgpio >/dev/null || pgrep -x wireguard-go >/dev/null || break; sleep 0.1; done
ip link del wg0 2>/dev/null || true
ip link del wgtun 2>/dev/null || true
ip link add link eno2 name vlan.2049 type vlan id 2049 2>/dev/null || true
ip link set eno2 up; ip link set vlan.2049 up
ip addr flush dev vlan.2049
ip route del $MYSITE 2>/dev/null || true
ip route del $PEERSITE 2>/dev/null || true
[ "$mode" = down ] && { echo "$role: down"; exit 0; }

# The kernel's receive rings, at the card's maximum. All of a tunnel is one flow, so it
# lands on one receive queue, and at the default 1024 that ring overflowed on bursts
# from the encrypting side while the core behind it sat nearly idle: 3.5% lost at
# 200 kpps, all of it in rx_out_of_buffer. Standard tuning for any gateway; the same
# for every mode.
if [ "$(ethtool -g eno2 | awk '/^Current/{c=1} c&&/^RX:/{print $2; exit}')" != 8192 ]; then
  ethtool -G eno2 rx 8192 tx 8192; sleep 2
fi

sysctl -qw net.ipv4.ip_forward=1
# sao-3 sends from addresses the gateway has no route back to through the port they
# arrive on (site A arrives at B out of the tunnel, and so on); strict reverse-path
# filtering would drop them. This is a lab with static routes, not an edge.
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > "$f"; done
# Same socket-buffer reasoning as bench/rigsao/kernel-up.remote.sh: raise receive only.
sysctl -qw net.core.rmem_max=134217728 net.core.rmem_default=16777216 net.core.netdev_max_backlog=250000

conf=/run/wg-rig3.conf
umask 077
cat > $conf <<EOF
[Interface]
PrivateKey = $key
ListenPort = $PORT

[Peer]
PublicKey = $peerpub
Endpoint = $PEER:$PORT
AllowedIPs = $PEERSITE
PersistentKeepalive = 25
EOF

kernel_plaintext() { # the kernel's half, shared by kernel, wggo and wgpio-tun
  local tundev=$1
  ip addr replace $MYLAN/24 dev vlan.2049
  ip neigh replace $SRC_LAN lladdr $srcmac dev vlan.2049 nud permanent
  ip neigh replace $NS_A_LAN lladdr $NS_A_MAC dev vlan.2049 nud permanent
  ip neigh replace $NS_B_LAN lladdr $NS_B_MAC dev vlan.2049 nud permanent
  # The TUN's queue is 500 packets by default, and a userspace reader takes it in
  # its own time; a burst that would not trouble a NIC is dropped here and counted
  # in tx_dropped. The same figure kernel WireGuard gets from its own queue.
  ip link set $tundev txqueuelen 10000
  ip route replace $PEERSITE dev $tundev
  ip route replace $MYSITE via $sitenh dev vlan.2049
}

# The kernel's share of the work -- receiving from the NIC, and forwarding what we
# write into the TUN -- must stay off the cores the receive goroutines spin on, or
# past the knee the softirqs steal the goroutines' time, the goroutines drain the
# TUN slower, the kernel drops more at the TUN and burns more doing it: a livelock
# that took delivery from 4.5 M to 0.9 M. NIC interrupts go to the other cores;
# RPS on the TUN moves the forwarding of written packets off the writing core.
# What any DPDK deployment does for its polling cores.
isolate_packet_cores() { # <tun device>
  local tundev=${1:-wgtun}
  systemctl stop irqbalance 2>/dev/null || true
  read -r lst mask < <(python3 - "$cpus" <<'PY2'
import sys
used = set()
for part in sys.argv[1].split(','):
    a, _, b = part.partition('-')
    used.update(range(int(a), int(b or a) + 1))
free = [c for c in range(48) if c not in used]
bits = sum(1 << c for c in free)
print(','.join(map(str, free)), f"{bits >> 32:x},{bits & 0xffffffff:08x}")
PY2
)
  for irq in $(awk -F: '/mlx5_comp.*c1:00\.1/{gsub(" ","",$1); print $1}' /proc/interrupts); do
    echo "$lst" > /proc/irq/$irq/smp_affinity_list 2>/dev/null || true
  done
  for q in /sys/class/net/$tundev/queues/rx-*; do echo "$mask" > $q/rps_cpus; done
  echo "$role: NIC irqs and TUN rps on cpus $lst (packet cores $cpus)"
}

case $mode in
kfwd)
  # No tunnel: the kernel routes the plaintext straight to the other gateway. What
  # the kernel path costs before WireGuard is added to it.
  ip addr replace $MY/24 dev vlan.2049
  ip neigh replace $PEER lladdr $peermac dev vlan.2049 nud permanent
  ip addr replace $MYLAN/24 dev vlan.2049
  ip neigh replace $SRC_LAN lladdr $srcmac dev vlan.2049 nud permanent
  ip neigh replace $NS_A_LAN lladdr $NS_A_MAC dev vlan.2049 nud permanent
  ip neigh replace $NS_B_LAN lladdr $NS_B_MAC dev vlan.2049 nud permanent
  ip route replace $PEERSITE via $PEER dev vlan.2049
  ip route replace $MYSITE via $sitenh dev vlan.2049
  ;;
l3fwd)
  # No tunnel, no kernel: packetio's example router. The rig's own ceiling.
  systemd-run --unit=wgpio --collect /usr/local/bin/pio-l3fwd -i eno2 -vlan 2049 -queues $queues -cpus $cpus \
    -route $PEERSITE,$peermac,2049 -route $MYSITE,$srcmac,2049 -duration 0 -report 1s   # l3fwd: the sink only
  ;;
kernel|wggo|wggo-mq|wggo-fast)
  ip addr replace $MY/24 dev vlan.2049
  ip neigh replace $PEER lladdr $peermac dev vlan.2049 nud permanent
  if [ $mode = wggo-fast ]; then
    # the fork's fast path over UDP sockets and a multi-queue TUN; no packetio.
    # <queues> is the number of TUN queues and sockets (ports 51820..+queues-1)
    systemd-run --unit=wireguard-go --collect /usr/local/bin/wggo-fast -name wg0 -queues $queues -port $PORT -mtu 1420 -stats 1s "$@"
    for i in $(seq 100); do [ -e /sys/class/net/wg0 ] && break; sleep 0.1; done
    [ -e /sys/class/net/wg0 ] || { journalctl -u wireguard-go --no-pager -o cat | tail -5; exit 1; }
  elif [ $mode = wggo-mq ]; then
    # upstream wireguard-go with only the TUN swapped for a multi-queue one;
    # <queues> is the number of TUN queues
    systemd-run --unit=wireguard-go --collect /usr/local/bin/wggo-mq -name wg0 -queues $queues -mtu 1420 "$@"
    for i in $(seq 100); do [ -e /sys/class/net/wg0 ] && break; sleep 0.1; done
    [ -e /sys/class/net/wg0 ] || { journalctl -u wireguard-go --no-pager -o cat | tail -5; exit 1; }
  elif [ $mode = wggo ]; then
    systemd-run --unit=wireguard-go --collect -E LOG_LEVEL=error /usr/local/bin/wireguard-go -f wg0
    for i in $(seq 100); do [ -e /sys/class/net/wg0 ] && break; sleep 0.1; done
    [ -e /sys/class/net/wg0 ] || { journalctl -u wireguard-go --no-pager -o cat | tail -5; exit 1; }
  else
    ip link add wg0 type wireguard
  fi
  wg setconf wg0 $conf
  ip link set wg0 mtu 1420 up
  kernel_plaintext wg0
  [ $mode = wggo-fast ] && isolate_packet_cores wg0
  ;;
wgpio)
  # Everything on VLAN 2049 is ours; the kernel keeps no address on it.
  systemd-run --unit=wgpio --collect /usr/local/bin/$bin -i eno2 -queues $queues -cpus $cpus \
    -steer-vlan 2049 -underlay-vlan 2049 -underlay-ip $MY/24 -lan-vlan 2049 -lan-ip $MYLAN/24 \
    -neighbor $PEER=$peermac -neighbor $SRC_LAN=$srcmac -neighbor $NS_A_LAN=$NS_A_MAC -neighbor $NS_B_LAN=$NS_B_MAC -route $MYSITE=$sitenh \
    -spray 64 -config $conf -stats 1s "$@"
  ;;
wgpio-tun)
  # packetio takes only frames for the underlay address; the plaintext on the same
  # VLAN is the kernel's, which routes it into and out of wgtun.
  systemd-run --unit=wgpio --collect /usr/local/bin/$bin -i eno2 -queues $queues -cpus $cpus \
    -steer-vlan 2049 -underlay-vlan 2049 -underlay-ip $MY/24 -lan-vlan 2049 -lan-ip $MYLAN/24 \
    -neighbor $PEER=$peermac -spray 64 -config $conf -stats 1s \
    -kernel-tun wgtun "$@"
  for i in $(seq 100); do [ -e /sys/class/net/wgtun ] && break; sleep 0.1; done
  [ -e /sys/class/net/wgtun ] || { journalctl -u wgpio --no-pager -o cat | tail -5; exit 1; }
  ip link set wgtun mtu 1420 up
  kernel_plaintext wgtun
  isolate_packet_cores wgtun
  ;;
*) echo "unknown mode $mode"; exit 1;;
esac
sleep 1
case $mode in wgpio*|l3fwd) systemctl is-active -q wgpio || { journalctl -u wgpio --no-pager -o cat | tail -8; exit 1; };; esac
echo "$role: $mode up ($(hostname)) | to peer site: $(ip route get ${PEERSITE%/*} 2>&1 | head -1) | to my site: $(ip route get ${MYSITE%/*} 2>&1 | head -1)"
