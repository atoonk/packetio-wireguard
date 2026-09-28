# Runs ON a São Paulo box as root: kernel WireGuard, or wireguard-go on a kernel TUN,
# on VLAN 2049 with the same keys and addressing wgpio uses.
#   kernel-up.remote.sh <role A|B> <privkey> <peer pubkey> <kernel|wggo> <peer mac> <rps 0|1>
set -euo pipefail
role=$1 key=$2 peerpub=$3 mode=$4 peermac=$5 rps=$6
case $role in
  A) MY=10.49.0.1; PEER=10.49.0.2; MYLAN=10.154.0.2; BEHIND=10.200.2.0/24;;
  B) MY=10.49.0.2; PEER=10.49.0.1; MYLAN=10.154.0.3; BEHIND=10.200.3.0/24;;
esac
systemctl stop wgpio 2>/dev/null || true
ip link add link eno2 name vlan.2049 type vlan id 2049 2>/dev/null || true
ip link set vlan.2049 up; ip addr replace $MY/24 dev vlan.2049
ip neigh replace $PEER lladdr $peermac dev vlan.2049 nud permanent
ip link del wg0 2>/dev/null || true
systemctl stop wireguard-go 2>/dev/null || true
systemctl reset-failed wireguard-go 2>/dev/null || true
if [ "$mode" = wggo ]; then
  systemd-run --unit=wireguard-go --collect -E LOG_LEVEL=error /usr/local/bin/wireguard-go -f wg0
  for i in $(seq 100); do [ -e /sys/class/net/wg0 ] && break; sleep 0.1; done
  [ -e /sys/class/net/wg0 ] || { journalctl -u wireguard-go --no-pager -o cat | tail -5; exit 1; }
else
  ip link add wg0 type wireguard
fi
ip link set wg0 mtu 1420
umask 077; kf=$(mktemp); echo "$key" > "$kf"
wg set wg0 private-key "$kf" listen-port 51820 peer "$peerpub" endpoint $PEER:51820 \
  allowed-ips 10.200.0.0/16,10.154.0.0/24 persistent-keepalive 25
rm -f "$kf"
ip addr replace $MYLAN/24 dev wg0
ip link set wg0 up
# What is behind the peer goes into the tunnel. What arrives for our own prefix is
# discarded, and it matters a great deal HOW.
#
# This used to be "dev lo", and that was wrong: the decrypting box sent a packet back
# through the tunnel for roughly three out of every four it received, so it was paying
# for an encrypt and a transmit on top of every decrypt, and the far side was paying to
# decrypt the return. Both kernel baselines were measured against a receiver doing
# twice the work the benchmark claimed. A blackhole route discards silently at the
# routing decision, with no ICMP and nothing sent back, which is what wgpio's -sink
# does: count the decrypted packet, drop it, do nothing else.
ip route replace 10.200.0.0/16 dev wg0
ip route replace blackhole $BEHIND
sysctl -qw net.ipv4.ip_forward=1
# wireguard-go reads the tunnel from an ordinary UDP socket, so a small receive buffer
# drops datagrams before it ever sees them and the loss is invisible in its own
# counters. Raise the receive side only.
#
# The send side is deliberately left alone. Raising wmem_default turned udpblast into a
# firehose -- 4.9 Mpps offered at a tunnel that carries 0.23 -- and wireguard-go's
# throughput fell from 231 kpps to 1.2 k. That is not its capacity, it is what a
# 20-times overload does to a userspace reader that never gets scheduled. Overload is
# not the thing being measured, so the generator is rate-limited instead (-pps).
sysctl -qw net.core.rmem_max=134217728 net.core.rmem_default=16777216 \
             net.core.netdev_max_backlog=250000 >/dev/null
# Receive Packet Steering: without it one softirq core takes the whole tunnel, since a
# single peer is a single 5-tuple and RSS has nothing to spread. With it the kernel
# hashes each packet onto another core before the WireGuard work begins.
mask() { python3 -c "print(format((1<<$1)-1 if $1<64 else 0,'x'))"; }
if [ "$rps" = 1 ]; then
  m=$(mask 24)   # the 24 physical cores; the SMT siblings are 24..47
  sysctl -qw net.core.rps_sock_flow_entries=32768 >/dev/null
  for q in /sys/class/net/wg0/queues/rx-*; do echo "$m" > $q/rps_cpus; echo 4096 > $q/rps_flow_cnt; done
  for q in /sys/class/net/vlan.2049/queues/rx-* /sys/class/net/eno2/queues/rx-*; do
    [ -e "$q/rps_cpus" ] && { echo "$m" > $q/rps_cpus; echo 4096 > $q/rps_flow_cnt; }
  done
else
  for q in /sys/class/net/wg0/queues/rx-* /sys/class/net/vlan.2049/queues/rx-* /sys/class/net/eno2/queues/rx-*; do
    [ -e "$q/rps_cpus" ] && { echo 0 > $q/rps_cpus; echo 0 > $q/rps_flow_cnt; }
  done
fi
echo "$role: $mode wg0 up rps=$rps"; wg show wg0 | sed -n 1p
# Record what the sink actually is, so a log says it rather than a comment claiming it.
# "ip route get" resolves what actually happens to a packet, which is the thing worth
# recording: "unreachable" here means the sink discards, not that something is broken.
echo "$role sink: $(ip route get ${BEHIND%/*} 2>&1 | head -1) | tunnel: $(ip route show 10.200.0.0/16 | tr -d '\n')"
