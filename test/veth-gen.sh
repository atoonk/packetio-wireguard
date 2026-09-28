#!/usr/bin/env bash
# The built-in generator and sink, end to end on one box: A generates
# plaintext into the tunnel, B counts and drops what comes out. Two gateways
# on a veth pair through DPDK's net_af_packet vdev, as veth.sh.
#
#   sudo test/veth-gen.sh [path/to/wgpio] [seconds]
#   sudo WGPIO_FLAGS=-fastpath=false test/veth-gen.sh bin/wgpio-stock
#
# With the fast path on, the generator hands its frames to fpEncrypt. With it
# off, it parks them in the LAN ring for wireguard-go's own RoutineReadFromTUN,
# which is the path the stock step of the benchmark ladder measures -- and the
# one where a generated frame, which belongs to the transmit pool, must not be
# recycled into the receive pool. This checks that packets arrive and that
# neither side's pools run dry, which is what that mistake looks like.
set -euo pipefail
WGPIO=${1:-$(dirname "$0")/../bin/wgpio}
SECS=${2:-8}
WGNAME=$(basename "$WGPIO")
VU=${VU:-2131} VL=${VL:-2154}
A=wggA B=wggB
DEVA=${DEVA:-net_af_packet0,iface=wggA} DEVB=${DEVB:-net_af_packet1,iface=wggB}
cleanup() {
  # Wait for them to be gone rather than guessing: an af_packet vdev holds
  # locked memory for its PACKET_MMAP rings, and the next run's EAL fails to
  # probe ("Operation not permitted") while the previous run still has it.
  pkill -x "$WGNAME" 2>/dev/null || true
  for i in $(seq 40); do pgrep -x "$WGNAME" >/dev/null || break; sleep 0.25; done
  pkill -9 -x "$WGNAME" 2>/dev/null || true; sleep 0.5
  ip link del $A 2>/dev/null || true
  rm -rf "${tmp:-}" /var/run/wireguard/wggenA.sock /var/run/wireguard/wggenB.sock
}
cleanup 2>/dev/null
tmp=$(mktemp -d); trap 'cleanup' EXIT
ip link add $A type veth peer name $B
ip link set $A up mtu 1600; ip link set $B up mtu 1600
sysctl -qw net.ipv6.conf.$A.disable_ipv6=1 net.ipv6.conf.$B.disable_ipv6=1
umask 077
wg genkey > $tmp/a.key; wg pubkey < $tmp/a.key > $tmp/a.pub
wg genkey > $tmp/b.key; wg pubkey < $tmp/b.key > $tmp/b.pub
cat > $tmp/a.conf <<CONF
[Interface]
PrivateKey = $(cat $tmp/a.key)
ListenPort = 51820
[Peer]
PublicKey = $(cat $tmp/b.pub)
AllowedIPs = 10.200.3.0/24, 10.154.9.0/24
Endpoint = 10.131.9.2:51820
PersistentKeepalive = 5
CONF
cat > $tmp/b.conf <<CONF
[Interface]
PrivateKey = $(cat $tmp/b.key)
ListenPort = 51820
[Peer]
PublicKey = $(cat $tmp/a.pub)
AllowedIPs = 10.200.2.0/24, 10.154.9.0/24
Endpoint = 10.131.9.1:51820
CONF
common="-no-huge 256 -frame-size 4096 -stats 2s ${WGPIO_FLAGS:-}"
$WGPIO -i "$DEVA" $common -name wggenA -underlay-vlan $VU -underlay-ip 10.131.9.1/24 \
  -lan-vlan $VL -lan-ip 10.154.9.1/24 -gen pps=${GENPPS:-200k},size=68,flows=16,src=10.154.9.50,dst=10.200.3.0/24 \
  -config $tmp/a.conf > $tmp/a.log 2>&1 &
# Stagger the second EAL: two of them initialising at the same instant
# intermittently fail to probe their vdev ("Operation not permitted").
sleep 2
$WGPIO -i "$DEVB" $common -name wggenB -underlay-vlan $VU -underlay-ip 10.131.9.2/24 \
  -lan-vlan $VL -lan-ip 10.154.9.2/24 -sink \
  -config $tmp/b.conf > $tmp/b.log 2>&1 &
for n in wggenA wggenB; do
  for i in $(seq 60); do wg show $n >/dev/null 2>&1 && break; sleep 0.25; done
  wg show $n >/dev/null 2>&1 || { echo "FAIL: $n not up"; echo "--- A ---"; cat $tmp/a.log; echo "--- B ---"; cat $tmp/b.log; exit 1; }
done
for i in $(seq 40); do
  wg show wggenA latest-handshakes | awk '{exit !($2>0)}' && break; sleep 0.25
done
wg show wggenA latest-handshakes | awk '{exit !($2>0)}' || { echo "FAIL: no handshake"; cat $tmp/a.log $tmp/b.log; exit 1; }
echo "ok: handshake"

# Counters are read as deltas over a window that starts after the handshake:
# before it, the generator is parking packets the tunnel cannot yet carry and
# wireguard-go stages or drops them, which is not what is being measured.
stat() { grep msg=stats "$1" | tail -1 | tr ' ' '\n' | grep "^$2=" | cut -d= -f2; }
snap() { # <log> <keys...> -> "k=v k=v"
  local f=$1; shift
  local out=""
  for k in "$@"; do out="$out $k=$(stat "$f" "$k")"; done
  echo "$out"
}
KEYS_A="gen gen_dropped lan_ring_full tx_ring_full tun_reads rxq_pool_empty fp_enc tx_tunnel_slow"
KEYS_B="rx rx_tunnel_slow sink fp_dec rxq_dropped rxq_pool_empty"
sleep 3   # let the first post-handshake stats line land
a0=$(snap $tmp/a.log $KEYS_A); b0=$(snap $tmp/b.log $KEYS_B)
sleep "$SECS"
a1=$(snap $tmp/a.log $KEYS_A); b1=$(snap $tmp/b.log $KEYS_B)
delta() { # <before> <after> <key>
  local x y
  x=$(echo "$1" | tr ' ' '\n' | grep "^$3=" | cut -d= -f2)
  y=$(echo "$2" | tr ' ' '\n' | grep "^$3=" | cut -d= -f2)
  echo $(( ${y:-0} - ${x:-0} ))
}
gen=$(delta "$a0" "$a1" gen)
gdrop=$(delta "$a0" "$a1" gen_dropped)
apool=$(delta "$a0" "$a1" rxq_pool_empty)
atx=$(( $(delta "$a0" "$a1" fp_enc) + $(delta "$a0" "$a1" tx_tunnel_slow) ))
sink=$(delta "$b0" "$b1" sink)
brx=$(delta "$b0" "$b1" rx)
bpool=$(delta "$b0" "$b1" rxq_pool_empty)
echo "A: gen=$gen gen_dropped=$gdrop lan_ring_full=$(delta "$a0" "$a1" lan_ring_full) tx_ring_full=$(delta "$a0" "$a1" tx_ring_full) tun_reads=$(delta "$a0" "$a1" tun_reads) rxq_pool_empty=$apool"
echo "B: rx=$brx rx_tunnel=$(delta "$b0" "$b1" rx_tunnel_slow) sink=$sink fp_dec=$(delta "$b0" "$b1" fp_dec) rxq_dropped=$(delta "$b0" "$b1" rxq_dropped) rxq_pool_empty=$bpool"
[ "${gen:-0}" -gt 1000 ] || { echo "FAIL: the generator made $gen packets in the window"; tail -n 5 $tmp/a.log; exit 1; }
[ "${sink:-0}" -gt 1000 ] || { echo "FAIL: the sink saw $sink packets in the window"; tail -n 5 $tmp/a.log; tail -n 5 $tmp/b.log; exit 1; }

# A pool that runs empty is what a leaked frame looks like: the generator
# takes frames from the transmit pool and they must come home to it, not be
# recycled into the receive pool. Nothing else in this test can cause it.
[ "${apool:-0}" -eq 0 ] || { echo "FAIL: A's receive pool ran empty $apool times: frames are leaking"; exit 1; }
[ "${bpool:-0}" -eq 0 ] || { echo "FAIL: B's receive pool ran empty $bpool times: frames are leaking"; exit 1; }
echo "ok: neither pool ran dry"

# What A put on the wire is what B took off it. This is the statement about
# packetio and the gateway; above them is wireguard-go's own queueing, which
# drops when the pipeline is overloaded -- the point of the stock measurement.
loss=$(( atx > 0 ? (atx - brx) * 1000 / atx : 1000 ))
[ "$loss" -lt 0 ] && loss=0
echo "ok: A sent $atx tunnel datagrams, B received $brx frames (${loss}/1000 lost on the wire)"
[ "$loss" -lt 10 ] || { echo "FAIL: more than 1% lost between A's transmit and B's receive"; exit 1; }

if [ "${GENPPS:-200k}" = 0 ]; then
  echo "ok: unlimited run, $sink of $gen generated packets delivered (wireguard-go's queues drop the rest)"
else
  pct=$(( sink * 100 / gen ))
  echo "ok: $pct% of A's generated packets reached B's sink"
  [ "$pct" -ge 90 ] || { echo "FAIL: lost more than 10% between the generator and the sink"; tail -n 3 $tmp/a.log; tail -n 3 $tmp/b.log; exit 1; }
fi
echo PASS
