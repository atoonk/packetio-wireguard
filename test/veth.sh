#!/usr/bin/env bash
# Single-box end-to-end test: two wgpio gateways on the two ends of a veth pair, through
# DPDK's net_af_packet virtual device (no NIC, no hugepages). Checks the handshake, then
# that a tagged LAN frame injected at A comes out of B decrypted, and the reverse.
#   sudo test/veth.sh [path/to/wgpio]
set -euo pipefail
WGPIO=${1:-$(dirname "$0")/../bin/wgpio}
# The frames are injected with python3 and counted with tcpdump; without tcpdump the
# count is silently zero and the test reports a failure that is not one.
for t in python3 tcpdump ip; do
  command -v $t >/dev/null || { echo "veth.sh needs $t (apt install tcpdump python3 iproute2)"; exit 2; }
done
# The ladder's binaries are wgpio-stock, wgpio-p1 ... so cleanup must kill the
# name it actually started, not "wgpio".
WGNAME=$(basename "$WGPIO")
VU=${VU:-2131} VL=${VL:-2154}         # set VU=0 VL=0 for the untagged variant
A=wgtA B=wgtB
# The device argument differs per backend: a DPDK vdev spec, or just the interface
# name for AF_XDP. Override to test another backend on the same veth pair.
DEVA=${DEVA:-net_af_packet0,iface=wgtA} DEVB=${DEVB:-net_af_packet1,iface=wgtB}
cleanup() {
  pkill -x "$WGNAME" 2>/dev/null || true
  for i in $(seq 40); do pgrep -x "$WGNAME" >/dev/null || break; sleep 0.25; done
  pkill -9 -x "$WGNAME" 2>/dev/null || true; sleep 0.5
  ip link del $A 2>/dev/null || true
  rm -rf "${tmp:-}" /var/run/wireguard/wgpioA.sock /var/run/wireguard/wgpioB.sock
}
cleanup 2>/dev/null
tmp=$(mktemp -d); trap 'cleanup' EXIT
ip link add $A type veth peer name $B
ip link set $A up mtu 1600; ip link set $B up mtu 1600
sysctl -qw net.ipv6.conf.$A.disable_ipv6=1 net.ipv6.conf.$B.disable_ipv6=1
MACA=$(cat /sys/class/net/$A/address); MACB=$(cat /sys/class/net/$B/address)
umask 077
wg genkey > $tmp/a.key; wg pubkey < $tmp/a.key > $tmp/a.pub
wg genkey > $tmp/b.key; wg pubkey < $tmp/b.key > $tmp/b.pub
cat > $tmp/a.conf <<CONF
[Interface]
PrivateKey = $(cat $tmp/a.key)
ListenPort = 51820
[Peer]
PublicKey = $(cat $tmp/b.pub)
AllowedIPs = 10.209.2.0/24, 10.154.9.0/24
Endpoint = 10.131.9.2:51820
PersistentKeepalive = 5
CONF
cat > $tmp/b.conf <<CONF
[Interface]
PrivateKey = $(cat $tmp/b.key)
ListenPort = 51820
[Peer]
PublicKey = $(cat $tmp/a.pub)
AllowedIPs = 10.209.1.0/24, 10.154.9.0/24
Endpoint = 10.131.9.1:51820
CONF
common="-no-huge 256 -frame-size 4096 -stats ${STATS:-0} ${WGPIO_FLAGS:-}"
# Each side's LAN next hop is a made-up host with a static MAC; the test watches for frames to it.
$WGPIO -i "$DEVA" $common -name wgpioA -underlay-vlan $VU -underlay-ip 10.131.9.1/24 \
  -lan-vlan $VL -lan-ip 10.154.9.1/24 -route 10.209.1.0/24=10.154.9.101 -neighbor 10.154.9.101=02:00:00:00:01:01 \
  -config $tmp/a.conf > $tmp/a.log 2>&1 &
# Stagger the second EAL: two of them initialising at the same instant
# intermittently fail to probe their vdev ("Operation not permitted").
sleep 2
$WGPIO -i "$DEVB" $common -name wgpioB -underlay-vlan $VU -underlay-ip 10.131.9.2/24 \
  -lan-vlan $VL -lan-ip 10.154.9.2/24 -route 10.209.2.0/24=10.154.9.102 -neighbor 10.154.9.102=02:00:00:00:02:02 \
  -config $tmp/b.conf > $tmp/b.log 2>&1 &
# Wait for both UAPI sockets rather than guessing: DPDK's EAL takes a
# second or two, and longer on a busy box, which used to fail the run.
for n in wgpioA wgpioB; do
  for i in $(seq 60); do wg show $n >/dev/null 2>&1 && break; sleep 0.25; done
  wg show $n >/dev/null 2>&1 || { echo "FAIL: $n not up"; cat $tmp/a.log $tmp/b.log; exit 1; }
done
# Handshake: wg show reports it once the first packets have crossed.
for i in $(seq 40); do
  if wg show wgpioA latest-handshakes | awk '{exit !($2>0)}'; then break; fi; sleep 0.25
done
wg show wgpioA latest-handshakes | awk '{exit !($2>0)}' || { echo "FAIL: no handshake"; cat $tmp/a.log $tmp/b.log; exit 1; }
echo "ok: handshake (A<->B over vlan $VU)"

# Inject a LAN frame at A (raw socket on B's end of the cable, dst = A's MAC): IPv4 UDP
# 10.154.9.50 -> 10.209.2.7. A must tunnel it to B; B must emit it on its LAN to 02:00:00:00:02:02.
inject() { # <iface> <dst mac> <src ip> <dst ip> <size>
  python3 - "$@" "$VL" <<'PY'
import socket, struct, sys
iface, dmac, sip, dip, size, vlan = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6])
def csum(b):
    if len(b) % 2: b += b'\0'
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
payload = bytes(range(256)) * 8
udplen = size
udp = struct.pack('!HHHH', 4000, 9000, 8 + udplen, 0) + payload[:udplen]
ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0, socket.inet_aton(sip), socket.inet_aton(dip))
ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + udp
eth = bytes.fromhex(dmac.replace(':', '')) + bytes.fromhex('02deadbeef01')
if vlan: eth += struct.pack('!HH', 0x8100, vlan)
eth += b'\x08\x00'
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
for _ in range(5): s.send(eth + ip)
PY
}
capture() { # <iface> <dst mac> <dst ip> -> prints count of matching IPv4 frames within 4s
  timeout 5 tcpdump -i "$1" -nn -l -c 3 -e "ether dst $2 and dst host $3 and udp" 2>/dev/null | grep -c "$3" || true
}
( capture $A 02:00:00:00:02:02 10.209.2.7 > $tmp/c1 ) & cap=$!; sleep 0.7
inject $B $MACA 10.154.9.50 10.209.2.7 100; wait $cap
[ "$(cat $tmp/c1)" -ge 3 ] || { echo "FAIL: A->B: $(cat $tmp/c1) frames out of B"; echo "A:"; tail -n 30 $tmp/a.log; echo "B:"; tail -n 30 $tmp/b.log; exit 1; }
echo "ok: A -> tunnel -> B -> LAN (100-byte UDP)"
( capture $B 02:00:00:00:01:01 10.209.1.7 > $tmp/c2 ) & cap=$!; sleep 0.7
inject $A $MACB 10.154.9.60 10.209.1.7 1380; wait $cap
[ "$(cat $tmp/c2)" -ge 3 ] || { echo "FAIL: B->A: $(cat $tmp/c2) frames out of A"; echo "A:"; tail -n 30 $tmp/a.log; echo "B:"; tail -n 30 $tmp/b.log; exit 1; }
echo "ok: B -> tunnel -> A -> LAN (1380-byte UDP)"
# Oversize (1500-byte IP packet > MTU 1420) must not cross.
( capture $A 02:00:00:00:02:02 10.209.2.8 > $tmp/c3 ) & cap=$!; sleep 0.7
inject $B $MACA 10.154.9.50 10.209.2.8 1472; wait $cap
[ "$(cat $tmp/c3)" -eq 0 ] || { echo "FAIL: oversize packet crossed"; exit 1; }
echo "ok: oversize dropped"
wg show wgpioA transfer | awk '{printf "ok: A transfer rx=%s tx=%s bytes\n", $2, $3}'
if [ -n "${LOAD:-}" ]; then
  # A burst of LOAD packets A -> B; B's tunnel receive count must match what A sent.
  before=$(wg show wgpioB transfer | awk '{print $2}')
  python3 - "$B" "$MACA" "$LOAD" "$VL" <<'PY'
import socket, struct, sys
iface, dmac, n, vlan = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
def csum(b):
    s = sum(struct.unpack('!%dH' % (len(b)//2), b))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff
udp = struct.pack('!HHHH', 4000, 9000, 8 + 72, 0) + bytes(72)
ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0, socket.inet_aton('10.154.9.50'), socket.inet_aton('10.209.2.9'))
ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:] + udp
eth = bytes.fromhex(dmac.replace(':', '')) + bytes.fromhex('02deadbeef01')
if vlan: eth += struct.pack('!HH', 0x8100, vlan)
frame = eth + b'\x08\x00' + ip
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind((iface, 0))
for _ in range(n): s.send(frame)
PY
  sleep 3
  after=$(wg show wgpioB transfer | awk '{print $2}')
  got=$(( (after - before) / (16 + 100 + 16) ))   # transport header + padded packet + tag, per datagram
  echo "load: sent $LOAD, B received ~$got datagrams ($(( after - before )) bytes)"
  [ "$got" -ge $((LOAD * 99 / 100)) ] || { echo "FAIL: lost more than 1% under load"; echo "A:"; tail -n 30 $tmp/a.log; echo "B:"; tail -n 30 $tmp/b.log; exit 1; }
  echo "ok: burst of $LOAD packets delivered"
  tail -1 $tmp/a.log; tail -1 $tmp/b.log
fi
if [ -n "${STATS:-}" ]; then for x in a b; do echo "$x: $(grep msg=stats $tmp/$x.log | tail -1 | sed "s/.*msg=stats //" | tr " " "\n" | grep -E "fp_(dec|enc|punt|authfail|replay)|rx_lan_slow|tx_lan_slow|rx_tunnel_slow|tx_tunnel_slow|tun_reads" | tr "\n" " ")"; done; fi
echo PASS
