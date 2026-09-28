# Runs ON a 100G box as root: kernel WireGuard (or wireguard-go with MODE=wggo) on VLAN 2049,
# same keys and addressing as wgpio. args: <role A|B> <privkey> <peer pubkey> <kernel|wggo>
set -euo pipefail
role=$1 key=$2 peerpub=$3 mode=$4
case $role in A) MY=10.49.0.2; PEER=10.49.0.3; MYLAN=10.154.0.2; BEHIND=10.200.2.0/24;; B) MY=10.49.0.3; PEER=10.49.0.2; MYLAN=10.154.0.3; BEHIND=10.200.3.0/24;; esac
systemctl stop wgpio 2>/dev/null || true
ip link add link eno2 name vlan.2049 type vlan id 2049 2>/dev/null || true
ip link set vlan.2049 up; ip addr replace $MY/24 dev vlan.2049
ip link del wg0 2>/dev/null || true
systemctl stop wireguard-go 2>/dev/null || true
if [ "$mode" = wggo ]; then
  systemctl reset-failed wireguard-go 2>/dev/null || true
  systemd-run --unit=wireguard-go --collect -E LOG_LEVEL=error /usr/local/bin/wireguard-go -f wg0
  for i in $(seq 50); do [ -e /sys/class/net/wg0 ] && break; sleep 0.1; done
else
  ip link add wg0 type wireguard
fi
ip link set wg0 mtu 1420
umask 077; kf=$(mktemp); echo "$key" > "$kf"
wg set wg0 private-key "$kf" listen-port 51820 peer "$peerpub" endpoint $PEER:51820 allowed-ips 10.200.0.0/16,10.154.0.0/24 persistent-keepalive 25
rm -f "$kf"
ip addr replace $MYLAN/24 dev wg0 2>/dev/null || true
ip link set wg0 up
# the prefix "behind" the peer goes into the tunnel; what arrives for our own prefix is dropped (the sink)
ip route replace 10.200.0.0/16 dev wg0
ip route replace $BEHIND dev lo 2>/dev/null || ip route replace $BEHIND via 127.0.0.1 dev lo
sysctl -qw net.ipv4.ip_forward=1
echo "$role: $mode wg0 up"; wg show wg0 | sed -n 1p
