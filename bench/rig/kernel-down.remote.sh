# Runs ON a peer. Tears down kernel WireGuard and our LAN VLAN; leaves vlan.2131 and its
# pre-existing 192.168.0.x address alone (other projects use it), removes only our address.
set -euo pipefail
ip link del wg0 2>/dev/null || true
ip route del 10.200.2.0/24 2>/dev/null || true
ip route del 10.200.3.0/24 2>/dev/null || true
ip addr del 10.131.0.2/24 dev vlan.2131 2>/dev/null || true
ip addr del 10.131.0.3/24 dev vlan.2131 2>/dev/null || true
ip link del vlan.2154 2>/dev/null || true
echo "$(hostname): kernel wireguard down"
