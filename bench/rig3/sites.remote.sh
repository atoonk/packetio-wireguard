# Runs ON sao-3 as root: two network namespaces on VLAN 2049 that stand in for a host
# at site A and a host at site B, so real kernel TCP can be pushed through the real
# gateways. Each has a LAN address (what the gateways route to) and a site address
# (what the tunnel carries). MTU 1420: the tunnel's, so nothing fragments.
#   sites.remote.sh up|down
set -euo pipefail
A_GW=10.154.0.12; B_GW=10.154.0.14
A_MAC=7c:c2:55:be:f3:c7; B_MAC=7c:c2:55:be:f4:1b
# Fixed MACs, and static neighbours both ways: wgpio steers only frames for its own
# MAC to its queues, so an ARP broadcast from a site never reaches it. (The kernel
# gateways would answer ARP; this keeps every mode the same.)
MAC_A=02:53:49:54:45:0a; MAC_B=02:53:49:54:45:0b
case $1 in
down)
  ip netns del site-a 2>/dev/null || true; ip netns del site-b 2>/dev/null || true
  echo "sites down"; exit 0;;
esac
if ip netns exec site-a ip -br addr show mv-site-a 2>/dev/null | grep -q 10.200.2.1 && ip netns exec site-b ip -br addr show mv-site-b 2>/dev/null | grep -q 10.200.3.1; then
  echo "sites already up"; exit 0
fi
ip netns del site-a 2>/dev/null || true; ip netns del site-b 2>/dev/null || true
sleep 0.5
ip link set vlan.2049 up
# sao-3's rings at the card's maximum, as the gateways': a single TCP flow at 10 Gbit/s
# bursts into one RSS queue, and 1024 descriptors overflowed (rx_out_of_buffer).
if [ "$(ethtool -g eno2 | awk '/^Current/{c=1} c&&/^RX:/{print $2; exit}')" != 8192 ]; then
  ethtool -G eno2 rx 8192 tx 8192; sleep 2
fi
mk() { # <ns> <lan ip> <site ip> <site prefix behind the other gw> <gw> <gw mac> <our mac>
  local ns=$1 lan=$2 site=$3 far=$4 gw=$5 gwmac=$6 mac=$7
  ip netns add $ns
  ip link add mv-$ns link vlan.2049 address $mac type macvlan mode bridge
  ip link set mv-$ns netns $ns
  ip -n $ns link set lo up
  ip -n $ns link set mv-$ns mtu 1420 up
  ip -n $ns addr add $lan/24 dev mv-$ns
  ip -n $ns addr add $site/24 dev mv-$ns
  ip -n $ns neigh replace $gw lladdr $gwmac dev mv-$ns nud permanent
  ip -n $ns route add $far via $gw dev mv-$ns src $site
  ip netns exec $ns sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.mv-$ns.rp_filter=0
  ip netns exec $ns sysctl -qw net.ipv4.tcp_rmem="4096 1048576 33554432" net.ipv4.tcp_wmem="4096 1048576 33554432" 2>/dev/null || true
}
mk site-a 10.154.0.21 10.200.2.1 10.200.3.0/24 $A_GW $A_MAC $MAC_A
mk site-b 10.154.0.22 10.200.3.1 10.200.2.0/24 $B_GW $B_MAC $MAC_B
echo "sites up: site-a 10.200.2.1 (lan 10.154.0.21, via $A_GW)  site-b 10.200.3.1 (lan 10.154.0.22, via $B_GW)  mac-a $(ip -n site-a link show mv-site-a | awk '/ether/{print $2}')  mac-b $(ip -n site-b link show mv-site-b | awk '/ether/{print $2}')"
