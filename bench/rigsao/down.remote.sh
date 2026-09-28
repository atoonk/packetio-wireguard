# Runs ON a São Paulo box as root: stop everything this harness starts and leave the
# box in its resting state -- kernel VLAN netdev up with its address, peer pinned in
# the neighbour table, no wgpio, no wireguard-go, no wg0.
#   down.remote.sh <role A|B> <peer underlay ip> <peer mac>
set -uo pipefail
role=$1 peerip=$2 peermac=$3
case $role in A) MY=10.49.0.1;; B) MY=10.49.0.2;; esac
systemctl stop wgpio 2>/dev/null; systemctl reset-failed wgpio 2>/dev/null
systemctl stop wireguard-go 2>/dev/null; systemctl reset-failed wireguard-go 2>/dev/null
pkill -x wgpio-stock; pkill -x wgpio-p1; pkill -x wgpio-p2; pkill -x wgpio-p3; pkill -x wgpio-p4
ip link del wg0 2>/dev/null
ip link add link eno2 name vlan.2049 type vlan id 2049 2>/dev/null
ip link set vlan.2049 up
ip addr replace $MY/24 dev vlan.2049
# udpblast cycles the last octet over its flow range, so the whole range is pinned:
# an unresolved destination collapses the offered load and looks like a slow receiver.
ip neigh replace $peerip lladdr $peermac dev vlan.2049 nud permanent
for i in $(seq 0 64); do
  ip neigh replace 10.49.0.$i lladdr $peermac dev vlan.2049 nud permanent 2>/dev/null
done
echo "$role: down, vlan.2049 $MY/24 up, peer $peerip pinned"
