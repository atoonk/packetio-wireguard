# Runs ON a São Paulo box as root: start one of the ladder's wgpio binaries on the
# DPDK port. The kernel's vlan.2049 netdev is deleted first -- the mlx5 port is
# bifurcated, so the kernel would otherwise claim the tagged frames DPDK is meant to
# receive -- and the peer's MAC is given statically, since with no netdev on the VLAN
# neither side can ARP for the other.
#
#   wgpio-up.remote.sh <role A|B> <binary> <privkey> <peer pubkey> <peer mac>
#                      <queues> <cpus> <tun-cpu> <steer|promisc> [extra flags...]
set -euo pipefail
role=$1 bin=$2 key=$3 peerpub=$4 peermac=$5 queues=$6 cpus=$7 tuncpu=$8 steer=$9; shift 9
case $role in
  A) MY=10.49.0.1; PEER=10.49.0.2; MYLAN=10.154.0.2;;
  B) MY=10.49.0.2; PEER=10.49.0.1; MYLAN=10.154.0.3;;
esac
mkdir -p /etc/wgpio; umask 077
cat > /etc/wgpio/wgpio0.conf <<CONF
[Interface]
PrivateKey = $key
ListenPort = 51820
[Peer]
PublicKey = $peerpub
Endpoint = $PEER:51820
AllowedIPs = 10.200.0.0/16, 10.154.0.0/24
PersistentKeepalive = 25
CONF
# 24 receive queues plus 25 transmit queues need a good deal more frame memory than a
# one-queue run: 4096 x 2 MB is 8 GB, which these 755 GB boxes will not miss.
sysctl -qw vm.nr_hugepages=4096 >/dev/null
systemctl stop wireguard-go 2>/dev/null || true
ip link del wg0 2>/dev/null || true
# DPDK takes the port away from the kernel, so the VLAN netdev must be registered
# (which is what makes the NIC accept the tag at all) and then removed, or the
# kernel claims the frames first. AF_XDP is the opposite: the kernel keeps the
# port and the driver, and an eBPF program redirects what we asked for, so the
# netdev must stay. Its address is removed either way, so the host does not answer
# ARP for an address the gateway is also using.
ip link add link eno2 name vlan.2049 type vlan id 2049 2>/dev/null || true
ip link set vlan.2049 up
sleep 0.2
case "$bin" in
  *-ax*|*-mx*) ip addr flush dev vlan.2049 2>/dev/null || true ;;
  *)           ip link del vlan.2049 ;;
esac
# AF_XDP binds to the kernel's netdev by name, where DPDK takes a PCI address; and
# its filters skip the VLAN tag, so it has to take the whole port. The tag also has
# to survive to the eBPF program, which means turning off the NIC's VLAN stripping:
# with it on, the tag is lifted into metadata and the gateway's classifier, which
# decides underlay from LAN by tag, would see neither.
dev=0000:c1:00.1
case "$bin" in
  # Direct verbs, like AF_XDP, binds to the kernel's netdev by name and leaves the
  # port with the kernel; unlike AF_XDP it can steer on a VLAN tag.
  *-mx*) dev=eno2
         ethtool -K eno2 rxvlan on >/dev/null 2>&1 || true
         ethtool -L eno2 combined 48 >/dev/null 2>&1 || true ;;
  *-ax*) dev=eno2; steer=promisc
         ethtool -K eno2 rxvlan off >/dev/null 2>&1 || true
         # An AF_XDP socket is bound to ONE receive queue, so we only see the
         # traffic RSS puts on the queues we opened. The card has 48 of them and
         # we open as many as the gateway has, so without this the handshake lands
         # on a queue nobody is reading and the tunnel never comes up. Shrink the
         # card to the queues we own -- and check the RSS table agrees, because it
         # can keep naming a queue that no longer exists.
         ethtool -L eno2 combined "$queues" >/dev/null 2>&1 || true
         if ethtool -x eno2 2>/dev/null | grep -oE "[0-9]+" | awk -v n="$queues" '$1>=n{f=1} END{exit !f}'; then
           echo "WARNING: the RSS table still names a queue at or above $queues" >&2
         fi ;;
  *)     ethtool -K eno2 rxvlan on >/dev/null 2>&1 || true
         ethtool -L eno2 combined 48 >/dev/null 2>&1 || true ;;
esac
case $steer in
  steer)   steerflag="-steer-vlan 2049";;
  promisc) steerflag="-promisc";;
  *) echo "steer must be steer or promisc"; exit 2;;
esac
systemctl stop wgpio 2>/dev/null || true; systemctl reset-failed wgpio 2>/dev/null || true
systemd-run --unit=wgpio --collect -p LimitMEMLOCK=infinity \
  "/usr/local/bin/$bin" -i "$dev" $steerflag -queues "$queues" -cpus "$cpus" -tun-cpu "$tuncpu" \
  -underlay-vlan 2049 -underlay-ip $MY/24 -lan-vlan 2049 -lan-ip $MYLAN/24 \
  -neighbor "$PEER=$peermac" -mtu 1420 \
  -config /etc/wgpio/wgpio0.conf -stats 1s -pprof 127.0.0.1:6060 "$@"
for i in $(seq 60); do
  [ -S /var/run/wireguard/wgpio0.sock ] && break
  systemctl is-active -q wgpio || break
  sleep 0.5
done
systemctl is-active -q wgpio || { echo "$role: wgpio did not start"; journalctl -u wgpio --no-pager -o cat | grep -vE "^EAL|^TELEMETRY|^mlx5_net" | tail -12; exit 1; }
echo "$role: $bin up, $queues queues on cpus $cpus, tun on $tuncpu, $steer"
