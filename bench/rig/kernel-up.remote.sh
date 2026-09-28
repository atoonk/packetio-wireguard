# Runs ON a peer (via env.sh's run()). Brings up kernel WireGuard as a two-VLAN gateway.
# args: <role ash2|ash3> <privkey> <peer pubkey>
set -euo pipefail
role=$1 key=$2 peerpub=$3
NIC=eno2; VU=2131; VL=2154; PORT=51820; MTU=1420; WG=wg0
case $role in
  ash2) MY_U=10.131.0.2; PEER_U=10.131.0.3; MY_L=10.154.0.2; BEHIND_ME=10.200.2.0/24; BEHIND_PEER=10.200.3.0/24;;
  ash3) MY_U=10.131.0.3; PEER_U=10.131.0.2; MY_L=10.154.0.3; BEHIND_ME=10.200.3.0/24; BEHIND_PEER=10.200.2.0/24;;
  *) echo "bad role $role" >&2; exit 2;;
esac
LAN_GW=10.154.0.1
for v in $VU $VL; do
  ip link show vlan.$v >/dev/null 2>&1 || ip link add link $NIC name vlan.$v type vlan id $v
  ip link set vlan.$v up
done
ip addr replace $MY_U/24 dev vlan.$VU
ip addr replace $MY_L/24 dev vlan.$VL
ip link show $WG >/dev/null 2>&1 && ip link del $WG
ip link add $WG type wireguard
ip link set $WG mtu $MTU
umask 077; kf=$(mktemp); echo "$key" > "$kf"
# allowed-ips = what may arrive FROM the peer: the prefix behind it and the generator's LAN
# (its packets enter the tunnel on the far side with their 10.154.0.1 source intact).
wg set $WG private-key "$kf" listen-port $PORT \
  peer "$peerpub" endpoint $PEER_U:$PORT allowed-ips $BEHIND_PEER,10.154.0.0/24 persistent-keepalive 25
rm -f "$kf"
ip link set $WG up
# Routing: the far prefix goes into the tunnel; the prefix "behind me" is reached via ash-1 on the LAN.
ip route replace $BEHIND_PEER dev $WG
ip route replace $BEHIND_ME via $LAN_GW dev vlan.$VL
sysctl -qw net.ipv4.ip_forward=1
for i in all default $WG vlan.$VL vlan.$VU; do echo 0 > /proc/sys/net/ipv4/conf/$i/rp_filter; done
echo "$role: kernel wireguard up"; wg show $WG | sed -n 1,4p; ip -br -4 addr show vlan.$VU; ip -br -4 addr show vlan.$VL
