# Runs ON a peer: stock wireguard-go (userspace, kernel TUN + UDP socket) as the two-VLAN
# gateway, same addresses/routes/keys as the kernel mode. args: <role> <privkey> <peer pubkey>
set -euo pipefail
role=$1 key=$2 peerpub=$3
NIC=eno2; VU=2131; VL=2154; PORT=51820; MTU=1420; WG=wg0
case $role in
  ash2) MY_U=10.131.0.2; PEER_U=10.131.0.3; MY_L=10.154.0.2; BEHIND_ME=10.200.2.0/24; BEHIND_PEER=10.200.3.0/24;;
  ash3) MY_U=10.131.0.3; PEER_U=10.131.0.2; MY_L=10.154.0.3; BEHIND_ME=10.200.3.0/24; BEHIND_PEER=10.200.2.0/24;;
esac
LAN_GW=10.154.0.1
for v in $VU $VL; do
  ip link show vlan.$v >/dev/null 2>&1 || ip link add link $NIC name vlan.$v type vlan id $v
  ip link set vlan.$v up
done
ip addr replace $MY_U/24 dev vlan.$VU
ip addr replace $MY_L/24 dev vlan.$VL
ip link show $WG >/dev/null 2>&1 && ip link del $WG
systemctl stop wireguard-go 2>/dev/null || true; systemctl reset-failed wireguard-go 2>/dev/null || true
systemd-run --unit=wireguard-go --collect -E LOG_LEVEL=error /usr/local/bin/wireguard-go -f $WG
for i in $(seq 50); do [ -e /sys/class/net/$WG ] && break; sleep 0.1; done
ip link set $WG mtu $MTU
umask 077; kf=$(mktemp); echo "$key" > "$kf"
wg set $WG private-key "$kf" listen-port $PORT \
  peer "$peerpub" endpoint $PEER_U:$PORT allowed-ips $BEHIND_PEER,10.154.0.0/24 persistent-keepalive 25
rm -f "$kf"
ip link set $WG up
ip route replace $BEHIND_PEER dev $WG
ip route replace $BEHIND_ME via $LAN_GW dev vlan.$VL
sysctl -qw net.ipv4.ip_forward=1
for i in all default $WG vlan.$VL vlan.$VU; do echo 0 > /proc/sys/net/ipv4/conf/$i/rp_filter; done
echo "$role: wireguard-go up ($(wireguard-go --version 2>/dev/null | head -1))"; wg show $WG | sed -n 1,4p
