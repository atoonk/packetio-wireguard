# Runs ON a peer: start wgpio under systemd-run (survives the ssh session), pinned.
# args: <role ash2|ash3> <privkey> <peer pubkey> <queues> <cpus> [extra wgpio flags...]
set -euo pipefail
role=$1 key=$2 peerpub=$3 queues=$4 cpus=$5; shift 5
case $role in
  ash2) MY_U=10.131.0.2; PEER_U=10.131.0.3; MY_L=10.154.0.2; BEHIND_ME=10.200.2.0/24; BEHIND_PEER=10.200.3.0/24;;
  ash3) MY_U=10.131.0.3; PEER_U=10.131.0.2; MY_L=10.154.0.3; BEHIND_ME=10.200.3.0/24; BEHIND_PEER=10.200.2.0/24;;
esac
mkdir -p /etc/wgpio; umask 077
cat > /etc/wgpio/wgpio0.conf <<CONF
[Interface]
PrivateKey = $key
ListenPort = 51820
[Peer]
PublicKey = $peerpub
Endpoint = $PEER_U:51820
AllowedIPs = $BEHIND_PEER, 10.154.0.0/24
PersistentKeepalive = 25
CONF
systemctl stop wgpio 2>/dev/null || true; systemctl reset-failed wgpio 2>/dev/null || true
systemd-run --unit=wgpio --collect -p LimitMEMLOCK=infinity \
  /usr/local/bin/wgpio -i 0000:01:00.0 -queues "$queues" -cpus "$cpus" \
  -underlay-vlan 2131 -underlay-ip $MY_U/24 -lan-vlan 2154 -lan-ip $MY_L/24 \
  -route $BEHIND_ME=10.154.0.1 -config /etc/wgpio/wgpio0.conf -stats 10s -pprof 127.0.0.1:6060 "$@"
# EAL init and the link wait take several seconds; poll for the UAPI socket.
for i in $(seq 40); do [ -S /var/run/wireguard/wgpio0.sock ] && break; systemctl is-active -q wgpio || break; sleep 0.5; done
systemctl is-active -q wgpio && wg show wgpio0 | head -4 || { journalctl -u wgpio --no-pager -o cat | grep -vE "^EAL|^TELEMETRY" | tail -20; exit 1; }
