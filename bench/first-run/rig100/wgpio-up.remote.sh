# Runs ON a 100G box as root. args: <role A|B> <privkey> <peer pubkey> <queues> <cpus> <tun-cpu> [extra wgpio flags...]
set -euo pipefail
role=$1 key=$2 peerpub=$3 queues=$4 cpus=$5 tuncpu=$6 dev=$7; shift 7
case $role in A) MY=10.49.0.2; PEER=10.49.0.3;; B) MY=10.49.0.3; PEER=10.49.0.2;; esac
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
sysctl -qw vm.nr_hugepages=256
ip link add link eno2 name vlan.2049 type vlan id 2049 2>/dev/null || true; ip link set vlan.2049 up   # registers the VLAN with the NIC; the kernel must not have an address on it
systemctl stop wgpio 2>/dev/null || true; systemctl reset-failed wgpio 2>/dev/null || true
systemd-run --unit=wgpio --collect -p LimitMEMLOCK=infinity \
  /usr/local/bin/wgpio -i "$dev" -steer-vlan 2049 -queues "$queues" -cpus "$cpus" -tun-cpu "$tuncpu" \
  -underlay-vlan 2049 -underlay-ip $MY/24 -lan-vlan 2049 -lan-ip 10.154.0.$([ $role = A ] && echo 2 || echo 3)/24 \
  -config /etc/wgpio/wgpio0.conf -stats 5s -pprof 127.0.0.1:6060 "$@"
for i in $(seq 40); do [ -S /var/run/wireguard/wgpio0.sock ] && break; systemctl is-active -q wgpio || break; sleep 0.5; done
systemctl is-active -q wgpio && wg show wgpio0 | sed -n 1p || { journalctl -u wgpio --no-pager -o cat | grep -vE "^EAL|^TELEMETRY" | tail -8; exit 1; }
