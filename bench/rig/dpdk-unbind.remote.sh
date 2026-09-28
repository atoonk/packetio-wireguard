# Runs ON a peer: give eno2 back to the kernel and restore vlan.2131 with its usual address.
set -euo pipefail
PCI=0000:01:00.0; NIC=eno2
pkill -x wgpio 2>/dev/null || true; sleep 0.5
dpdk-devbind.py --bind=ixgbe $PCI
for i in $(seq 50); do [ -e /sys/class/net/$NIC ] && break; sleep 0.2; done
ip link set $NIC up
ip link show vlan.2131 >/dev/null 2>&1 || ip link add link $NIC name vlan.2131 type vlan id 2131
ip link set vlan.2131 up
case $(hostname) in *ash-2) ip addr replace 192.168.0.2/24 dev vlan.2131;; *ash-3) ip addr replace 192.168.0.3/24 dev vlan.2131;; esac
ethtool $NIC | grep -E "Speed|Link detected"
