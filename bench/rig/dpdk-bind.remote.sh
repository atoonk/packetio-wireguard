# Runs ON a peer: hand eno2 to DPDK. The kernel VLAN interfaces on it go away with it.
set -euo pipefail
PCI=0000:01:00.0; NIC=eno2
sysctl -qw vm.nr_hugepages=128
modprobe vfio-pci
if [ -e /sys/class/net/$NIC ]; then ip link set $NIC down; fi
dpdk-devbind.py --bind=vfio-pci $PCI
dpdk-devbind.py --status-dev net | grep -A1 "DPDK-compatible" | tail -1
grep HugePages_Free /proc/meminfo
