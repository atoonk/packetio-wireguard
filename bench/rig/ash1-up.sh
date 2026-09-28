#!/usr/bin/env bash
# ash-1 (generator/sink): a kernel VLAN interface on the LAN VLAN so the peers can ARP
# for 10.154.0.1 and so AF_XDP receive on the tagged VLAN is registered with the kernel.
set -euo pipefail
. "$(dirname "$0")/env.sh"
ip link show vlan.$VLAN_LAN >/dev/null 2>&1 || ip link add link $NIC name vlan.$VLAN_LAN type vlan id $VLAN_LAN
ip addr replace $ASH1_LAN/24 dev vlan.$VLAN_LAN
ip link set vlan.$VLAN_LAN up
sysctl -qw net.ipv4.ip_forward=0
ip -br -4 addr show vlan.$VLAN_LAN
# Routes to the "behind" prefixes via each peer. A ping to 10.200.3.x goes ash-2 -> tunnel ->
# ash-3 -> back to us (nobody answers; gate.sh proves it came back by watching the wire).
ip route replace $BEHIND_ASH3 via $ASH2_LAN dev vlan.$VLAN_LAN
ip route replace $BEHIND_ASH2 via $ASH3_LAN dev vlan.$VLAN_LAN
