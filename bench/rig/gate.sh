#!/usr/bin/env bash
# Prove the tunnel path works in both directions before any load is offered:
# 5 ICMP echos to a "behind" address must come back to ash-1's wire from the far peer's MAC.
# Exit 1 (and print why) if either direction fails. Any mode (kernel/wggo/wgpio) passes it.
set -uo pipefail
. "$(dirname "$0")/env.sh"
check() { # <dst> <expected returning src MAC> <label> [payload bytes]
  local dst=$1 mac=$2 label=$3 size=${4:-56} n
  n=$(timeout 6 tcpdump -i vlan.$VLAN_LAN -nn -c 5 -l "icmp and ether src $mac and dst $dst" 2>/dev/null &
      sleep 0.5; ping -c 5 -i 0.2 -W 0.3 -s $size -I vlan.$VLAN_LAN $dst >/dev/null 2>&1; wait; ) 
  n=$(echo "$n" | grep -c "ICMP echo request")
  if [ "$n" -ge 4 ]; then echo "gate ok:   $label ($n/5 back from $mac)"; return 0; fi
  echo "gate FAIL: $label ($n/5 back from $mac)"; return 1
}
# Warm the peers' ARP for the return path first; a freshly started gateway drops the packets
# it has no next-hop MAC for yet.
ping -c 2 -i 0.2 -W 0.3 -I vlan.$VLAN_LAN 10.200.3.9 >/dev/null 2>&1; ping -c 2 -i 0.2 -W 0.3 -I vlan.$VLAN_LAN 10.200.2.9 >/dev/null 2>&1
ok=0
check 10.200.3.9 "$ASH3_MAC" "ash-1 -> ash-2 -> ash-3 -> ash-1" || ok=1
check 10.200.2.9 "$ASH2_MAC" "ash-1 -> ash-3 -> ash-2 -> ash-1" || ok=1
# A full-MTU packet (1420-byte IP) too: the largest thing the tunnel must carry.
check 10.200.3.9 "$ASH3_MAC" "ash-1 -> ash-2 -> ash-3 -> ash-1, 1420-byte" 1392 || ok=1
exit $ok
