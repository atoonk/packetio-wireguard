#!/usr/bin/env bash
# Diff the peers' drop counters around one wireblast run: where do packets go missing?
#   bench/rig/drops.sh <rate> <size> <fwd|rev> [dur]
set -euo pipefail
. "$(dirname "$0")/env.sh"
rate=$1 size=$2 dir=$3 dur=${4:-15}
case $dir in fwd) dst=$BEHIND_ASH3; via=$ASH2;; rev) dst=$BEHIND_ASH2; via=$ASH3;; esac
via_mac=$(mac_of $via)
snap() { for h in $ASH2 $ASH3; do run $h counters.remote.sh; done; }
b=$(snap)
wireblast -i $NIC --vlan $VLAN_LAN --src-ip $ASH1_LAN --dst-ip $dst --flows 64 --dst-mac "$via_mac" \
  --dst-port 9000 --pps "$rate" --packet-size "$size" --duration "${dur}s" --rx-mode udp-port --rx-port 9000 \
  --no-tui -y 2>&1 | grep -E "^  (tx|rx):"
a=$(snap)
paste -d'\n' <(echo "$b") <(echo "$a") | awk 'NR%2==1{split($0,B," "); next} {split($0,A," "); line=(NR==2?"ash-2:":"ash-3:");
  for(i=1;i<=length(A);i++){split(A[i],kv,"="); split(B[i],kb,"="); d=kv[2]-kb[2]; if(d!=0) line=line" "kv[1]"=+"d}; print line}'
