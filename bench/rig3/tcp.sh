#!/usr/bin/env bash
# Real TCP through the tunnel: iperf3 between two namespaces on sao-3 (site-a behind
# gateway A, site-b behind gateway B), with the gateways up in whatever mode is under
# test (run.sh up ... with SITES=1). What comes out, per stream count: throughput, the
# sender's retransmits and reordering detection, the receiver's out-of-order queueing,
# and every place a packet was dropped on the way (sao-3's NIC, the gateways' NICs,
# wgpio's rings). Then UDP, because iperf3's UDP receiver counts out-of-order
# datagrams directly, which TCP's counters cannot separate from loss.
#
#   SITES=1 bench/rig3/run.sh up wgpio 16 wgpio-p4-mx -rx-depth 4096 [-spray-mode flow]
#   [STREAMS="1 8 32"] [REV=1] [UDP=1] bench/rig3/tcp.sh <label> [seconds]
set -euo pipefail
source "$(dirname "$0")/env.sh"
label=${1:?label}; secs=${2:-10}
TCSV=$RESULTS/tcp.csv
mkdir -p "$RESULTS" "$LOGS"
[ -s "$TCSV" ] || echo "ts,label,test,streams,dir,gbps,retrans,ofo_queue,sack_reorder,dsack_recv,retrans_segs,drops,udp_lost,udp_pkts,udp_ooo,notes" > "$TCSV"

run $SRC sites.remote.sh up >/dev/null
S="$SSH $USER@$SRC sudo"
$S pkill -x iperf3 2>/dev/null || true
$S ip netns exec site-b iperf3 -s -D -p 5201 >/dev/null
sleep 1

# One line of counters: receiver's out-of-order queueing, sender's reordering
# detection and retransmits, and the drop counters along the path.
snap() { # <sender ns> <receiver ns>
  local snd=$1 rcv=$2
  {
    $S ip netns exec $rcv nstat -az 2>/dev/null | awk '/TcpExtTCPOFOQueue/{printf "r_%s=%s ", $1, $2}'
    $S ip netns exec $snd nstat -az 2>/dev/null | awk '/TcpExtTCPSACKReorder|TcpExtTCPDSACKRecv|TcpRetransSegs/{printf "s_%s=%s ", $1, $2}'
    $S ethtool -S eno2 | awk '/ (rx_discards_phy|rx_out_of_buffer):/{gsub(":","");printf "src_%s=%s ",$1,$2}'
    for h in a b; do
      local host=$GWA; [ $h = b ] && host=$GWB
      $SSH $USER@$host "sudo ethtool -S eno2 | awk '/ rx_discards_phy:/{printf \"${h}_nic_discards=%s \", \$2}'; sudo journalctl -u wgpio -o cat -n 20 --no-pager 2>/dev/null | grep msg=stats | tail -1 | tr ' ' '\n' | grep -E '^(tx_ring_full|lan_ring_full|fp_noroom|nic_missed|rxq_pool_empty|no_neighbor)=' | sed 's/^/${h}_wg_/' | tr '\n' ' '"
    done
  } | tr -d '\n'
  echo
}
delta() { python3 -c '
import sys
p=lambda s: {k:int(v) for k,v in (x.split("=") for x in s.split() if "=" in x)}
a,b=p(sys.argv[1]),p(sys.argv[2])
d=lambda k: b.get(k,0)-a.get(k,0)
cols=["r_TcpExtTCPOFOQueue","s_TcpExtTCPSACKReorder","s_TcpExtTCPDSACKRecv","s_TcpRetransSegs"]
drops=" ".join(f"{k}={d(k)}" for k in sorted(b) if k.startswith(("src_","a_","b_")) and d(k))
print(",".join(str(d(k)) for k in cols)+","+(drops or "none"))
' "$1" "$2"; }

one() { # <streams> <fwd|rev>
  local P=$1 dir=$2 rflag= snd=site-a rcv=site-b
  [ "$dir" = rev ] && { rflag=-R; snd=site-b; rcv=site-a; }
  local s0; s0=$(snap $snd $rcv)
  local log=$LOGS/tcp-$label-P$P-$dir-$(date -u +%H%M%S).json
  $S ip netns exec site-a iperf3 -c 10.200.3.1 -p 5201 -P "$P" -t "$secs" $rflag -J > "$log" 2>&1 || true
  local s1; s1=$(snap $snd $rcv)
  local row; row=$(python3 -c '
import json,sys
try:
    j=json.load(open(sys.argv[1])); e=j["end"]
    s=e.get("sum_sent") or e["sum"]; r=e.get("sum_received") or e["sum"]
    print("%.2f,%d" % (r["bits_per_second"]/1e9, s.get("retransmits",0)))
except Exception:
    print("0,0")
' "$log")
  local ts; ts=$(date -u +%FT%TZ)
  echo "$ts,$label,tcp,$P,$dir,$row,$(delta "$s0" "$s1"),,,," | tee -a "$TCSV" | cut -d, -f2-12
}

udp() { # <streams> <rate per stream>
  local P=$1 b=$2
  local log=$LOGS/udp-$label-P$P-$(date -u +%H%M%S).json
  $S ip netns exec site-a iperf3 -c 10.200.3.1 -p 5201 -u -P "$P" -b "$b" -l 200 -t "$secs" -J > "$log" 2>&1 || true
  local row; row=$(python3 -c '
import json,sys
try:
    j=json.load(open(sys.argv[1])); e=j["end"]
    lost=pk=ooo=0
    for st in e.get("streams",[]):
        u=st.get("udp",{}); lost+=u.get("lost_packets",0); pk+=u.get("packets",0); ooo+=u.get("out_of_order",0)
    print("%d,%d,%d" % (lost,pk,ooo))
except Exception:
    print("0,0,0")
' "$log")
  local ts; ts=$(date -u +%FT%TZ)
  echo "$ts,$label,udp,$P,fwd,,,,,,,,$row,$b/stream" | tee -a "$TCSV" | cut -d, -f2-5,13-16
}

echo "label,test,streams,dir,gbps,retrans,ofo_queue,sack_reorder,dsack_recv,retrans_segs,drops"
for P in ${STREAMS:-1 8 32}; do one $P fwd; done
[ "${REV:-1}" = 1 ] && one 8 rev
if [ "${UDP:-1}" = 1 ]; then
  echo "label,test,streams,dir,udp_lost,udp_pkts,udp_ooo,rate"
  udp 8 200M
  udp 32 100M
fi
$S pkill -x iperf3 2>/dev/null || true
