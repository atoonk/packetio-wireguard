#!/usr/bin/env bash
# Offer a ladder of rates through the tunnel and record what comes back, with the peers'
# CPU use sampled during each rung. One CSV row per rung. Run from ash-1.
#
#   bench/run.sh --mode kernel --size 68 --dir fwd --rates 250k,500k,1M,2M,unlimited --dur 20 --repeats 1
#
# dir fwd = ash-1 -> ash-2 (encrypt) -> ash-3 (decrypt) -> ash-1; rev = the mirror.
# The tunnel must already be up in the requested mode; run.sh only gates and measures.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); . "$here/rig/env.sh"
mode=kernel size=68 dir=fwd rates=250k,500k,1M,2M,unlimited dur=20 repeats=1 flows=64 out=""
proc=""   # process whose RSS to record on the peers (wireguard-go / wgpio); empty for kernel
while [ $# -gt 0 ]; do case $1 in
  --mode) mode=$2;; --size) size=$2;; --dir) dir=$2;; --rates) rates=$2;; --dur) dur=$2;;
  --repeats) repeats=$2;; --flows) flows=$2;; --out) out=$2;; --proc) proc=$2;;
  *) echo "unknown flag $1" >&2; exit 2;; esac; shift 2; done
[ -n "$out" ] || out="$here/results/$mode-$size-$dir-$(date +%Y%m%d-%H%M%S).csv"
case $dir in
  fwd) dst=$BEHIND_ASH3; via=$ASH2;;
  rev) dst=$BEHIND_ASH2; via=$ASH3;;
  *) echo "dir must be fwd or rev" >&2; exit 2;; esac
via_mac=$(mac_of $via)

# wireblast's XDP attach/detach bounces this box's link for ~8 s; wait for it before gating,
# and give the gate a second chance, since a failed gate voids the whole ladder.
for i in $(seq 30); do ethtool $NIC 2>/dev/null | grep -q "Link detected: yes" && break; sleep 1; done; sleep 2
"$here/rig/gate.sh" || { sleep 10; "$here/rig/gate.sh"; } || { echo "gate failed, no numbers" >&2; exit 1; }
echo "mode,size,dir,offered,tx_kpps,rx_kpps,loss_pct,ash2_busy_cores,ash2_softirq_cores,ash3_busy_cores,ash3_softirq_cores,ash2_max_core_pct,ash3_max_core_pct,ash2_rss_mb,ash3_rss_mb,ts" > "$out"
for rate in ${rates//,/ }; do for r in $(seq "$repeats"); do
  log=$(mktemp)
  # wireblast spends ~10 s attaching XDP (the link bounces) before "running"; sample the peers
  # only for the middle of the run so the startup and tail do not dilute the CPU numbers.
  ( sleep 14; run $ASH2 cpu.remote.sh $((dur-6)) ) > "$log.cpu2" &
  ( sleep 14; run $ASH3 cpu.remote.sh $((dur-6)) ) > "$log.cpu3" &
  ( sleep $((dur/2+10)); [ -n "$proc" ] && run $ASH2 rss.remote.sh "$proc" || echo rss_mb=0 ) > "$log.rss2" &
  ( sleep $((dur/2+10)); [ -n "$proc" ] && run $ASH3 rss.remote.sh "$proc" || echo rss_mb=0 ) > "$log.rss3" &
  timeout $((dur+60)) wireblast -i $NIC --vlan $VLAN_LAN --src-ip $ASH1_LAN --dst-ip $dst --flows $flows \
     --dst-mac "$via_mac" --dst-port 9000 --pps "$rate" --packet-size "$size" --duration "${dur}s" \
     --rx-mode udp-port --rx-port 9000 --no-tui -y > "$log" 2>&1 || { echo "wireblast failed:"; tail -5 "$log"; }
  wait
  # wireblast prints pps, kpps or Mpps depending on the rate; normalise to kpps. The last
  # three per-second lines are the steady state (the summary includes the ramp).
  last=$(grep -E '^\[[0-9]+:[0-9]+\]' "$log" | tail -3 | awk '{
      t=""; r="";
      for(i=1;i<=NF;i++){ u=$i; v=$(i-1); k=0;
        if(u=="pps"){k=v/1000} else if(u=="kpps"){k=v} else if(u=="Mpps"){k=v*1000} else continue;
        if(t==""){t=k} else if(r==""){r=k} }
      if(t!="") {tx+=t; rx+=r; n++} }
      END{ if(n) printf "%.2f %.2f", tx/n, rx/n; else print "0 0" }')
  txs=${last% *}; rxs=${last#* }
  loss=$(awk -v t="$txs" -v r="$rxs" 'BEGIN{ if (t>0) printf "%.2f", 100*(t-r)/t; else print "nan"}')
  c2=$(cat "$log.cpu2"); c3=$(cat "$log.cpu3")
  b2=$(sed -n 's/.*busy_cores=\([0-9.]*\).*/\1/p' <<<"$c2"); s2=$(sed -n 's/.*softirq_cores=\([0-9.]*\).*/\1/p' <<<"$c2")
  b3=$(sed -n 's/.*busy_cores=\([0-9.]*\).*/\1/p' <<<"$c3"); s3=$(sed -n 's/.*softirq_cores=\([0-9.]*\).*/\1/p' <<<"$c3")
  x2=$(sed -n 's/.*max_core_pct=\([0-9.]*\).*/\1/p' <<<"$c2"); x3=$(sed -n 's/.*max_core_pct=\([0-9.]*\).*/\1/p' <<<"$c3")
  m2=$(sed -n 's/rss_mb=//p' "$log.rss2"); m3=$(sed -n 's/rss_mb=//p' "$log.rss3")
  echo "$mode,$size,$dir,$rate,$txs,$rxs,$loss,$b2,$s2,$b3,$s3,$x2,$x3,$m2,$m3,$(date +%FT%T)" | tee -a "$out"
  rm -f "$log" "$log".*
done; done
echo "wrote $out"
