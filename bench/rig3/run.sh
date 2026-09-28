#!/usr/bin/env bash
# The three-box wire-to-wire benchmark. See env.sh for the picture.
#
#   run.sh up   <mode> [queues] [binary] [extra wgpio flags...]   bring up both gateways
#   run.sh point <pps> [frame] [repeat] [note]                     measure one rate
#   run.sh down                                                    tear both gateways down
#
# A point: sao-3 starts pio-drop (so the returning traffic is taken in userspace, on
# cores the generator does not use -- left to the kernel it lands on the generator's
# cores and caps it), snapshots all three boxes, sends <pps> of <frame>-byte plaintext
# for $SECS seconds, snapshots again. Offered and delivered are both sao-3's own NIC
# counters: one machine, one clock, and the gateways never grade their own work.
set -euo pipefail
source "$(dirname "$0")/env.sh"
SECS=${SECS:-10}
mkdir -p "$RESULTS" "$LOGS"
STATE=$RESULTS/.current   # mode, queues, binary of what is up now

cmd=${1:?up|point|down}; shift
case $cmd in
up)
  mode=$1 queues=${2:-8} bin=${3:-none}; shift $(( $# < 3 ? $# : 3 ))
  cpus="1-$queues"
  for h in $GWA $GWB; do
    $SSH $USER@$h "sudo install -m755 /tmp/rig3-bin/* /usr/local/bin/ 2>/dev/null; true"
  done
  # SITES=1: the gateways route their site to the namespaces on sao-3 (sites.remote.sh)
  # instead of the pio-drop sink, for the TCP tests.
  nhA=- nhB=-; [ "${SITES:-0}" = 1 ] && { nhA=$NS_A_LAN; nhB=$NS_B_LAN; }
  run $GWB gw.remote.sh $mode B "$(cat $KEYS/saoB.key)" "$(cat $KEYS/saoA.pub)" $A_MAC $SRC_MAC $queues $cpus $bin $nhB "$@"
  run $GWA gw.remote.sh $mode A "$(cat $KEYS/saoA.key)" "$(cat $KEYS/saoB.pub)" $B_MAC $SRC_MAC $queues $cpus $bin $nhA "$@"
  echo "$mode $queues $bin $*" > $STATE
  # Handshake, and prove the loop end to end before anything is measured: a second of
  # light traffic must come back.
  sleep 2
  if [ "${SITES:-0}" = 1 ]; then
    run $SRC sites.remote.sh up >/dev/null
    if $SSH $USER@$SRC "sudo ip netns exec site-a ping -c3 -i0.2 -W1 -s 1392 -M do 10.200.3.1 >/dev/null"; then
      echo "gate ok: site-a pings site-b through the tunnel at full MTU"
    else
      echo "GATE FAIL: no ping site-a -> site-b"; exit 1
    fi
  else
  SECS=3 "$0" point 20000 68 0 warmup >/dev/null || true
  tail -1 $CSV | awk -F, '{ if ($14+0 < 1000) { print "GATE FAIL: warmup delivered " $14; exit 1 } else print "gate ok: warmup delivered " $14 " pps" }'
  fi
  ;;
down)
  for h in $GWA $GWB; do run $h gw.remote.sh down A x x x x 1 1 x -; done
  rm -f $STATE
  ;;
point)
  pps=$1 frame=${2:-68} repeat=${3:-1} note=${4:-}
  read -r mode queues bin extra < $STATE || { echo "nothing is up"; exit 1; }
  [ -n "$extra" ] && note="$note${note:+ }[$extra]"
  [ -s "$CSV" ] || echo "ts,mode,bin,queues,frame,pps_req,repeat,secs,offered,a_rx,a_tx,b_rx,b_tx,delivered,loss_pct,a_discard,b_discard,src_discard,busy_a,busy_b,tun_txdrop_a,limiter,note" > $CSV
  ts=$(date -u +%FT%TZ)
  log=$LOGS/$mode-q$queues-f$frame-p$pps-r$repeat-$(date -u +%H%M%S).log
  # pio-drop: 8 queues on cpus 13-20; pio-blast: 8 queues on cpus 1-8. Disjoint.
  $SSH $USER@$SRC "sudo timeout $((SECS+15)) pio-drop -i eno2 -vlan $VLAN -queues 8 -cpus 13-20 -duration $((SECS+6))s -report $((SECS+6))s" > $log.drop 2>&1 &
  dpid=$!
  sleep 2
  snap() { # one line per box, tagged with its role
    { echo "role=src $(run $SRC snap.remote.sh)" & echo "role=a $(run $GWA snap.remote.sh)" & echo "role=b $(run $GWB snap.remote.sh)" & wait; }
  }
  s0=$(snap)
  # A batch is about a millisecond of traffic per queue (256 at most): a paced source
  # that sends its second in a few large bursts measures the gateway's queues, not
  # its throughput. Same rule as bench/udpblast.
  batch=$(( pps / 8 / 1000 )); [ $batch -lt 1 ] && batch=1; [ $batch -gt ${BATCH:-256} ] && batch=${BATCH:-256}
  $SSH $USER@$SRC "sudo pio-blast -i eno2 -dst-mac $A_MAC -vlan $VLAN -size $frame -queues 8 -cpus 1-8 -flows ${FLOWS:-64} -batch $batch \
      -src-ip 10.200.2.1 -dst-ip 10.200.3.1 -pps $pps -duration ${SECS}s -report ${SECS}s" > $log.blast 2>&1
  sleep 1   # let the pipeline drain into the counters
  s1=$(snap)
  wait $dpid 2>/dev/null || true
  case $mode in wgpio*) $SSH $USER@$GWA "journalctl -u wgpio --no-pager -o cat | grep stats | tail -1" > $log.wgpioA 2>&1 || true
                        $SSH $USER@$GWB "journalctl -u wgpio --no-pager -o cat | grep stats | tail -1" > $log.wgpioB 2>&1 || true;; esac
  { echo "s0:"; echo "$s0"; echo "s1:"; echo "$s1"; } > $log
  python3 - "$ts" "$mode" "$bin" "$queues" "$frame" "$pps" "$repeat" "$SECS" "$note" "$s0" "$s1" <<'PY2' | tee -a $CSV
import sys
ts, mode, binn, queues, frame, pps, repeat, secs, note, s0, s1 = sys.argv[1:]
def parse(text):
    out = {}
    for line in text.strip().splitlines():
        kv = dict(x.split('=', 1) for x in line.split())
        out[kv.pop('role')] = kv
    return out
a0, a1 = parse(s0), parse(s1)
def d(role, k):
    return float(a1[role].get(k, 0)) - float(a0[role].get(k, 0))
# Every rate is over the traffic duration: the generator runs SECS seconds and the
# drain second after it only lets in-flight packets reach the counters.
T = float(secs)
rate = lambda role, k: d(role, k) / T
off = rate('src', 'tx_packets_phy')
a_rx, a_tx = rate('a', 'rx_packets_phy'), rate('a', 'tx_packets_phy')
b_rx, b_tx = rate('b', 'rx_packets_phy'), rate('b', 'tx_packets_phy')
dlv = rate('src', 'rx_packets_phy') - rate('src', 'rx_discards_phy')
busy = lambda r: d(r, 'cpu_busy') / d(r, 'cpu_all') * 48 if d(r, 'cpu_all') else 0
loss = (1 - dlv / off) * 100 if off > 0 else 0
lim = 'none'
if off < 0.98 * float(pps): lim = 'source'
elif a_tx < 0.99 * a_rx: lim = 'gateway-A'
elif b_rx < 0.99 * a_tx: lim = 'wire'
elif b_tx < 0.99 * b_rx: lim = 'gateway-B'
elif dlv < 0.99 * b_tx: lim = 'sink'
print(','.join(str(x) for x in [ts, mode, binn, queues, frame, pps, repeat, secs,
    round(off), round(a_rx), round(a_tx), round(b_rx), round(b_tx), round(dlv), '%.2f' % loss,
    round(rate('a', 'rx_discards_phy')), round(rate('b', 'rx_discards_phy')), round(rate('src', 'rx_discards_phy')),
    '%.1f' % busy('a'), '%.1f' % busy('b'), round(rate('a', 'tun_txdrop')), lim, '"%s"' % note]))
PY2
  true
  ;;
esac
