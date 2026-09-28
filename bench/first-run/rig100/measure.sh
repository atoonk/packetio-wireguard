#!/usr/bin/env bash
# One measurement: the generator on A (or B with DIR=rev) at <pps> and <size>; sink on
# the other. Rates are steady-state, from each box's own stats lines.
#   measure.sh <pps|0> <size> <queues> <cpus> <tun-cpu> [extra flags]
set -euo pipefail; here=$(dirname "$0"); . "$here/env.sh"
pps=$1 size=$2 queues=$3 cpus=$4 tuncpu=$5; shift 5
dir=${DIR:-fwd}
case $dir in fwd) enc=$SAO2; dec=$SAO3; A_FLAGS="-gen pps=$pps,size=$size,flows=64,src=10.154.0.1,dst=10.200.3.0/24"; B_FLAGS="-sink";;
              rev) enc=$SAO3; dec=$SAO2; B_FLAGS="-gen pps=$pps,size=$size,flows=64,src=10.154.0.1,dst=10.200.2.0/24"; A_FLAGS="-sink";; esac
A_FLAGS="$A_FLAGS" B_FLAGS="$B_FLAGS" "$here/wgpio-up.sh" "$queues" "$cpus" "$tuncpu" "$@" >/dev/null
for i in $(seq 40); do ok=1; for h in $enc $dec; do $SSH $USER@$h 'sudo wg show wgpio0 latest-handshakes | awk "{exit !(\$2>0)}"' || ok=0; done; [ $ok = 1 ] && break; sleep 1; done
[ ${ok:-0} = 1 ] || { echo "no handshake"; exit 1; }
sleep 16   # two full stats intervals of steady state
e=$(run $enc rate.remote.sh gen gen_dropped fp_enc tx_ring_full nic_missed); d=$(run $dec rate.remote.sh fp_dec sink nic_missed fp_authfail fp_replay rxq_dropped)
echo "ENC $(echo $e | tr '\n' ' ')"; echo "DEC $(echo $d | tr '\n' ' ')"
gen=$(echo "$e" | sed -n 's/.*fp_enc=\([0-9]*\).*/\1/p'); dec=$(echo "$d" | sed -n 's/.*fp_dec=\([0-9]*\).*/\1/p')
python3 -c "g=$gen; d=$dec; print(f'RESULT dir={\"$dir\"} q=$queues size=$size pps=$pps encrypted={g/1e6:.2f}M/s delivered={d/1e6:.2f}M/s loss={(1-d/g)*100 if g else 0:.1f}%')"
