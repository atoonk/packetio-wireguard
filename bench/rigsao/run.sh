#!/usr/bin/env bash
# One measurement point on the São Paulo pair, written to
# bench/results/redo-100g/results.csv with its own log beside it.
#
#   run.sh kernel      --frame 68 --threads 8 [--secs 20] [--repeat 1]
#   run.sh kernel-rps  --frame 68 --threads 8
#   run.sh wggo        --frame 68 --threads 8
#   run.sh wgpio       --variant stock|p1|p2|p3|p4 --queues 8
#                      [--frame 68] [--pps 0] [--spray 64] [--dir fwd|rev] [--secs 20]
#
# Roles: A is sao-2, B is sao-3. With --dir fwd (the default) A encrypts and B
# decrypts; --dir rev swaps them. Every row records which.
#
# The point is gated before it is measured and aborted if the gate fails, and the
# offered load is recorded next to the delivered one so the two can be reconciled.
# Nothing here reports a number it did not see both ends of.
set -euo pipefail
. "$(dirname "$0")/env.sh"

mode=${1:?run.sh kernel|kernel-rps|wggo|wggo-rps|wgpio ...}; shift
variant=- queues=1 frame=68 threads=8 pps=0 spray=64 dir=fwd secs=20 repeat=1 notes= profile=0
while [ $# -gt 0 ]; do
  case $1 in
    --variant) variant=$2; shift 2;;
    --queues)  queues=$2; shift 2;;
    --frame)   frame=$2; shift 2;;
    --threads) threads=$2; shift 2;;
    --pps)     pps=$2; shift 2;;
    --spray)   spray=$2; shift 2;;
    --dir)     dir=$2; shift 2;;
    --secs)    secs=$2; shift 2;;
    --repeat)  repeat=$2; shift 2;;
    --notes)   notes=$2; shift 2;;
    --profile) profile=1; shift;;
    *) echo "unknown option $1"; exit 2;;
  esac
done

case $dir in
  fwd) ENC=$SAO2; DEC=$SAO3; enc_role=A; dec_role=B;;
  rev) ENC=$SAO3; DEC=$SAO2; enc_role=B; dec_role=A;;
  *) echo "--dir fwd|rev"; exit 2;;
esac
export ENC DEC

# The plaintext packet inside a frame of $frame bytes: the frame carries a VLAN tag
# (18-byte link header) and the 4-byte FCS, and udpblast is told the UDP payload.
payload=$(( frame - 4 - 18 - 20 - 8 ))
[ "$payload" -ge 0 ] || { echo "--frame $frame is too small"; exit 2; }

# N queues take cpus 2..N+1 and the TUN reader takes N+2, leaving 0 and 1 for the
# operating system. The boxes have 24 physical cores (0..23); 24..47 are their SMT
# siblings, so a sweep past 22 queues starts sharing cores and the row says so.
cpus="2-$(( queues + 1 ))"
tuncpu=$(( queues + 2 ))
if [ "$mode" != wgpio ]; then
  # A kernel baseline has no queues of ours, no pinning and no spraying: leaving the
  # columns blank keeps a reader from comparing a wgpio row's queue count with one
  # that never had any.
  queues=; cpus=; tuncpu=; spray=
else
  threads=   # wgpio has no udpblast threads; the generator runs on the receive cores
fi
if [ "$mode" = wgpio ] && [ $(( queues + 2 )) -ge 24 ]; then
  notes="${notes:+$notes; }packet cores run past core 23 onto SMT siblings"
fi

mkdir -p "$RESULTS" "$LOGS"
[ -s "$CSV" ] || echo "ts,mode,variant,dir,queues,cpus,tuncpu,spray,frame,threads,pps,repeat,offered_pps,encrypted_pps,delivered_pps,loss_pct,offered_loss_pct,txdrop_a,busy_a,busy_b,nic_missed_b,limiter,fork_rev,gate,notes" > "$CSV"

ts=$(date -u +%FT%TZ)
tag="$mode${variant:+-$variant}-${dir}-q${queues}-f${frame}-t${threads}-r${repeat}-$(date -u +%H%M%S)"
log="$LOGS/$tag.log"
fork_rev=-
if [ "$mode" = wgpio ] && [ -f "$RESULTS/ladder.txt" ]; then
  fork_rev=$(awk -v b="wgpio-$variant" '$1==b{print $2}' "$RESULTS/ladder.txt" | sed 's/^fork=//')
fi

{
  echo "=== $tag"
  echo "encrypting: $(name_of $ENC) (role $enc_role)   decrypting: $(name_of $DEC) (role $dec_role)"
  echo "frame=$frame payload=$payload queues=$queues cpus=$cpus tun-cpu=$tuncpu secs=$secs"
} | tee "$log"

# ---- bring the rig up -------------------------------------------------------------
case $mode in
kernel|kernel-rps|wggo|wggo-rps)
  km=kernel; rps=0
  case $mode in
    kernel-rps) rps=1;;
    wggo)       km=wggo;;
    wggo-rps)   km=wggo; rps=1;;
  esac
  run $SAO2 kernel-up.remote.sh A "$(cat "$KEYS/saoA.key")" "$(cat "$KEYS/saoB.pub")" $km "$B_MAC" $rps | tee -a "$log"
  run $SAO3 kernel-up.remote.sh B "$(cat "$KEYS/saoB.key")" "$(cat "$KEYS/saoA.pub")" $km "$A_MAC" $rps | tee -a "$log"
  gate_mode=$km
  ;;
wgpio)
  [ "$variant" = - ] && { echo "wgpio needs --variant"; exit 2; }
  bin="wgpio-$variant"
  fp="-fastpath=true"
  case "$variant" in *stock*) fp="-fastpath=false";; esac
  enc_flags="$fp -spray $spray -gen pps=$pps,size=$frame,flows=64,src=10.154.0.1,dst=$([ $enc_role = A ] && echo $B_BEHIND || echo $A_BEHIND)/24"
  dec_flags="$fp -spray $spray -sink"
  eargs=(); dargs=()
  # shellcheck disable=SC2206
  eargs=($enc_flags); dargs=($dec_flags)
  run $DEC wgpio-up.remote.sh $dec_role "$bin" "$(cat "$KEYS/sao$dec_role.key")" "$(cat "$KEYS/sao$([ $dec_role = A ] && echo B || echo A).pub")" \
      "$([ $dec_role = A ] && echo $B_MAC || echo $A_MAC)" "$queues" "$cpus" "$tuncpu" "$STEER" "${dargs[@]}" | tee -a "$log"
  run $ENC wgpio-up.remote.sh $enc_role "$bin" "$(cat "$KEYS/sao$enc_role.key")" "$(cat "$KEYS/sao$([ $enc_role = A ] && echo B || echo A).pub")" \
      "$([ $enc_role = A ] && echo $B_MAC || echo $A_MAC)" "$queues" "$cpus" "$tuncpu" "$STEER" "${eargs[@]}" | tee -a "$log"
  gate_mode=wgpio
  ;;
*) echo "run.sh kernel|kernel-rps|wggo|wggo-rps|wgpio ..."; exit 2;;
esac

# ---- the gate ---------------------------------------------------------------------
gate=pass
if ! "$(dirname "$0")/gate.sh" "$gate_mode" 2>&1 | tee -a "$log" | grep -q "^gate ok"; then
  gate=FAIL
  echo "$ts,$mode,$variant,$dir,$queues,$cpus,$tuncpu,$spray,$frame,$threads,$pps,$repeat,,,,,,,,,,,$fork_rev,FAIL,\"gate failed; point aborted\"" >> "$CSV"
  echo "ABORTED: the gate failed, nothing measured" | tee -a "$log"
  exit 1
fi

# ---- the window -------------------------------------------------------------------
a0=$(run $SAO2 counters.remote.sh); b0=$(run $SAO3 counters.remote.sh)
offered=
if [ "$mode" = wgpio ]; then
  sleep "$secs"
else
  # -pps 0 means "as fast as the socket path allows", which for these baselines is
  # twenty times what the tunnel carries and measures collapse rather than capacity.
  # The grid ladders the rate instead; see bench/udpblast.
  echo "generator: udpblast -threads $threads -pps $pps -duration ${secs}s -size $payload" >> "$log"
  offered=$($SSH $USER@$ENC "sudo udpblast -threads $threads -pps $pps -duration ${secs}s -size $payload -dst $([ $enc_role = A ] && echo $B_BEHIND || echo $A_BEHIND) -flows 64 -port 9000" | sed 's/.*pps=//')
fi
a1=$(run $SAO2 counters.remote.sh); b1=$(run $SAO3 counters.remote.sh)

# Profiles are taken while the point is still at its ceiling, from the decrypting peer
# -- the side the patches are about -- and from the encrypting one, which is where the
# nonce reservation and the timer work live.
if [ "$profile" = 1 ] && [ "$mode" = wgpio ]; then
  pdir="$RESULTS/profiles"; mkdir -p "$pdir"
  for side in dec enc; do
    h=$([ $side = dec ] && echo $DEC || echo $ENC)
    lbl="$variant-${queues}q-f$frame-$side"
    run $h profile.remote.sh "$lbl" 20 >> "$log" 2>&1 || { echo "profile on $(name_of $h) failed" | tee -a "$log"; continue; }
    for k in cpu mutex block; do
      scp -q $USER@$h:/tmp/"$lbl-$k.pprof" "$pdir/" 2>/dev/null || true
      scp -q $USER@$h:/tmp/"$lbl-$k.txt"   "$pdir/" 2>/dev/null || true
    done
    echo "profiles: $pdir/$lbl-{cpu,mutex,block}.pprof" | tee -a "$log"
  done
fi
{ echo "A before: $a0"; echo "A after:  $a1"; echo "B before: $b0"; echo "B after:  $b1"; } >> "$log"

row=$(python3 - "$mode" "$dir" "$offered" <<PY
import sys
mode, dir_, offered = sys.argv[1], sys.argv[2], sys.argv[3]
def kv(s):
    d = {}
    for tok in s.split():
        if '=' in tok:
            k, v = tok.split('=', 1)
            try: d[k] = float(v)
            except ValueError: pass
    return d
A0, A1 = kv("""$a0"""), kv("""$a1""")
B0, B1 = kv("""$b0"""), kv("""$b1""")
enc0, enc1, dec0, dec1 = (A0, A1, B0, B1) if dir_ == 'fwd' else (B0, B1, A0, A1)
def d(a, b, k): return b.get(k, 0) - a.get(k, 0)
el_a = d(A0, A1, 'now') or 1.0
el_b = d(B0, B1, 'now') or 1.0
# The window the counters bracket includes the ssh round trips that read them. wgpio's
# generator runs for all of it, so its rate is the delta over the window. udpblast runs
# for exactly secs of it and nothing flows either side, so dividing a kernel delta by
# the window understates it by the ratio of the two -- about 21% here, which is what
# made kernel WireGuard look like 0.5 Mpps when it carries 0.69.
if mode == 'wgpio':
    # wgpio's counters are timestamped by wgpio, so divide by its clock, not ours.
    el, eld = d(enc0, enc1, 'wgts'), d(dec0, dec1, 'wgts')
    if el <= 0 or eld <= 0:
        raise SystemExit('wgts missing or not advancing: cannot compute a rate')
else:
    el = eld = float($secs)
hz = A1.get('hz', 100)
busy_a = d(A0, A1, 'busy') / hz / el_a
busy_b = d(B0, B1, 'busy') / hz / el_b
if mode == 'wgpio':
    off = d(enc0, enc1, 'gen') / el
    encd = (d(enc0, enc1, 'fp_enc') + d(enc0, enc1, 'tx_tunnel_slow')) / el
    dlv = d(dec0, dec1, 'sink') / eld
    missed = d(dec0, dec1, 'nic_missed')
else:
    off = float(offered) if offered else 0.0
    encd = d(enc0, enc1, 'wg0_tx') / el
    dlv = d(dec0, dec1, 'wg0_rx') / eld
    missed = d(dec0, dec1, 'rx_out_of_buffer') + d(dec0, dec1, 'rx_steer_missed_packets')
loss = (1 - dlv / encd) * 100 if encd > 0 else 0.0
# Loss on the wire is only half the story. A row where the sending box threw away
# half the offered load before encrypting it used to print "0.00% loss", because
# delivered was compared against what was encrypted rather than against what was
# offered. wg0_txdrop is the kernel's own count of that: WireGuard trims a peer's
# staged queue at 128 packets and counts the rest as tx_dropped.
offloss = (1 - encd / off) * 100 if off > 0 else 0.0
txdrop = d(enc0, enc1, 'wg0_txdrop')
# Name what stopped this point, from a counter rather than a guess.
if txdrop > 0.01 * off * el:
    limiter = 'tunnel-staged-queue'
elif missed > 0.01 * dlv * eld:
    limiter = 'nic'
elif offloss > 5:
    limiter = 'sender'
elif loss > 5:
    limiter = 'receiver'
else:
    limiter = 'none-offered-load'
print("%.0f,%.0f,%.0f,%.2f,%.2f,%.0f,%.2f,%.2f,%.0f,%s" % (off, encd, dlv, loss, offloss, txdrop, busy_a, busy_b, missed, limiter))
PY
)
IFS=, read -r off encd dlv loss offloss txdrop ba bb missed limiter <<< "$row"
echo "$ts,$mode,$variant,$dir,$queues,$cpus,$tuncpu,$spray,$frame,$threads,$pps,$repeat,$off,$encd,$dlv,$loss,$offloss,$txdrop,$ba,$bb,$missed,$limiter,$fork_rev,$gate,\"$notes\"" >> "$CSV"
printf 'RESULT %s %s dir=%s q=%s frame=%s offered=%.2fM encrypted=%.2fM delivered=%.2fM loss=%s%% offloss=%s%% txdrop=%s limiter=%s busy A=%s B=%s missed_b=%s\n' \
  "$mode" "$variant" "$dir" "$queues" "$frame" \
  "$(python3 -c "print($off/1e6)")" "$(python3 -c "print($encd/1e6)")" "$(python3 -c "print($dlv/1e6)")" \
  "$loss" "$offloss" "$txdrop" "$limiter" "$ba" "$bb" "$missed" | tee -a "$log"
