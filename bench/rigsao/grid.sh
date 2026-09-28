#!/usr/bin/env bash
# The whole measurement grid, in the order the write-up tells it. Each step can be run
# on its own so a long batch can be resumed:
#
#   grid.sh 1     kernel WireGuard, defaults
#   grid.sh 2     kernel WireGuard with RPS
#   grid.sh 3     stock wireguard-go on a kernel TUN, and again with RPS
#   grid.sh 4..8  wgpio: unmodified wireguard-go, then patches 0001..0004 one at a time
#   grid.sh 9     the rate ladder, the larger frames and the reverse direction, on p4
#   grid.sh all
#
# Every point is measured three times; the write-up takes the median. REPEATS=1 makes
# a quick pass for checking the harness.
set -euo pipefail
here=$(dirname "$0"); . "$here/env.sh"
REPEATS=${REPEATS:-3}
SECS=${SECS:-20}
QUEUES=${QUEUES:-"1 4 8 12 16 20 24"}
step=${1:?grid.sh 1|2|3|3b|4|5|6|7|8|9|all}

point() { # <args to run.sh...>
  for r in $(seq "$REPEATS"); do
    echo "--- repeat $r/$REPEATS: $*"
    "$here/run.sh" "$@" --repeat "$r" --secs "$SECS" 2>&1 | tail -1 || echo "POINT FAILED: $*"
  done
}

# The baselines are measured as a rate ladder, not as a flood. Offering everything the
# sender can produce does not find a tunnel's capacity: wireguard-go carried 231 kpps
# when offered 2.2 Mpps and 1.2 kpps when offered 4.9 Mpps, because a sender that
# monopolises the machine starves the userspace reader. The ladder finds the knee, and
# the peak delivered is the number worth quoting. The sender thread count is fixed at
# 8; it never changed a delivered figure in the earlier grid.
# The rungs bracket the knee closely, because the knee is the result. Kernel WireGuard
# saturates one CPU with its per-peer serial transmit worker somewhere around 700 kpps
# and falls away after, so 600/700/800/900 are the rungs that matter and the rest are
# there to show the shape. 1.9 M is the top: udpblast itself tops out near there.
RATES_68=${RATES_68:-"200000 400000 600000 700000 800000 900000 1200000 1900000"}
RATES_BIG=${RATES_BIG:-"400000 800000 1200000"}
REPEATS_BIG=${REPEATS_BIG:-2}
kernel_grid() { # <kernel|kernel-rps|wggo|wggo-rps>
  local mode=$1
  for r in $RATES_68;  do point "$mode" --frame 68   --threads 8 --pps "$r"; done
  local keep=$REPEATS
  REPEATS=$REPEATS_BIG
  for f in 512 1442; do
    for r in $RATES_BIG; do point "$mode" --frame "$f" --threads 8 --pps "$r"; done
  done
  REPEATS=$keep
}

sweep() { # <variant>
  for q in $QUEUES; do point wgpio --variant "$1" --queues "$q" --frame 68; done
}

case $step in
  1) kernel_grid kernel;;
  2) kernel_grid kernel-rps;;
  3) kernel_grid wggo;;
  3b|10) kernel_grid wggo-rps;;
  4) sweep stock;;
  5) sweep p1;;
  6) sweep p2;;
  7) sweep p3;;
  8) sweep p4;;
  9) best=${BEST_QUEUES:?set BEST_QUEUES to the queue count step 8 peaked at}
     # The ladder starts well below the sweep's unlimited rate on purpose. The
     # baselines turned out to have been measured in collapse rather than at
     # capacity, and the same question has to be asked of wgpio: if it delivers more
     # when offered less, the sweep understated it too.
     for pps in 5000000 10000000 20000000 30000000 36000000 40000000 44000000; do
       point wgpio --variant p4 --queues "$best" --frame 68 --pps "$pps"
     done
     for f in 512 1442; do point wgpio --variant p4 --queues "$best" --frame "$f"; done
     point wgpio --variant p4 --queues "$best" --frame 68 --dir rev
     ;;
  all) for s in 1 2 3 3b 4 5 6 7 8; do "$0" "$s"; done;;
  *) echo "grid.sh 1|2|3|3b|4|5|6|7|8|9|all"; exit 2;;
esac
"$here/down.sh" >/dev/null
echo "step $step done"
