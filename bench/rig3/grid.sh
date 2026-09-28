#!/usr/bin/env bash
# The whole matrix, three repeats per point. Rates ladder up to and past each mode's
# knee, found in the exploratory runs (results-explore.csv). ~1.7 h.
set -uo pipefail
cd "$(dirname "$0")"
R() { ./run.sh point "$@" | cut -d, -f2,4,5,6,7,14,15,22; }
ladder() { # <frames...> -- <rates...>
  local frames=() rates=(); local f=frames
  for a in "$@"; do [ "$a" = -- ] && { f=rates; continue; }; eval "$f+=($a)"; done
  for fr in "${frames[@]}"; do for rep in 1 2 3; do for r in "${rates[@]}"; do R $r $fr $rep; done; done; done
}
echo "== kfwd";       ./run.sh up kfwd  | tail -1;  ladder 68 -- 5000000 10000000 15000000 20000000 25000000
echo "== l3fwd 16q";  ./run.sh up l3fwd 16 pio-l3fwd | tail -1; ladder 68 -- 40000000 60000000 80000000
echo "== kernel";     ./run.sh up kernel | tail -1; ladder 68 512 1442 -- 300000 400000 450000 500000 550000 600000
echo "== wggo";       ./run.sh up wggo   | tail -1; ladder 68 512 1442 -- 200000 300000 350000 400000 450000
echo "== wgpio-tun";  ./run.sh up wgpio-tun 8 wgpio-stock-mx -rx-depth 4096 | tail -1; ladder 68 512 1442 -- 300000 400000 450000 500000 600000
echo "== wgpio stock 8q"; ./run.sh up wgpio 8 wgpio-stock-mx -fastpath=false -rx-depth 4096 | tail -1; ladder 68 -- 1000000 1250000 1500000 1750000 2000000
echo "== wgpio p4 16q"; ./run.sh up wgpio 16 wgpio-p4-mx -rx-depth 4096 | tail -1
  ladder 68 -- 30000000 34000000 38000000 40000000 42000000
  ladder 512 -- 16000000 18000000 19500000 20500000
  ladder 1442 -- 7000000 7500000 8000000 8150000
echo "== wgpio p4 8q";  ./run.sh up wgpio 8 wgpio-p4-mx -rx-depth 4096 | tail -1;  ladder 68 -- 18000000 20000000 22000000 24000000
echo "== wgpio p4 24q"; ./run.sh up wgpio 24 wgpio-p4-mx -rx-depth 4096 | tail -1; ladder 68 -- 30000000 36000000 40000000 44000000
./run.sh down
echo "== grid done $(date -u)"
