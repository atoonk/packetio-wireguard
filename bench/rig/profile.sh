#!/usr/bin/env bash
# Pull CPU, mutex and block profiles from a peer's wgpio/wireguard-go pprof endpoint while a
# run is in progress, and print the top of each.   profile.sh <ash2|ash3> [seconds]
set -euo pipefail
. "$(dirname "$0")/env.sh"
case $1 in ash2) h=$ASH2;; ash3) h=$ASH3;; *) echo "ash2 or ash3" >&2; exit 2;; esac
secs=${2:-15}
out=$(dirname "$0")/../results/profiles/$1-$(date +%Y%m%d-%H%M%S); mkdir -p "$out"
$SSH root@$h "curl -s -o /tmp/cpu.pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=$secs; \
  curl -s -o /tmp/mutex.pprof http://127.0.0.1:6060/debug/pprof/mutex; \
  curl -s -o /tmp/block.pprof http://127.0.0.1:6060/debug/pprof/block; \
  curl -s -o /tmp/heap.pprof http://127.0.0.1:6060/debug/pprof/heap"
for p in cpu mutex block heap; do scp -q root@$h:/tmp/$p.pprof "$out/$p.pprof"; done
scp -q root@$h:/usr/local/bin/wgpio "$out/wgpio" 2>/dev/null || true
bin="$out/wgpio"; [ -s "$bin" ] || bin=""
echo "== cpu (top 25)"; go tool pprof -top -nodecount=25 $bin "$out/cpu.pprof" 2>/dev/null | sed -n 1,32p
echo "== mutex (top 10)"; go tool pprof -top -nodecount=10 $bin "$out/mutex.pprof" 2>/dev/null | sed -n 4,16p
echo "saved in $out"
