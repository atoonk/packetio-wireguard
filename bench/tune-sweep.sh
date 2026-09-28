#!/usr/bin/env bash
# Try each kernel tune on its own at the rungs where the default drops (68-byte fwd,
# 350k and 500k offered), then reset. Prints one CSV row per rung per tune.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=$here/results/kernel-tune-sweep-$(date +%Y%m%d-%H%M%S).csv
for tune in irq rings rps coalesce; do
  "$here/rig/kernel-tune.sh" reset >/dev/null
  "$here/rig/kernel-tune.sh" $tune | sed "s/^/  [$tune] /"
  "$here/run.sh" --mode "kernel+$tune" --size 68 --dir fwd --rates 350k,500k --dur 15 --out "$out.$tune" | grep "^kernel"
done
"$here/rig/kernel-tune.sh" reset >/dev/null
cat "$out".* > "$out"; rm -f "$out".*
echo "wrote $out"
