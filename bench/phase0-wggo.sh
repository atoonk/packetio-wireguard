#!/usr/bin/env bash
# Stock wireguard-go baseline: bring it up on both peers (kernel WireGuard down first) and run
# the same ladders as the kernel rows.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
"$here/rig/kernel-down.sh" >/dev/null || true
"$here/rig/wggo-up.sh"
for spec in "68 fwd" "68 rev" "512 fwd" "1442 fwd"; do set -- $spec
  "$here/run.sh" --mode wggo --size $1 --dir $2 --rates 100k,200k,300k,350k,400k,500k,700k,1M,2M --dur 20 --proc wireguard-go 2>&1 | grep "^wggo"
done
