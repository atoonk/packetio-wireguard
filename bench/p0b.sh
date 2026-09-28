#!/usr/bin/env bash
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
for spec in "512 fwd" "1442 fwd"; do set -- $spec
  "$here/run.sh" --mode kernel --size $1 --dir $2 --rates 100k,200k,300k,350k,400k,500k,1M,2M --dur 20 2>&1 | grep "^kernel"
done
"$here/tune-sweep.sh" 2>&1 | grep -E "^kernel|^\s+\[|wrote"
