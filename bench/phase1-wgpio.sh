#!/usr/bin/env bash
# wgpio on the rig: tear down whatever kernel mode is up, hand the ports to DPDK, start wgpio
# with the given queues/cpus, run the ladders.   phase1-wgpio.sh <queues> <cpus> [label]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
queues=${1:-1} cpus=${2:-2} label=${3:-wgpio-q$1}
"$here/rig/wggo-down.sh" >/dev/null 2>&1 || true
"$here/rig/dpdk-bind.sh"
"$here/rig/wgpio-up.sh" "$queues" "$cpus" -tun-cpu "${TUN_CPU:-3}"
sleep 3
for spec in "68 fwd" "68 rev" "512 fwd" "1442 fwd"; do set -- $spec
  "$here/run.sh" --mode "$label" --size $1 --dir $2 --rates 250k,500k,1M,1.5M,2M,3M,4M,6M,unlimited --dur 20 --proc wgpio 2>&1 | grep "^$label"
done
