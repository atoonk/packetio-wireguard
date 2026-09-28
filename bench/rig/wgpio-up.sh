#!/usr/bin/env bash
# Deploy the local bin/wgpio to both peers and start it: wgpio-up.sh <queues> <cpus> [extra flags]
set -euo pipefail
. "$(dirname "$0")/env.sh"
queues=${1:-1} cpus=${2:-2}; shift 2 || true
# Stop first: copying over a running binary fails with "text file busy".
for h in $ASH2 $ASH3; do $SSH root@$h "systemctl stop wgpio 2>/dev/null; true"; scp -q "$(dirname "$0")/../../bin/wgpio" root@$h:/usr/local/bin/wgpio; done
run $ASH2 wgpio-up.remote.sh ash2 "$(cat $KEYS/ash2.key)" "$(cat $KEYS/ash3.pub)" "$queues" "$cpus" "$@"
run $ASH3 wgpio-up.remote.sh ash3 "$(cat $KEYS/ash3.key)" "$(cat $KEYS/ash2.pub)" "$queues" "$cpus" "$@"
