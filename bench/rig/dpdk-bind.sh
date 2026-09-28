#!/usr/bin/env bash
# Hand both peers' eno2 to DPDK (tears down the kernel WireGuard mode first).
set -euo pipefail
. "$(dirname "$0")/env.sh"
"$(dirname "$0")/kernel-down.sh" || true
run $ASH2 dpdk-bind.remote.sh; run $ASH3 dpdk-bind.remote.sh
