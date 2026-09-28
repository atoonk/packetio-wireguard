#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/env.sh"
run $ASH2 dpdk-unbind.remote.sh; run $ASH3 dpdk-unbind.remote.sh
