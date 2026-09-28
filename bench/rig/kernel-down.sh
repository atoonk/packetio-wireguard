#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/env.sh"
run $ASH2 kernel-down.remote.sh; run $ASH3 kernel-down.remote.sh
