#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/env.sh"
run $ASH2 wggo-down.remote.sh; run $ASH3 wggo-down.remote.sh
