#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/env.sh"
run $ASH2 wgpio-down.remote.sh; run $ASH3 wgpio-down.remote.sh
