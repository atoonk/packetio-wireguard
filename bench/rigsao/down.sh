#!/usr/bin/env bash
# Put both boxes back in their resting state.
set -euo pipefail; . "$(dirname "$0")/env.sh"
run $SAO2 down.remote.sh A "$B_IP" "$B_MAC"
run $SAO3 down.remote.sh B "$A_IP" "$A_MAC"
