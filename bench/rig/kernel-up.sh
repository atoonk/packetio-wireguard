#!/usr/bin/env bash
# Bring up kernel WireGuard on both peers (run from ash-1).
set -euo pipefail
. "$(dirname "$0")/env.sh"
"$(dirname "$0")/keys.sh" >/dev/null
run $ASH2 kernel-up.remote.sh ash2 "$(cat $KEYS/ash2.key)" "$(cat $KEYS/ash3.pub)"
run $ASH3 kernel-up.remote.sh ash3 "$(cat $KEYS/ash3.key)" "$(cat $KEYS/ash2.pub)"
