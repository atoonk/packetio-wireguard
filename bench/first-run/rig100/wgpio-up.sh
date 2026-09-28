#!/usr/bin/env bash
# wgpio-up.sh <queues> <cpus> <tun-cpu> [extra flags common to both]  -- plus A_FLAGS / B_FLAGS env for per-role flags
set -euo pipefail; . "$(dirname "$0")/env.sh"; "$(dirname "$0")/keys.sh"
queues=$1 cpus=$2 tuncpu=$3; shift 3
for h in $SAO2 $SAO3; do $SSH $USER@$h "sudo systemctl stop wgpio 2>/dev/null; true"; scp -q "$(dirname "$0")/../../bin/$BIN" $USER@$h:/tmp/wgpio; $SSH $USER@$h "sudo install -m 755 /tmp/wgpio /usr/local/bin/wgpio"; done
run $SAO2 wgpio-up.remote.sh A "$(cat $KEYS/saoA.key)" "$(cat $KEYS/saoB.pub)" "$queues" "$cpus" "$tuncpu" "$DEV" "$@" ${A_FLAGS:-}
run $SAO3 wgpio-up.remote.sh B "$(cat $KEYS/saoB.key)" "$(cat $KEYS/saoA.pub)" "$queues" "$cpus" "$tuncpu" "$DEV" "$@" ${B_FLAGS:-}
