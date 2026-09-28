#!/usr/bin/env bash
# Apply tunes on both peers: kernel-tune.sh irq rings threaded ...   (or: reset)
set -euo pipefail
. "$(dirname "$0")/env.sh"
run $ASH2 kernel-tune.remote.sh "$@"; run $ASH3 kernel-tune.remote.sh "$@"
