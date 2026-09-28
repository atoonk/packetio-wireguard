#!/usr/bin/env bash
set -euo pipefail; . "$(dirname "$0")/env.sh"; umask 077
for p in saoA saoB; do [ -s "$KEYS/$p.key" ] || wg genkey > "$KEYS/$p.key"; wg pubkey < "$KEYS/$p.key" > "$KEYS/$p.pub"; done
