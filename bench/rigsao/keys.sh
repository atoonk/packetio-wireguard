#!/usr/bin/env bash
# The peer keys, made once and kept out of git (bench/keys is .gitignored).
set -euo pipefail; . "$(dirname "$0")/env.sh"; umask 077
mkdir -p "$KEYS"
for p in saoA saoB; do
  [ -s "$KEYS/$p.key" ] || wg genkey > "$KEYS/$p.key"
  wg pubkey < "$KEYS/$p.key" > "$KEYS/$p.pub"
done
echo "A $(cat $KEYS/saoA.pub)"; echo "B $(cat $KEYS/saoB.pub)"
