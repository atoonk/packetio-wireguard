#!/usr/bin/env bash
# Generate the fixed WireGuard keypairs used by every mode (kernel, wireguard-go, wgpio).
# They live in bench/keys/, which is gitignored.
set -euo pipefail
. "$(dirname "$0")/env.sh"
mkdir -p "$KEYS"; umask 077
for p in ash2 ash3; do
  [ -s "$KEYS/$p.key" ] || wg genkey > "$KEYS/$p.key"
  wg pubkey < "$KEYS/$p.key" > "$KEYS/$p.pub"
done
echo "ash2 pub: $(cat "$KEYS/ash2.pub")"; echo "ash3 pub: $(cat "$KEYS/ash3.pub")"
