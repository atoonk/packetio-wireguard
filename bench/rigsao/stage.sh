#!/usr/bin/env bash
# Put the ladder's binaries on both boxes. They are cross-built here (neither box has
# Go) and installed into /usr/local/bin, which is where the remote scripts look.
set -euo pipefail; . "$(dirname "$0")/env.sh"
bins=${*:-wgpio-stock wgpio-p1 wgpio-p2 wgpio-p3 wgpio-p4 wireguard-go udpblast}
for h in $SAO2 $SAO3; do
  for b in $bins; do
    [ -x "$BIN/$b" ] || { echo "$BIN/$b is missing; run bench/build-ladder.sh"; exit 1; }
    scp -q "$BIN/$b" $USER@$h:/tmp/$b
    $SSH $USER@$h "sudo install -m 755 /tmp/$b /usr/local/bin/$b && rm -f /tmp/$b"
  done
  echo "$(name_of $h): staged $(echo $bins | wc -w) binaries"
done
[ -f "$BIN/ladder.txt" ] && cp "$BIN/ladder.txt" "$RESULTS/ladder.txt" 2>/dev/null || true
