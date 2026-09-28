#!/usr/bin/env bash
# Deploy bin/wireguard-go (built from upstream golang.zx2c4.com/wireguard) to both peers and start it.
set -euo pipefail
. "$(dirname "$0")/env.sh"
for h in $ASH2 $ASH3; do $SSH root@$h "systemctl stop wireguard-go 2>/dev/null; true"; scp -q "$(dirname "$0")/../../bin/wireguard-go" root@$h:/usr/local/bin/wireguard-go; done
run $ASH2 wggo-up.remote.sh ash2 "$(cat $KEYS/ash2.key)" "$(cat $KEYS/ash3.pub)"
run $ASH3 wggo-up.remote.sh ash3 "$(cat $KEYS/ash3.key)" "$(cat $KEYS/ash2.pub)"
