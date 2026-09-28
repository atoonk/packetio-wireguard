#!/usr/bin/env bash
# Same low rate in each direction, with both peers' counters diffed around it, so the
# forward/reverse asymmetry has numbers instead of a theory.  dirtest.sh [rate] [size] [secs]
set -uo pipefail
. "$(dirname "$0")/env.sh"
rate=${1:-100k} size=${2:-68} secs=${3:-15}
# The *_slow counters are the stock path's; with the fast path on, the
# traffic is in fp_dec/fp_enc, which the stats line prints separately.
snap() { # <host> -> "wgrx wgtx rxtun txtun rxlan txlan ringfull oversize noneigh noroute"
  $SSH root@$1 'set -- $(wg show wgpio0 transfer | cut -f2,3); echo -n "$1 $2 ";
    journalctl -u wgpio --no-pager -o cat | grep stats | tail -1 |
    sed -n "s/.*rx_tunnel_slow=\([0-9]*\).*tx_tunnel_slow=\([0-9]*\).*/\1 \2/p" | tr -d "\n"; echo -n " ";
    journalctl -u wgpio --no-pager -o cat | grep stats | tail -1 |
    sed -n "s/.*rx_lan_slow=\([0-9]*\).*/\1/p" | tr -d "\n"; echo -n " ";
    journalctl -u wgpio --no-pager -o cat | grep stats | tail -1 |
    sed -n "s/.*tx_lan_slow=\([0-9]*\).*/\1/p" | tr -d "\n"; echo -n " ";
    journalctl -u wgpio --no-pager -o cat | grep stats | tail -1 |
    sed -n "s/.*lan_ring_full=\([0-9]*\).*tx_ring_full=\([0-9]*\).*/\1 \2/p" | tr -d "\n"; echo -n " ";
    journalctl -u wgpio --no-pager -o cat | grep stats | tail -1 |
    sed -n "s/.*no_neighbor=\([0-9]*\).*no_route=\([0-9]*\).*/\1 \2/p"'
}
for dir in fwd rev; do
  case $dir in fwd) dst=$BEHIND_ASH3; via=$ASH2; enc=$ASH2; dec=$ASH3;; rev) dst=$BEHIND_ASH2; via=$ASH3; enc=$ASH3; dec=$ASH2;; esac
  b2=$(snap $ASH2); b3=$(snap $ASH3)
  out=$(wireblast -i $NIC --vlan $VLAN_LAN --src-ip $ASH1_LAN --dst-ip $dst --flows 64 --dst-mac "$(mac_of $via)" \
     --dst-port 9000 --pps "$rate" --packet-size "$size" --duration "${secs}s" --rx-mode udp-port --rx-port 9000 \
     --no-tui -y 2>&1 | grep -E "^  (tx|rx):")
  sleep 11   # let one more stats line land
  a2=$(snap $ASH2); a3=$(snap $ASH3)
  echo "===== $dir ($rate, ${size}B): encrypt=$enc decrypt=$dec"
  echo "$out"
  for who in 2 3; do
    eval "b=\$b$who; a=\$a$who; h=\$ASH$who"
    echo "$b" "$a" | awk -v h="ash-$who" '{ n=NF/2;
      printf "  %s: wg_rx +%d B  wg_tx +%d B | rx_tunnel +%d  tx_tunnel +%d  rx_lan +%d  tx_lan +%d  lan_ring_full +%d  tx_ring_full +%d  no_neighbor +%d  no_route +%d\n",
        h, $(n+1)-$1, $(n+2)-$2, $(n+3)-$3, $(n+4)-$4, $(n+5)-$5, $(n+6)-$6, $(n+7)-$7, $(n+8)-$8, $(n+9)-$9, $(n+10)-$10 }'
  done
done
