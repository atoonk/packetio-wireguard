# Runs ON a peer: one line of the drop-relevant counters, for before/after diffs.
set -eu
nic=eno2; d=0; s=0
while read -r _ dr sq _; do d=$((d + 0x$dr)); s=$((s + 0x$sq)); done < /proc/net/softnet_stat
printf "softnet_dropped=%d softnet_squeezed=%d " $d $s
ethtool -S $nic | awk '/rx_missed_errors|rx_no_buffer|rx_dropped|tx_dropped|^ *rx_packets|^ *tx_packets/{gsub(":","",$1); printf "%s=%s ", $1, $2}'
for i in wg0 vlan.2131 vlan.2154; do ip -s link show $i 2>/dev/null | awk -v i=$i 'NR==4{printf "%s_rx=%s %s_rxdrop=%s ", i,$2,i,$4} NR==6{printf "%s_tx=%s %s_txdrop=%s ", i,$2,i,$4}'; done
echo
