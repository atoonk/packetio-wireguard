# Runs ON any rig box: one line of key=value counters. The NIC's hardware counters
# (what crossed the wire, whoever owns the queues), CPU time, and the tunnel device's
# counters where there is one.
ethtool -S eno2 | awk '/ (rx_packets_phy|tx_packets_phy|rx_discards_phy|rx_out_of_buffer):/{gsub(":","");printf "%s=%s ",$1,$2}'
printf "k_rx=%s k_rxdrop=%s " $(cat /sys/class/net/eno2/statistics/rx_packets /sys/class/net/eno2/statistics/rx_dropped)
awk '/^cpu /{printf "cpu_busy=%d cpu_all=%d ", $2+$3+$4+$7+$8, $2+$3+$4+$5+$6+$7+$8}' /proc/stat
for d in wg0 wgtun; do
  [ -e /sys/class/net/$d ] || continue
  s=/sys/class/net/$d/statistics
  printf "tun_rx=%s tun_tx=%s tun_txdrop=%s tun_rxdrop=%s " $(cat $s/rx_packets $s/tx_packets $s/tx_dropped $s/rx_dropped)
done

# wgpio's own view when it is running: what it received, what the fast path did.
if systemctl is-active -q wgpio 2>/dev/null; then
  journalctl -u wgpio -o cat -n 30 --no-pager | grep 'msg=stats' | tail -1 | tr ' ' '\n' \
    | grep -E '^(rx|fp_enc|fp_dec|fp_noroom|fp_punt|fp_nokey|tx_tunnel_slow|tx_lan_slow|rx_lan_slow|rx_tunnel_slow|tx_error|tx_ring_full|lan_ring_full|nic_missed|rxq_dropped|other)=' \
    | sed 's/^/wg_/' | tr '\n' ' '
fi
echo "t=$(date +%s.%N)"
