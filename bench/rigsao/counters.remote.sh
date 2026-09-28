# Runs ON a box: one line of "key=value" naming everything a measurement window is
# bracketed by. The driver reads it before and after and differences it, so nothing
# depends on when a stats line happened to be printed.
set -eu
printf 'now=%s hz=%s ' "$(date +%s.%N)" "$(getconf CLK_TCK)"
awk '/^cpu /{printf "busy=%d ", $2+$3+$4+$7+$8+$9}' /proc/stat
if [ -e /sys/class/net/wg0/statistics/rx_packets ]; then
  printf 'wg0_rx=%s wg0_tx=%s ' \
    "$(cat /sys/class/net/wg0/statistics/rx_packets)" "$(cat /sys/class/net/wg0/statistics/tx_packets)"
fi
ethtool -S eno2 2>/dev/null |
  awk '/ (rx_packets_phy|tx_packets_phy|rx_steer_missed_packets|rx_out_of_buffer):/{gsub(":","",$1); printf "%s=%s ", $1, $2}'
# Where the kernel lost datagrams on the way to userspace. wireguard-go reads the
# tunnel from an ordinary UDP socket, so a full socket queue drops packets it never
# sees and cannot count; without these the loss is invisible in its own numbers.
awk '/^Udp:/{if(!h){for(i=2;i<=NF;i++)k[i]=$i;h=1;next} for(i=2;i<=NF;i++)printf "udp_%s=%s ",k[i],$i}' /proc/net/snmp
if [ -e /sys/class/net/wg0/statistics/rx_dropped ]; then
  printf 'wg0_rxdrop=%s wg0_txdrop=%s ' \
    "$(cat /sys/class/net/wg0/statistics/rx_dropped)" "$(cat /sys/class/net/wg0/statistics/tx_dropped)"
fi
# wgpio's own counters, if it is running: the whole stats line, already key=value.
#
# wgts is the moment wgpio printed that line, and it matters. The counters come from a
# line printed on wgpio's own schedule; everything else here is read now. Dividing a
# counter delta by the wall-clock window mixes the two, and with a 5-second stats
# interval in a 24-second window that is a systematic error of up to 20% -- which is
# exactly the size of the "bimodal" 37-versus-46 Mpps swing it produced.
line=$(journalctl -u wgpio --no-pager -o cat 2>/dev/null | grep msg=stats | tail -1)
if [ -n "$line" ]; then
  t=$(printf '%s' "$line" | sed -n 's/^time=\([^ ]*\).*/\1/p')
  printf 'wgts=%s ' "$(date -u -d "$t" +%s.%N 2>/dev/null || echo 0)"
  printf '%s' "$line" | sed 's/.*msg=stats //' | tr -d '"'
fi
echo
