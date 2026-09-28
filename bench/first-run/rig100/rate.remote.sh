# Runs ON a box: steady-state rates from wgpio's last two stats lines (5 s apart), so no
# ssh timing enters the number. Prints "<key>=<per-second> ..." for the counters given.
set -eu
lines=$(journalctl -u wgpio --no-pager -o cat | grep msg=stats | tail -2)
[ "$(echo "$lines" | wc -l)" = 2 ] || { echo "rate: fewer than two stats lines"; exit 1; }
t0=$(echo "$lines" | sed -n '1s/^time=\([^ ]*\).*/\1/p'); t1=$(echo "$lines" | sed -n '2s/^time=\([^ ]*\).*/\1/p')
dt=$(python3 -c "from datetime import datetime as d; f='%Y-%m-%dT%H:%M:%S.%fZ'; print((d.strptime('$t1',f)-d.strptime('$t0',f)).total_seconds())")
for k in "$@"; do
  a=$(echo "$lines" | sed -n "1s/.* $k=\([0-9]*\).*/\1/p"); b=$(echo "$lines" | sed -n "2s/.* $k=\([0-9]*\).*/\1/p")
  printf "%s=%.0f " "$k" "$(python3 -c "print((${b:-0}-${a:-0})/$dt)")"
done
awk '/^cpu /{print $2+$3+$4+$7+$8+$9}' /proc/stat > /tmp/cpu0; sleep 2; awk -v a=$(cat /tmp/cpu0) -v hz=$(getconf CLK_TCK) '/^cpu /{printf "busy_cores=%.2f\n", (($2+$3+$4+$7+$8+$9)-a)/(hz*2)}' /proc/stat
