# Runs ON a box: the latest wgpio stats line, and whole-machine CPU over <secs> seconds.
set -eu; secs=${1:-0}
line() { journalctl -u wgpio --no-pager -o cat | grep msg=stats | tail -1 | sed "s/.*msg=stats //"; }
if [ "$secs" -gt 0 ]; then
  a=$(awk '/^cpu /{print $2+$3+$4+$7+$8+$9, $5+$6}' /proc/stat); s0=$(date +%s.%N); l0=$(line); sleep "$secs"; b=$(awk '/^cpu /{print $2+$3+$4+$7+$8+$9, $5+$6}' /proc/stat); s1=$(date +%s.%N); l1=$(line)
  set -- $a $b; awk -v b=$(($3-$1)) -v i=$(($4-$2)) -v hz=$(getconf CLK_TCK) -v el=$(awk -v a=$s0 -v b=$s1 'BEGIN{print b-a}') 'BEGIN{printf "busy_cores=%.2f ", b/(hz*el)}'
  echo "BEGIN $l0"; echo "END $l1"
else line; fi
