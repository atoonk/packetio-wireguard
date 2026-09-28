# Runs ON a box: sample /proc/stat over <seconds> and print whole-machine CPU use as
# "busy_cores=<N.NN> busy_pct=<P> softirq_cores=<N.NN> max_core_pct=<P> ncpu=<n>". No sysstat needed.
set -eu
secs=${1:-10}
snap() { awk '/^cpu/{print $1, $2+$3+$4+$7+$8+$9, $5+$6, $8}' /proc/stat; }
a=$(snap); s0=$(date +%s.%N); sleep "$secs"; b=$(snap); s1=$(date +%s.%N)
paste <(echo "$a") <(echo "$b") | awk -v n=$(nproc) -v hz=$(getconf CLK_TCK) -v s0=$s0 -v s1=$s1 '
  $1=="cpu" { busy=$6-$2; idle=$7-$3; sirq=$8-$4; next }
  { p=100*($6-$2)/(($6-$2)+($7-$3)); if (p>mx) mx=p }
  END { el=s1-s0; printf "busy_cores=%.2f busy_pct=%.1f softirq_cores=%.2f max_core_pct=%.0f ncpu=%d\n", busy/(hz*el), 100*busy/(busy+idle), sirq/(hz*el), mx, n }'
