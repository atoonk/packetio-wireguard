# Runs ON a box as root: take CPU, mutex and block profiles from the running wgpio and
# leave them in /tmp, with a text summary beside each.
#   profile.remote.sh <label> <cpu seconds>
set -euo pipefail
label=$1 secs=${2:-20}
systemctl is-active -q wgpio || { echo "wgpio is not running"; exit 1; }
cd /tmp
curl -sf "http://127.0.0.1:6060/debug/pprof/profile?seconds=$secs" -o "$label-cpu.pprof"
curl -sf "http://127.0.0.1:6060/debug/pprof/mutex" -o "$label-mutex.pprof"
curl -sf "http://127.0.0.1:6060/debug/pprof/block" -o "$label-block.pprof"
bin=$(systemctl show -p ExecStart --value wgpio | sed -n 's/.*path=\([^ ;]*\).*/\1/p')
for k in cpu mutex block; do
  go tool pprof -top -nodecount=25 "$bin" "$label-$k.pprof" > "$label-$k.txt" 2>/dev/null ||
    echo "(no go toolchain on this box; analyse $label-$k.pprof on the control box)" > "$label-$k.txt"
done
ls -la "$label"-*.pprof | awk '{print $NF, $5}'
