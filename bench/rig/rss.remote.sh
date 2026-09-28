# Runs ON a box: print RSS in MB of the named process (0 if not running). args: <exact process name>
set -eu
pid=$(pgrep -x "$1" | head -1 || true)
[ -n "$pid" ] && awk '/VmRSS/{printf "rss_mb=%.0f\n", $2/1024}' /proc/$pid/status || echo rss_mb=0
