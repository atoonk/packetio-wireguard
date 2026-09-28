#!/usr/bin/env bash
# Kernel (or wireguard-go) baseline on the 100G rig: udpblast (sendmmsg) into wg0 on A, count wg0 rx on B.
#   baseline.sh <kernel|wggo> <threads> [secs] [size]
set -euo pipefail; here=$(dirname "$0"); . "$here/env.sh"; "$here/keys.sh"
mode=$1 threads=$2 secs=${3:-20} size=${4:-46}
scp -q "$here/../../bin/udpblast" $USER@$SAO2:/tmp/udpblast; $SSH $USER@$SAO2 "sudo install -m 755 /tmp/udpblast /usr/local/bin/udpblast"
if [ "$mode" = wggo ]; then for h in $SAO2 $SAO3; do scp -q "$here/../../bin/wireguard-go" $USER@$h:/tmp/wireguard-go; $SSH $USER@$h "sudo install -m 755 /tmp/wireguard-go /usr/local/bin/wireguard-go"; done; fi
run $SAO2 kernel-up.remote.sh A "$(cat $KEYS/saoA.key)" "$(cat $KEYS/saoB.pub)" $mode >/dev/null
run $SAO3 kernel-up.remote.sh B "$(cat $KEYS/saoB.key)" "$(cat $KEYS/saoA.pub)" $mode >/dev/null
sleep 2; $SSH $USER@$SAO2 'ping -c 2 -W 1 10.154.0.3 >/dev/null && echo "ping through the tunnel ok" || echo "PING FAILED"'
rx0=$($SSH $USER@$SAO3 "cat /sys/class/net/wg0/statistics/rx_packets"); c0=$($SSH $USER@$SAO3 "awk '/^cpu /{print \$2+\$3+\$4+\$7+\$8+\$9}' /proc/stat")
sent=$($SSH $USER@$SAO2 "sudo udpblast -threads $threads -duration ${secs}s -size $size -dst 10.200.3.0 -flows 64 -port 9000")
rx1=$($SSH $USER@$SAO3 "cat /sys/class/net/wg0/statistics/rx_packets"); c1=$($SSH $USER@$SAO3 "awk '/^cpu /{print \$2+\$3+\$4+\$7+\$8+\$9}' /proc/stat")
echo "$sent"; echo "RESULT mode=$mode threads=$threads size=$size offered=$(( $(echo $sent | sed 's/.*pps=//') /1000 ))k delivered=$(( (rx1-rx0)/secs/1000 ))k dec_busy_cores=$(python3 -c "print(round(($c1-$c0)/100/$secs,2))")"
