# Runs ON a peer. Apply one or more of the usual kernel WireGuard tunes; "reset" undoes them.
#   args: <tune>...   tunes: irq  rings  threaded  rps  coalesce  reset
# Each is what a sysadmin would actually reach for; kernel-tune.sh measures them one at a time.
set -euo pipefail
NIC=eno2; WG=wg0; N=$(nproc)
for t in "$@"; do case $t in
  irq)      # spread the NIC's queue interrupts over all CPUs, one queue per CPU
    systemctl stop irqbalance 2>/dev/null || true
    i=0; for irq in $(grep "$NIC-TxRx" /proc/interrupts | cut -d: -f1); do
      echo $((i % N)) > /proc/irq/$irq/smp_affinity_list; i=$((i+1)); done
    echo "irq: $i queue interrupts spread over $N cpus";;
  rings)    ethtool -G $NIC rx 4096 tx 4096 && echo "rings: 4096";;
  threaded) # per-peer NAPI in a kernel thread the scheduler may move, instead of softirq on the RSS core
    echo 1 > /sys/class/net/$WG/threaded && echo "threaded napi on $WG";;
  rps)      # decrypted packets spread over all CPUs for the forwarding step
    mask=$(printf '%x' $(( (1<<N)-1 )))
    for q in /sys/class/net/$WG/queues/rx-*; do echo $mask > $q/rps_cpus; done
    for q in /sys/class/net/vlan.2131/queues/rx-*; do echo $mask > $q/rps_cpus; done
    sysctl -qw net.core.rps_sock_flow_entries=32768
    echo "rps on $WG and vlan.2131: cpus $mask";;
  coalesce) ethtool -C $NIC rx-usecs 50 && echo "rx-usecs 50";;
  reset)
    ethtool -G $NIC rx 512 tx 512 2>/dev/null || true
    ethtool -C $NIC rx-usecs 1 2>/dev/null || true
    [ -e /sys/class/net/$WG/threaded ] && echo 0 > /sys/class/net/$WG/threaded || true
    for q in /sys/class/net/$WG/queues/rx-* /sys/class/net/vlan.2131/queues/rx-*; do [ -e $q ] && echo 0 > $q/rps_cpus; done
    systemctl start irqbalance 2>/dev/null || true
    echo "reset";;
  *) echo "unknown tune $t" >&2; exit 2;;
esac; done
