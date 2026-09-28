# Rig definition for the packetio-wireguard benchmarks. Sourced by every script.
# Three boxes: ash-1 generates and sinks, ash-2/ash-3 are the two WireGuard peers.
ASH1=206.223.228.203   # this box: generator + sink (wireblast on eno2, VLAN 2154)
ASH2=206.223.228.209   # peer A
ASH3=206.223.228.217   # peer B
NIC=eno2               # the 10G port on every box; eno1 is management and is never touched
PCI=0000:01:00.0       # eno2 on ash-2 and ash-3
VLAN_UNDERLAY=2131     # WireGuard UDP between the peers
VLAN_LAN=2154          # plaintext side; ash-1 lives here
UNDERLAY_NET=10.131.0.0/24
LAN_NET=10.154.0.0/24
ASH1_LAN=10.154.0.1
ASH2_LAN=10.154.0.2
ASH3_LAN=10.154.0.3
ASH2_UNDERLAY=10.131.0.2
ASH3_UNDERLAY=10.131.0.3
BEHIND_ASH2=10.200.2.0/24   # generator sends here to traverse ash-3 -> ash-2 -> ash-1
BEHIND_ASH3=10.200.3.0/24   # generator sends here to traverse ash-2 -> ash-3 -> ash-1
WG_PORT=51820
WG_MTU=1420
WG_IF=wg0
KEYS=$(cd "$(dirname "${BASH_SOURCE[0]}")/../keys" 2>/dev/null && pwd || echo "$HOME/packetio-wireguard/bench/keys")
SSH="ssh -o BatchMode=yes -o ConnectTimeout=5"
# The peers' eno2 MACs: under DPDK the kernel no longer has the interface to ask.
ASH2_MAC=3c:ec:ef:b4:c2:dc
ASH3_MAC=3c:ec:ef:b4:c5:5e
mac_of() { case $1 in $ASH2) echo $ASH2_MAC;; $ASH3) echo $ASH3_MAC;; *) $SSH root@$1 cat /sys/class/net/$NIC/address;; esac; }

# run <host> <script> [args...]: ship a local script to a box and run it there as root.
run() { local h=$1 s=$2; shift 2; $SSH root@"$h" bash -s -- "$@" < "$(dirname "${BASH_SOURCE[0]}")/$s"; }
