# The three-box São Paulo rig: a real site-to-site test, plaintext on the wire at
# both ends. All three are ConnectX-6 Dx / EPYC 9275F on one tagged VLAN.
#
#   sao-3 (SRC)  traffic source AND sink: pio-blast sends plaintext "from site A to
#                site B" to gateway A's MAC; pio-drop takes what comes back.
#   sao-2 (A)    gateway A: plaintext in from the LAN, encrypted out to B
#   sao-4 (B)    gateway B: encrypted in, plaintext out to the LAN -- back to sao-3
#
#   sao-3 ──plaintext──► sao-2 ══WireGuard══► sao-4 ──plaintext──► sao-3
#
# Everything is on eno2, VLAN 2049, tagged (untagged never passes the switch). eno1 is
# management and is never touched. The hostnames are the machines' own: .91 is sao-4.
SRC=103.88.233.111   # sao-3
GWA=103.88.233.93    # sao-2
GWB=103.88.233.91    # sao-4
SRC_MAC=7c:c2:55:be:f3:b3
A_MAC=7c:c2:55:be:f3:c7
B_MAC=7c:c2:55:be:f4:1b
USER=ubuntu
VLAN=2049
# underlay (the tunnel between the gateways) and LAN (the plaintext side) are two
# subnets on the one VLAN
A_U=10.49.0.12; B_U=10.49.0.14
A_LAN=10.154.0.12; B_LAN=10.154.0.14; SRC_LAN=10.154.0.13
NS_A_LAN=10.154.0.21; NS_B_LAN=10.154.0.22   # the TCP-test namespaces on sao-3 (sites.remote.sh)
SITE_A=10.200.2.0/24  # what sao-3 sends from
SITE_B=10.200.3.0/24  # what sao-3 sends to, and receives back
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
RESULTS=${RESULTS:-$REPO/bench/results/rig3}
CSV=$RESULTS/results.csv
LOGS=$RESULTS/logs
KEYS=$REPO/bench/keys
BIN=$REPO/bin/rig3
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"
# run <host> <script in this directory> [args...] -- as root on that box.
run() { local h=$1 s=$2; shift 2; $SSH $USER@"$h" sudo bash -s -- "$@" < "$HERE/$s"; }
