# The 100G São Paulo pair (docs/TESTBED-SAO.md): two ConnectX-6 Dx / EPYC 9275F boxes on
# one tagged VLAN. No third box, so the plaintext side is wgpio's built-in generator
# (encrypting peer) and sink (decrypting peer); what is measured is the tunnel itself.
#
#   role A = sao-2, the encrypting side by default (DIR=fwd)
#   role B = sao-3, the decrypting side
#
# Say the role out loud in every message: confusing the two boxes has cost a day before.
SAO2=103.88.233.93    # role A: underlay 10.49.0.1, LAN 10.154.0.2, behind 10.200.2.0/24
SAO3=103.88.233.91    # role B: underlay 10.49.0.2, LAN 10.154.0.3, behind 10.200.3.0/24
A_MAC=7c:c2:55:be:f3:c7
B_MAC=7c:c2:55:be:f4:1b
USER=ubuntu
PCI=0000:c1:00.1      # eno2 on both; eno1 is management and is never touched
DEV=$PCI              # the DPDK backend opens the port by PCI address
VLAN=2049
A_IP=10.49.0.1; B_IP=10.49.0.2
A_LAN=10.154.0.2; B_LAN=10.154.0.3
A_BEHIND=10.200.2.0; B_BEHIND=10.200.3.0
PORT=51820
MTU=1420
# How the fast path is steered onto our queues on a bifurcated mlx5 port: an rte_flow
# rule for the VLAN plus isolate (steer), or take every frame (promisc). Both work;
# run.sh records which was used. Set STEER=promisc to compare.
STEER=${STEER:-steer}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
RESULTS=${RESULTS:-$REPO/bench/results/blog}
CSV=$RESULTS/results.csv
LOGS=$RESULTS/logs
KEYS=$REPO/bench/keys
BIN=$REPO/bin
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"
# run <host> <script in this directory> [args...] -- as root on that box.
run() { local h=$1 s=$2; shift 2; $SSH $USER@"$h" sudo bash -s -- "$@" < "$HERE/$s"; }
role_of() { case $1 in $SAO2) echo A;; $SAO3) echo B;; esac; }
host_of() { case $1 in A) echo $SAO2;; B) echo $SAO3;; esac; }
name_of() { case $1 in $SAO2) echo sao-2;; $SAO3) echo sao-3;; esac; }
