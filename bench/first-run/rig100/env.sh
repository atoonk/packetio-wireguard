# The 100G rig: two ConnectX-6 Dx / EPYC 9275F boxes on one tagged VLAN. No third box,
# so the plaintext side is wgpio's built-in generator (encrypting peer) and sink
# (decrypting peer); what is measured is the tunnel itself.
SAO2=103.88.233.93    # role A: underlay 10.49.0.2
SAO3=103.88.233.111   # role B: underlay 10.49.0.3
USER=ubuntu
PCI=0000:c1:00.1      # eno2; eno1 is management and is never touched
# Backend: DPDK's mlx5 PMD steers nothing on this kernel (docs/PACKETIO-NOTES.md), so the
# verbs backend is used here: DEV=eno2 with bin/wgpio-mlx5. Set BACKEND=dpdk to retry DPDK.
BACKEND=${BACKEND:-mlx5}
case $BACKEND in mlx5) DEV=eno2; BIN=wgpio-mlx5;; dpdk) DEV=$PCI; BIN=wgpio;; esac
VLAN=2049
A_IP=10.49.0.2; B_IP=10.49.0.3
PORT=51820
KEYS=$(cd "$(dirname "${BASH_SOURCE[0]}")/../keys" && pwd)
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"
run() { local h=$1 s=$2; shift 2; $SSH $USER@"$h" sudo bash -s -- "$@" < "$(dirname "${BASH_SOURCE[0]}")/$s"; }
role_of() { case $1 in $SAO2) echo A;; $SAO3) echo B;; esac; }
