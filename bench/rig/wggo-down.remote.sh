set -euo pipefail
systemctl stop wireguard-go 2>/dev/null || true
ip link del wg0 2>/dev/null || true
echo "$(hostname): wireguard-go stopped"
