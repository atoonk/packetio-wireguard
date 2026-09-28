set -euo pipefail
systemctl stop wgpio 2>/dev/null || true
echo "$(hostname): wgpio stopped"
