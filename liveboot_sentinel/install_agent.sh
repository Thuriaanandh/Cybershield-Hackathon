#!/usr/bin/env bash
# install_agent.sh - Install and configure the LiveBoot Sentinel agent.
# Must be run as root.
#
# Usage: sudo bash install_agent.sh

set -euo pipefail

INSTALL_DIR="/opt/liveboot_sentinel"
CONFIG_DIR="/etc/liveboot_sentinel"
LOG_DIR="/var/log"
SERVICE_FILE="liveboot-sentinel.service"
SYSTEMD_DIR="/etc/systemd/system"

# ── Checks ────────────────────────────────────────────────────────────────────
if [[ "$EUID" -ne 0 ]]; then
    echo "[ERROR] This script must be run as root."
    exit 1
fi

if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python 3 is required. Install with: apt install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 -c "import sys; print(sys.version_info.minor)")
if [[ "$PYTHON_VERSION" -lt 11 ]]; then
    echo "[ERROR] Python 3.11+ is required. Found 3.${PYTHON_VERSION}."
    exit 1
fi

# ── Install ───────────────────────────────────────────────────────────────────
echo "[*] Installing LiveBoot Sentinel agent to $INSTALL_DIR..."

mkdir -p "$INSTALL_DIR/agent"
mkdir -p "$CONFIG_DIR"

# Copy agent files
cp agent/*.py "$INSTALL_DIR/agent/"
chmod 750 "$INSTALL_DIR/agent"
chmod 640 "$INSTALL_DIR/agent"/*.py

# ── Config ────────────────────────────────────────────────────────────────────
if [[ ! -f "$CONFIG_DIR/agent.env" ]]; then
    cp agent.env.template "$CONFIG_DIR/agent.env"
    chmod 600 "$CONFIG_DIR/agent.env"
    echo "[!] Edit $CONFIG_DIR/agent.env with your server URL and API key."
fi

# ── Systemd ───────────────────────────────────────────────────────────────────
cp "$SERVICE_FILE" "$SYSTEMD_DIR/"
chmod 644 "$SYSTEMD_DIR/$SERVICE_FILE"

systemctl daemon-reload
systemctl enable "$SERVICE_FILE"

echo ""
echo "[+] LiveBoot Sentinel agent installed."
echo ""
echo "Next steps:"
echo "  1. Edit $CONFIG_DIR/agent.env"
echo "  2. Run baseline generator: python3 $INSTALL_DIR/agent/baseline_generator.py"
echo "  3. Start agent: systemctl start liveboot-sentinel"
echo "  4. Check status: systemctl status liveboot-sentinel"
