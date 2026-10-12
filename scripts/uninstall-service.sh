#!/usr/bin/env bash
# Remove the panel service and the sudoers entry. Leaves the engine and data/ alone.
set -euo pipefail

echo "==> Stopping the service"
sudo systemctl disable --now rapi-panel.service 2>/dev/null || true
sudo rm -f /etc/systemd/system/rapi-panel.service
sudo systemctl daemon-reload

echo "==> Removing the sudoers entry"
sudo rm -f /etc/sudoers.d/rapi-panel

echo "Done. The alert database stays in data/panel.db - remove it by hand if you want."
