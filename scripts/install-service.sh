#!/usr/bin/env bash
# Install the panel as a systemd service + narrow sudo privileges.
# Requires sudo. To undo: scripts/uninstall-service.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -d frontend/dist/rapi-panel/browser ]]; then
  echo "Frontend is not built. Run scripts/build.sh first." >&2
  exit 1
fi

echo "==> Sudo privileges (engine control only)"
# The disable.conf path depends on the install directory, so the template is filled in here.
TMP_SUDOERS="$(mktemp)"
trap 'rm -f "$TMP_SUDOERS"' EXIT
# The account the panel runs as, which is this one: the unit below is built
# with the same name. A checkout by anybody not called rapi used to get a
# sudoers entry for an account that was not theirs, and every privileged
# feature of the panel silently did nothing.
sed -e "s|@DISABLE_CONF@|${ROOT}/data/disable.conf|g" \
    -e "s|@DROP_CONF@|${ROOT}/data/drop.conf|g" \
    -e "s|@PANEL_USER@|$(id -un)|g" \
    deploy/sudoers-rapi-panel > "$TMP_SUDOERS"
sudo visudo -cf "$TMP_SUDOERS"
sudo install -m 0440 -o root -g root "$TMP_SUDOERS" /etc/sudoers.d/rapi-panel

# Where rapi-ips-mode writes the queue rule. The panel reaches it through a bind
# mount that only exists if the directory does, and the nftables package does
# not create it.
sudo install -d -m 0755 -o root -g root /etc/nftables.d

echo "==> Engine config overrides (changing the log directory from the panel)"
scripts/setup-suricata-override.sh

echo "==> TLS certificate"
scripts/setup-tls.sh

echo "==> Engine autostart"
# The Debian package already enables the unit in its postinst, so this is a
# guarantee rather than a fix: an appliance whose whole job is detection must
# not depend on nobody having run `systemctl disable` at some point. Enabling an
# already-enabled unit is a no-op, so it costs nothing to be sure.
sudo systemctl enable suricata.service
sudo systemctl restart suricata.service

echo "==> Daily signature refresh"
# Always with the panel's disable.conf: a rebuild without it switches every
# disabled category and every silenced signature back on, and nothing says so.
sudo install -m 0755 -o root -g root deploy/rapi-rules-update /usr/local/sbin/rapi-rules-update
# Read only companion: the vendor build date of the set, which lives in
# suricata-update's root-only cache and nowhere the panel's user can reach.
sudo install -m 0755 -o root -g root deploy/rapi-rules-date /usr/local/sbin/rapi-rules-date
# The SSH password follows the panel's, but only for an account the panel set
# itself or found locked. On a checkout the account is somebody's own login
# and the helper leaves it alone (deploy/rapi-login-password says why).
sudo install -m 0755 -o root -g root deploy/rapi-login-password /usr/local/sbin/rapi-login-password
TMP_UPDATE="$(mktemp)"
trap 'rm -f "$TMP_SUDOERS" "$TMP_UPDATE"' EXIT
sed -e "s|@DISABLE_CONF@|${ROOT}/data/disable.conf|g" \
    -e "s|@DROP_CONF@|${ROOT}/data/drop.conf|g" \
    deploy/rapi-rules-update.service.in > "$TMP_UPDATE"
sudo install -m 0644 -o root -g root "$TMP_UPDATE" \
    /etc/systemd/system/rapi-rules-update.service
sudo install -m 0644 -o root -g root deploy/rapi-rules-update.timer \
    /etc/systemd/system/rapi-rules-update.timer
sudo systemctl daemon-reload
sudo systemctl enable --now rapi-rules-update.timer

echo "==> USB network adapters that boot as a CD drive"
# See deploy/rapi-usb-nic.modeswitch. The rule calls usb-modeswitch's own udev
# wrapper, so without the package it would only log an error on every plug.
if [ -x /usr/lib/udev/usb_modeswitch ]; then
    sudo install -D -m 0644 -o root -g root deploy/rapi-usb-nic.modeswitch \
        /etc/usb_modeswitch.d/0bda:8151
    sudo install -D -m 0644 -o root -g root deploy/rapi-usb-nic.rules \
        /etc/udev/rules.d/40-rapi-usb-nic.rules
    sudo udevadm control --reload
    # The new rule reaches the next plug, not an adapter already sitting in a
    # port: udev fires no event for one that is there. Printed rather than
    # triggered, because a trigger replays add events for every USB device on
    # what may be a probe with traffic crossing it.
    echo "    done. An adapter already plugged in and showing as a CD drive needs"
    echo "    a replug, a reboot, or: sudo udevadm trigger --subsystem-match=usb --action=add"
else
    echo "    skipped: apt install usb-modeswitch usb-modeswitch-data, then run this again"
fi

echo "==> systemd service"
# Same template the image build uses; here it points at the checkout and its venv.
TMP_UNIT="$(mktemp)"
trap 'rm -f "$TMP_SUDOERS" "$TMP_UPDATE" "$TMP_UNIT"' EXIT
sed -e "s|@PANEL_ROOT@|${ROOT}|g" \
    -e "s|@DATA_DIR@|${ROOT}/data|g" \
    -e "s|@PYTHON@|${ROOT}/backend/.venv/bin/python|g" \
    -e "s|@PANEL_USER@|$(id -un)|g" \
    deploy/rapi-panel.service.in > "$TMP_UNIT"
sudo install -m 0644 -o root -g root "$TMP_UNIT" /etc/systemd/system/rapi-panel.service
sudo systemctl daemon-reload
sudo systemctl enable --now rapi-panel.service

sleep 2
echo
sudo systemctl status rapi-panel.service --no-pager -l | head -15
echo
echo "The panel should be reachable at: https://$(hostname).local  (or https://$(hostname -I | awk '{print $1}'))"
echo "Plain HTTP on 80 and 8000 redirects there."
echo
echo "Until the panel CA is trusted, the browser will warn on every visit."
echo "Import this file once per device:"
echo "    ${ROOT}/data/tls/ca.crt"
echo
echo "Logs:  journalctl -u rapi-panel -f"
