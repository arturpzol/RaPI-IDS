#!/usr/bin/env bash
# Turn a freshly debootstrapped Debian into the appliance. Runs inside the
# unshare namespace mmdebstrap created, with $1 pointing at the root filesystem.
#
# Everything here is what a *copy* of the image may carry. Anything that has to
# be unique per device (host keys, TLS, machine id) or depends on the network is
# in image/first-boot/rapi-first-boot.sh instead.
set -euo pipefail

ROOTFS="$1"
SRC="${PANEL_SRC:?PANEL_SRC (the checkout) is not set}"
PANEL_ROOT=/opt/rapi-panel
DATA_DIR=/var/lib/rapi-panel
PANEL_USER=rapi

say() { echo "customize: $*"; }
inch() { chroot "$ROOTFS" "$@"; }

# --- the panel itself -------------------------------------------------------
say "installing the panel into $PANEL_ROOT"
install -d -m 0755 "$ROOTFS$PANEL_ROOT"
# Only what the appliance runs: the backend, the *built* frontend (the image has
# no Node and never will), the root-owned helpers and the two scripts the first
# boot calls. The development scripts have nothing to do on a device with no
# checkout and no test suite.
# The English README only (see build-image.sh), installed as README.md.
OPTIONAL=()
if [[ -f "$SRC/README.en.md" ]]; then OPTIONAL+=(README.en.md)
elif [[ -f "$SRC/README.md" ]]; then OPTIONAL+=(README.md); fi
tar -C "$SRC" -cf - \
    backend/app \
    deploy \
    scripts/setup-suricata-override.sh scripts/setup-tls.sh \
    frontend/dist/rapi-panel/browser \
    LICENSE \
    "${OPTIONAL[@]}" \
  | tar -C "$ROOTFS$PANEL_ROOT" -xf -
if [[ -f "$ROOTFS$PANEL_ROOT/README.en.md" ]]; then
  mv "$ROOTFS$PANEL_ROOT/README.en.md" "$ROOTFS$PANEL_ROOT/README.md"
fi
find "$ROOTFS$PANEL_ROOT" -name __pycache__ -type d -prune -exec rm -rf {} +

# --- the account it runs as -------------------------------------------------
# No password. Nothing in the image can log in until someone sets a password
# through userconf.txt on the boot partition, and the panel account is created
# by whoever opens the panel first.
# Not in group sudo. The panel runs as this account and may set its password
# (the panel password becomes the SSH one), so with sudo membership a panel
# taken over could set a password it knows and then `sudo -S` anything: the
# narrow sudoers entry would guard nothing. Root is for the account whose
# password came with the card, which the panel never sees; first boot gives
# that one sudo. adm and systemd-journal are enough to read the logs.
say "creating the $PANEL_USER account"
inch useradd --create-home --shell /bin/bash --groups adm,systemd-journal "$PANEL_USER"
inch passwd --lock "$PANEL_USER" >/dev/null
# Locked by the image, so the panel may give it the panel password for SSH.
# Only this file says so: on a checkout the account is somebody's own, and a
# locked one there is locked on purpose (deploy/rapi-login-password says more).
install -d "$ROOTFS/var/lib"
printf 'image %s\n' "$PANEL_USER" > "$ROOTFS/var/lib/rapi-ssh-login"
chmod 0644 "$ROOTFS/var/lib/rapi-ssh-login"
install -d -m 0750 "$ROOTFS$DATA_DIR"
inch chown -R "$PANEL_USER:$PANEL_USER" "$DATA_DIR"

# --- privileged helpers -----------------------------------------------------
say "installing the root-owned helpers and the sudoers entry"
for helper in rapi-capture-apply rapi-capture-iface rapi-capture-probe rapi-log-dir \
             rapi-issue rapi-ips-mode rapi-bridge rapi-rules-date rapi-inline \
             rapi-login-password; do
  install -m 0755 -o root -g root "$SRC/deploy/$helper" "$ROOTFS/usr/local/sbin/$helper"
done
install -m 0755 -o root -g root "$SRC/image/first-boot/rapi-first-boot.sh" \
  "$ROOTFS/usr/local/sbin/rapi-first-boot"
install -m 0755 -o root -g root "$SRC/image/first-boot/rapi-imager-config" \
  "$ROOTFS/usr/local/sbin/rapi-imager-config"

sed -e "s|@DISABLE_CONF@|$DATA_DIR/disable.conf|g" \
    -e "s|@DROP_CONF@|$DATA_DIR/drop.conf|g" \
    -e "s|@PANEL_USER@|$PANEL_USER|g" "$SRC/deploy/sudoers-rapi-panel" \
  > "$ROOTFS/etc/sudoers.d/rapi-panel"
chmod 0440 "$ROOTFS/etc/sudoers.d/rapi-panel"
inch visudo -cf /etc/sudoers.d/rapi-panel

# --- services ---------------------------------------------------------------
say "installing the units"
sed -e "s|@PANEL_ROOT@|$PANEL_ROOT|g" \
    -e "s|@DATA_DIR@|$DATA_DIR|g" \
    -e "s|@PYTHON@|/usr/bin/python3|g" \
    -e "s|@PANEL_USER@|$PANEL_USER|g" \
    "$SRC/deploy/rapi-panel.service.in" > "$ROOTFS/etc/systemd/system/rapi-panel.service"
install -m 0644 "$SRC/image/first-boot/rapi-first-boot.service" \
  "$ROOTFS/etc/systemd/system/rapi-first-boot.service"
install -m 0644 "$SRC/image/first-boot/rapi-imager-config.service" \
  "$ROOTFS/etc/systemd/system/rapi-imager-config.service"
install -m 0644 "$SRC/deploy/rapi-issue.service" \
  "$ROOTFS/etc/systemd/system/rapi-issue.service"

# The daily signature refresh. It was in scripts/install-service.sh and not
# here, so every image ever built shipped without it: a device flashed and left
# alone ran on the rules from the day the image was made, for as long as it was
# plugged in, and looked perfectly healthy doing it. That is word for word the
# failure the timer was written to prevent, and the image was the one place it
# still happened. Found by the blocking self test in scripts/test-image-vm.sh,
# which called a helper that was not there.
install -m 0755 -o root -g root "$SRC/deploy/rapi-rules-update" \
  "$ROOTFS/usr/local/sbin/rapi-rules-update"
sed -e "s|@DISABLE_CONF@|$DATA_DIR/disable.conf|g" \
    -e "s|@DROP_CONF@|$DATA_DIR/drop.conf|g" \
    "$SRC/deploy/rapi-rules-update.service.in" \
    > "$ROOTFS/etc/systemd/system/rapi-rules-update.service"
chmod 0644 "$ROOTFS/etc/systemd/system/rapi-rules-update.service"
install -m 0644 "$SRC/deploy/rapi-rules-update.timer" \
  "$ROOTFS/etc/systemd/system/rapi-rules-update.timer"

# The banner has to follow the address, not just the boot. A lease that arrives
# or changes an hour later would otherwise leave a URL on screen that no longer
# works. NetworkManager runs everything in dispatcher.d on every such event, and
# passes the interface and the action as arguments, which this script ignores -
# so the hook is the script itself.
# Where rapi-ips-mode writes the queue rule. Created here because the panel
# reaches it through a bind mount that only exists if the directory does, and
# because the nftables package does not create it.
install -d "$ROOTFS/etc/nftables.d"

# A Realtek USB adapter that boots as a CD drive, which the data package has no
# entry for. See deploy/rapi-usb-nic.modeswitch.
install -D -m 0644 "$SRC/deploy/rapi-usb-nic.modeswitch" \
  "$ROOTFS/etc/usb_modeswitch.d/0bda:8151"
install -D -m 0644 "$SRC/deploy/rapi-usb-nic.rules" \
  "$ROOTFS/etc/udev/rules.d/40-rapi-usb-nic.rules"

install -d "$ROOTFS/etc/NetworkManager/dispatcher.d"
ln -sf /usr/local/sbin/rapi-issue "$ROOTFS/etc/NetworkManager/dispatcher.d/50-rapi-issue"

# What the screen says between the first getty and the first run of the banner,
# and what it says if that run ever fails. Debian's default is the distribution
# name, which on an appliance is the one fact nobody needed.
cat > "$ROOTFS/etc/issue" <<'EOF'

  RaPi IDS

  Starting up. The panel address appears here once the network answers.

EOF

# The Debian package ships the engine disabled, so an appliance built from it
# would boot with no detection and nothing on screen to say so.
inch systemctl enable suricata.service rapi-panel.service rapi-first-boot.service \
     rapi-imager-config.service rapi-issue.service rapi-rules-update.timer \
     ssh.service NetworkManager.service avahi-daemon.service systemd-timesyncd.service

# --- system configuration ---------------------------------------------------
say "system configuration"
echo "rapi-ids" > "$ROOTFS/etc/hostname"
cat > "$ROOTFS/etc/hosts" <<EOF
127.0.0.1	localhost
127.0.1.1	rapi-ids
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters
EOF
install -m 0644 "$SRC/image/fstab" "$ROOTFS/etc/fstab"

# Interfaces are eth0 and wlan0, not end0: the documentation, the wizard and
# every example in the panel name them that way, and Raspberry Pi OS masks the
# same two files for the same reason.
install -d "$ROOTFS/etc/systemd/network"
ln -sf /dev/null "$ROOTFS/etc/systemd/network/99-default.link"
ln -sf /dev/null "$ROOTFS/etc/systemd/network/73-usb-net-by-mac.link"

# The journal is the single biggest writer on an idle appliance and the card is
# the one part that wears out. It lives in RAM and is capped.
install -d "$ROOTFS/etc/systemd/journald.conf.d"
cat > "$ROOTFS/etc/systemd/journald.conf.d/00-rapi-volatile.conf" <<'EOF'
# Written by the image build. The alerts that matter are in the panel database
# on disk; the journal is for the current boot.
[Journal]
Storage=volatile
RuntimeMaxUse=48M
EOF

# --- rules ------------------------------------------------------------------
# One fetch here means a device that boots on a network with no route out still
# has signatures. suricata-update keeps its cache per engine version, so this
# has to happen with the same Suricata the image ships.
if [[ "${FETCH_RULES:-1}" = 1 ]]; then
  # --fail: a fetch that does not arrive otherwise leaves the engine's own 445
  # rules, exit 0, and an image that says its signature set was fetched.
  if inch suricata-update --fail --no-test >"$ROOTFS/tmp/su.log" 2>&1; then
    say "signature set fetched: $(inch sh -c 'ls -1 /var/lib/suricata/rules 2>/dev/null | wc -l') files"
  else
    say "WARNING: no signatures in the image (see below), the device fetches them itself"
    tail -5 "$ROOTFS/tmp/su.log" | sed 's/^/customize:   /'
  fi
  rm -f "$ROOTFS/tmp/su.log"

  # The BSD licence on the Emerging Threats rules asks for one thing in return:
  # that the notice travels with the binaries. suricata-update merges 68 000
  # rules into a single suricata.rules and leaves the licence where it found it,
  # inside the archive it cached, in a directory only root can open. Present,
  # and not "provided with the distribution" in any sense a person could act on.
  #
  # Only the ET range is BSD. The engine's own event rules carry SIDs inside the
  # range ET's LICENSE claims, but they come from the Debian suricata package
  # and are GPL-2 with the engine, covered by the same written offer as the rest
  # of the userland.
  ET_ARCHIVE="$(find "$ROOTFS/var/lib/suricata/update/cache" -maxdepth 1 \
                     -name '*.tar.gz' -printf '%T@\t%p\n' 2>/dev/null \
                | sort -n | tail -n 1 | cut -f2-)"
  if [[ -n "$ET_ARCHIVE" ]]; then
    install -d -m 0755 "$ROOTFS/usr/share/doc/emerging-threats-rules"
    tar -xzf "$ET_ARCHIVE" -C "$ROOTFS/usr/share/doc/emerging-threats-rules" \
        --strip-components=1 rules/LICENSE rules/BSD-License.txt
    say "rule licences placed in /usr/share/doc/emerging-threats-rules"
  else
    say "WARNING: no rule archive to take the licence text from"
  fi
fi

# --- what must not be shared by every copy ----------------------------------
say "removing per-device state"
rm -f "$ROOTFS"/etc/ssh/ssh_host_*
: > "$ROOTFS/etc/machine-id"
rm -f "$ROOTFS/var/lib/dbus/machine-id"
# mmdebstrap leaves the build host's resolver in place so apt (and the signature
# fetch above) can work. It would otherwise ship the build network's DNS server
# to every device; NetworkManager writes the real one on the first connection.
: > "$ROOTFS/etc/resolv.conf"
# Files, not directories: /var/log/suricata is created by the package, and an
# engine whose log directory is missing exits at once ("error opening file
# /var/log/suricata//suricata.log"). Found by booting the image in a container -
# it left the appliance with no detection at all.
find "$ROOTFS/var/log" -type f -delete
# Not /tmp: mmdebstrap keeps its own apt configuration in there while it works,
# and deleting it makes apt fall back to defaults and fail on every permission.
rm -rf "$ROOTFS"/var/tmp/*
# The apt cache and the package lists are mmdebstrap's job. Clearing them here
# leaves apt without the directories it expects and its own cleanup then fails.
