#!/usr/bin/env bash
# Everything that must happen on the device rather than in the image.
#
# Three kinds of work live here:
#   1. things that are wrong to bake into an image at all (host keys, the TLS
#      certificate, the machine id) because every copy of the image would share
#      them,
#   2. things that depend on the card or disk the image was written to (the size
#      of the root filesystem),
#   3. things that depend on the network the device was plugged into (HOME_NET,
#      which decides whether 88 % of the rules can ever match).
#
# Runs once, as root, before the panel starts. Idempotent anyway: a half-finished
# first boot (power cut) is repeated on the next one.
set -uo pipefail

PANEL_ROOT=/opt/rapi-panel
DATA_DIR=/var/lib/rapi-panel
STAMP="$DATA_DIR/.first-boot-done"
BOOT=/boot/firmware

log() { echo "first-boot: $*"; }

# --- 1. the root filesystem is as small as the build made it ----------------
grow_root() {
  local source dev part
  source="$(findmnt -no SOURCE /)" || return 0
  # lsblk rather than string surgery on the device name: mmcblk0p2, sda2 and
  # nvme0n1p2 all split differently, and a card that boots from a reader the
  # pattern list has never seen is exactly when this must not give up.
  dev="/dev/$(lsblk -no PKNAME "$source" 2>/dev/null)"
  part="$(cat "/sys/class/block/${source##*/}/partition" 2>/dev/null)"
  if [[ ! -b "$dev" || -z "$part" ]]; then
    log "cannot tell which disk $source is on, not resizing"
    return 0
  fi
  # growpart rather than parted. The partition being grown is the mounted root,
  # and `parted resizepart` treats that as a question for a human: it printed
  # "Partition /dev/vda2 is being used. Are you sure you want to continue?" and
  # gave up. So this step had never once succeeded - not on a card either, where
  # the root is just as mounted. growpart rewrites the table with sfdisk and
  # tells the running kernel with partx, both of which work on a partition in
  # use, and it is idempotent: exit 1 is its "nothing to do", which is the
  # normal case on every boot after the first.
  log "growing $source to the end of $dev"
  local grown=0
  growpart "$dev" "$part" 2>&1 | sed 's/^/first-boot: /' || grown=$?
  (( grown == 0 )) || log "the partition already reaches the end of the disk"
  # ext4 grows online, so this resizes the filesystem it is running from.
  resize2fs "$source" 2>&1 | sed 's/^/first-boot: /' || log "resize2fs failed"
}

# --- 2. secrets must not be shared by every copy of the image ---------------
ssh_host_keys() {
  # The image ships without them precisely so that two devices from the same
  # image cannot be impersonated by each other.
  if ! ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1; then
    log "generating SSH host keys"
    ssh-keygen -A
  fi
}

# --- 3. the operator's way in, handed over on the boot partition -------------
# The image has no account with a password: whoever powers it up first would
# otherwise own it. Someone with physical access to the card can put a password
# hash (userconf.txt, the format Raspberry Pi Imager writes) or an SSH key on the
# FAT partition, which is readable from any machine.
apply_userconf() {
  if [[ -f "$BOOT/userconf.txt" ]]; then
    local line user hash
    line="$(grep -v '^\s*#' "$BOOT/userconf.txt" | grep ':' | head -1)"
    user="${line%%:*}"
    hash="${line#*:}"
    if [[ -n "$user" && -n "$hash" ]]; then
      id -u "$user" >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo "$user"
      log "setting the password for $user from userconf.txt"
      # Recorded so the panel leaves it alone: the password that came with the
      # card stays the SSH password. See deploy/rapi-login-password.
      # Sudo goes with a password from the card, and only with that: the panel
      # never sees it and cannot change it, so it is the one safe way to root.
      # rapi included, when the card names it; the image leaves rapi without.
      usermod -p "$hash" "$user" && printf 'card %s\n' "$user" > /var/lib/rapi-ssh-login \
        && usermod -aG sudo "$user"
    fi
    shred -u "$BOOT/userconf.txt" 2>/dev/null || rm -f "$BOOT/userconf.txt"
  fi

  if [[ -f "$BOOT/authorized_keys" ]]; then
    log "installing authorized_keys for rapi"
    install -d -m 0700 -o rapi -g rapi /home/rapi/.ssh
    install -m 0600 -o rapi -g rapi "$BOOT/authorized_keys" /home/rapi/.ssh/authorized_keys
    # Keys and no password: whoever prepared the card chose keys, so the panel
    # must not add a password. A password from userconf.txt above wins.
    if ! grep -q '^card ' /var/lib/rapi-ssh-login 2>/dev/null; then
      printf 'key rapi\n' > /var/lib/rapi-ssh-login
    fi
    rm -f "$BOOT/authorized_keys"
  fi
}

# --- 4. engine configuration that depends on this network -------------------
wire_engine() {
  log "wiring the engine override and HOME_NET"
  RAPI_SURICATA_YAML=/etc/suricata/suricata.yaml RAPI_PANEL_USER=rapi \
    "$PANEL_ROOT/scripts/setup-suricata-override.sh" 2>&1 | sed 's/^/first-boot: /'
}

# --- 5. TLS material, one CA per device -------------------------------------
issue_tls() {
  local tls="$DATA_DIR/tls"
  log "issuing the panel certificate"
  RAPI_TLS_DIR="$tls" "$PANEL_ROOT/scripts/setup-tls.sh" 2>&1 \
    | sed 's/^/first-boot: /' || return 1
  # The panel serves with the server pair and nothing else. The CA key stays
  # root's: it signs certificates every machine that imported ca.crt trusts,
  # so a panel process taken over must not be able to mint one. This used to
  # be a chown -R of the whole directory to the panel's account.
  chown root:rapi "$tls" && chmod 0750 "$tls" || return 1
  chown root:root "$tls/ca.key" && chmod 0600 "$tls/ca.key" || return 1
  [[ -e "$tls/ca.srl" ]] && { chown root:root "$tls/ca.srl"; chmod 0600 "$tls/ca.srl"; }
  chown rapi:rapi "$tls/server.key" && chmod 0600 "$tls/server.key" || return 1
  chown root:root "$tls/ca.crt" "$tls/server.crt" \
    && chmod 0644 "$tls/ca.crt" "$tls/server.crt" || return 1
  # The CA certificate is public by definition and the operator needs it on
  # their own machine, so it is left where a card reader can reach it.
  install -m 0644 "$DATA_DIR/tls/ca.crt" "$BOOT/rapi-ca.crt" 2>/dev/null || true
}

# A step that fails leaves the stamp unwritten and the unit failed, so the next
# boot runs all of this again (every step is safe to repeat) and
# `systemctl --failed` names it. The stamp used to be written whatever
# happened: a certificate that was never issued stayed missing for the life of
# the card, and the panel, which cannot start without it, restarted forever.
# The resize is the exception, as before: a card that cannot grow still works.
failed=()
step() { "$@" || { log "$1 failed"; failed+=("$1"); }; }

grow_root
step ssh_host_keys
step apply_userconf
step wire_engine
step issue_tls
install -d -o rapi -g rapi "$DATA_DIR"

# What the panel and the engine need, checked rather than assumed from the
# steps' exit codes: a pipe through sed can hide a failure on older bash.
[[ -s "$DATA_DIR/tls/server.crt" && -s "$DATA_DIR/tls/server.key" ]] \
  || failed+=("no panel certificate")
# Named anywhere in suricata.yaml: the include starts as one line and is later
# rewritten into a list by rapi-include, and both forms are wired.
grep -q '/etc/suricata/rapi-overrides.yaml' /etc/suricata/suricata.yaml \
  || failed+=("engine override not wired")

if (( ${#failed[@]} )); then
  log "not finished, will run again on the next boot: ${failed[*]}"
  exit 1
fi
: > "$STAMP"
log "done"
