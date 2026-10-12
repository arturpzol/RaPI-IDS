#!/usr/bin/env bash
# Boot a built image on this machine and check that it comes up.
#
# The image cannot be booted the way the hardware boots it: QEMU has no Pi 5
# machine and the Pi kernel is built without virtio, so there is nothing to run
# it in. What can be checked without a card is everything above the kernel, and
# that is what this does: the image's own systemd, in a container, with a real
# eth0 handed to it so the engine has an interface and HOME_NET has an address.
#
# Not covered, and only a card in a real board will tell you: firmware,
# config.txt, the initramfs, mounting by PARTUUID, interface naming and the
# partition growing to the medium.
#
#   scripts/test-image.sh [--image FILE] [--keep] [--shell]
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE=""
KEEP=0
SHELL_AFTER=0
MACHINE="rapi-imgtest"
MNT=/mnt/rapi-imgtest
# A link with two ends and no gateway: the container gets an address so the
# first boot has something to derive HOME_NET from, and the panel can be
# reached from here without entering the container's namespace.
HOST_IP=10.66.0.1
GUEST_IP=10.66.0.2
PREFIX=24
VETH=vt-rapi-test
BOOT_TIMEOUT=240

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --keep)  KEEP=1; shift ;;         # leave the container running afterwards
    --shell) SHELL_AFTER=1; shift ;;  # drop into a shell inside it at the end
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$IMAGE" ]]; then
  IMAGE="$(ls -t "${RAPI_IMAGE_OUT:-$ROOT/build}"/rapi-ids-*.img 2>/dev/null | head -1)"
fi
[[ -f "${IMAGE:-}" ]] || {
  echo "No image. Pass --image FILE or set RAPI_IMAGE_OUT to where they are built." >&2
  exit 2
}
command -v systemd-nspawn >/dev/null || {
  echo "systemd-nspawn missing (apt install systemd-container)" >&2; exit 2; }

COPY="${IMAGE%.img}.boot-test.img"
LOOP=""
LOG="$(mktemp /tmp/rapi-imgtest.XXXXXX.log)"
PASS=0
FAIL=0

cleanup() {
  if [[ $KEEP -eq 1 ]]; then
    echo
    echo "Left running. Enter it with:  sudo machinectl shell $MACHINE"
    echo "Stop and clean up with:       sudo machinectl terminate $MACHINE;"
    echo "                              sudo umount $MNT/boot/firmware $MNT;"
    echo "                              sudo losetup -d $LOOP; rm -f $COPY"
    return
  fi
  sudo machinectl terminate "$MACHINE" 2>/dev/null
  sleep 2
  sudo umount "$MNT/boot/firmware" "$MNT" 2>/dev/null
  [[ -n "$LOOP" ]] && sudo losetup -d "$LOOP" 2>/dev/null
  sudo rmdir "$MNT" 2>/dev/null
  rm -f "$COPY"
}
trap cleanup EXIT

check() {  # check <description> <command...>
  if "${@:2}" >/dev/null 2>&1; then
    printf '  \033[32mok  \033[0m %s\n' "$1"; PASS=$((PASS + 1))
  else
    printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1))
  fi
}

echo "==> Image: $IMAGE ($(du -h "$IMAGE" | cut -f1))"
# On a copy: the first boot writes host keys, a certificate and an account into
# it, and a tested image must stay the image that gets shipped.
cp "$IMAGE" "$COPY"

LOOP="$(sudo losetup -Pf --show "$COPY")"
sudo mkdir -p "$MNT"
sudo mount "${LOOP}p2" "$MNT"
sudo mount "${LOOP}p1" "$MNT/boot/firmware"

# A fixture, not part of the image: the test network has no DHCP server, and
# without an address the first boot cannot work out HOME_NET - the one step
# worth watching here.
sudo install -d -m 0755 "$MNT/etc/NetworkManager/system-connections"
sudo tee "$MNT/etc/NetworkManager/system-connections/eth0-test.nmconnection" >/dev/null <<EOF
[connection]
id=eth0-test
type=ethernet
interface-name=eth0
[ipv4]
method=manual
address1=$GUEST_IP/$PREFIX
[ipv6]
method=ignore
EOF
sudo chmod 0600 "$MNT/etc/NetworkManager/system-connections/eth0-test.nmconnection"

# What the official flashing tool leaves on the card when somebody answers its
# wizard. Put here rather than described in a unit test, because the question
# this answers is whether the unit runs at all, early enough, on the real image.
# Invented values: nothing of the machine that built the image belongs in it.
sudo tee "$MNT/boot/firmware/custom.toml" >/dev/null <<'EOF'
[system]
hostname = "ids-example"

[ssh]
enabled = true

[wlan]
ssid = "Example Wi-Fi"
password = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
hidden = false
country = "PL"

[locale]
timezone = "Europe/Warsaw"
EOF

echo "==> Booting it as a container (log: $LOG)"
sudo systemd-nspawn -D "$MNT" --machine="$MACHINE" --boot \
  --private-network --network-veth-extra="$VETH:eth0" \
  >"$LOG" 2>&1 &

# The host end of the link exists as soon as nspawn has set it up.
for _ in $(seq 30); do
  ip link show "$VETH" >/dev/null 2>&1 && break
  sleep 1
done
sudo ip addr add "$HOST_IP/$PREFIX" dev "$VETH" 2>/dev/null
sudo ip link set "$VETH" up 2>/dev/null

started=$(date +%s)
for _ in $(seq "$BOOT_TIMEOUT"); do
  curl -sk --max-time 2 "https://$GUEST_IP/api/auth/state" >/dev/null 2>&1 && break
  sleep 1
done
elapsed=$(( $(date +%s) - started ))

PID="$(sudo machinectl show "$MACHINE" -p Leader --value 2>/dev/null)"
if [[ -z "$PID" ]]; then
  echo "The container did not start at all. Last lines of the log:"
  tail -20 "$LOG"
  exit 1
fi
inside() { sudo nsenter -t "$PID" -a "$@"; }

echo "==> Checks (panel answered after ${elapsed}s)"
check "first boot finished"        inside systemctl is-active --quiet rapi-first-boot
check "panel is running"           inside systemctl is-active --quiet rapi-panel
check "engine is running"          inside systemctl is-active --quiet suricata
check "ssh is running"             inside systemctl is-active --quiet ssh
check "panel answers over HTTPS"   sh -c "curl -sk https://$GUEST_IP/api/auth/state | grep -q configured"
check "port 80 redirects to HTTPS" sh -c "curl -s -o /dev/null -w '%{redirect_url}' http://$GUEST_IP/ | grep -q '^https://'"
check "the panel asks for an account" \
                                   sh -c "curl -sk https://$GUEST_IP/api/auth/state | grep -q '\"configured\":false'"
check "the API is behind the guard" \
                                   sh -c "curl -sk -o /dev/null -w '%{http_code}' https://$GUEST_IP/api/health | grep -q 401"
check "certificate issued on the device" \
                                   inside test -s /var/lib/rapi-panel/tls/server.crt
check "CA left on the boot partition" \
                                   inside test -s /boot/firmware/rapi-ca.crt
check "host keys generated here"   inside sh -c 'ls /etc/ssh/ssh_host_ed25519_key >/dev/null'
check "HOME_NET follows the machine" \
                                   inside grep -q "HOME_NET follows this machine" /etc/suricata/suricata.yaml
check "engine loaded the signatures" \
                                   inside grep -q "rules successfully loaded" /var/log/suricata/suricata.log

# The Emerging Threats rules are BSD: redistributing them in binary form is
# free, and asks that the notice go with them. suricata-update merges the rules
# into one file and leaves the licence inside the archive it cached, in a
# root-only directory - so shipping an image without this step distributes
# 68 000 BSD rules with no notice a person could find.
# The flashing tool's wizard. Three files, because the three answers land in
# three places and any one of them alone is a device somebody cannot reach.
check "the wizard's hostname was applied" \
  inside sh -c 'grep -qx ids-example /etc/hostname && grep -q "127.0.1.1[[:space:]]*ids-example" /etc/hosts'
# The file name is scrubbed of anything that could steer a path; the SSID
# itself lives inside the file.
check "the wizard's wireless network was written" \
  inside sh -c 'grep -q "ssid=Example Wi-Fi" /etc/NetworkManager/system-connections/Example_Wi-Fi.nmconnection'
check "the wireless backend is installed" \
  inside sh -c 'command -v wpa_supplicant >/dev/null && test -d /lib/firmware/brcm'
check "the wizard's file is gone from the card" \
  inside sh -c '! test -e /boot/firmware/custom.toml'

check "the rule licence travels with the rules" \
                                   inside grep -q "BSD License" /usr/share/doc/emerging-threats-rules/LICENSE

# Two units cannot work in a container and their failure says nothing about the
# image: the clock cannot be set without CAP_SYS_TIME and / cannot be remounted.
UNEXPECTED="$(inside systemctl list-units --state=failed --no-legend --plain 2>/dev/null \
  | awk '{print $1}' | grep -vE '^(fake-hwclock-load|systemd-remount-fs)\.service$')"
if [[ -z "$UNEXPECTED" ]]; then
  printf '  \033[32mok  \033[0m no unexpected failed units\n'; PASS=$((PASS + 1))
else
  printf '  \033[31mFAIL\033[0m failed units: %s\n' "$(echo "$UNEXPECTED" | tr '\n' ' ')"
  FAIL=$((FAIL + 1))
fi

echo
if [[ $FAIL -eq 0 ]]; then
  printf '\033[32m%d checks passed.\033[0m The image is fine above the kernel.\n' "$PASS"
else
  printf '\033[31m%d of %d checks failed.\033[0m Boot log: %s\n' "$FAIL" "$((PASS + FAIL))" "$LOG"
  echo "Look inside with:  sudo nsenter -t $PID -a journalctl -b --no-pager | tail -40"
fi

if [[ $SHELL_AFTER -eq 1 ]]; then
  echo
  echo "Dropping into the container. Leave it with Ctrl+D."
  sudo machinectl shell "$MACHINE" || sudo nsenter -t "$PID" -a /bin/bash
fi

[[ $FAIL -eq 0 ]]
