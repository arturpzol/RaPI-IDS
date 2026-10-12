#!/usr/bin/env bash
# Boot a built image in a virtual machine and check the part a container cannot.
#
#   scripts/test-image-vm.sh [--image FILE] [--disk-gb N] [--ram-mb N]
#                            [--keep] [--console]
#   scripts/test-image-vm.sh --interactive [--bind ADDR] [--fresh] [--nics N]
#   scripts/test-image-vm.sh --ips
#   scripts/test-image-vm.sh --inline
#   scripts/test-image-vm.sh --gui [--demo]
#
# --demo, with --gui, is for the pictures in the README: once the walkthrough
# is over, the guest appends made-up alert events to its own eve.json
# (scripts/demo-alerts.py: real signature names from the installed rules,
# documentation addresses, no traffic), so the screens are photographed with a
# spread of ratings instead of three copies of one test request. After the
# walkthrough, never before, so none of its checks can be met by a made-up
# event.
#
# --gui does what the panel's screens can do, one after another, on the booted
# machine: scripts/gui-walkthrough.py sends the same requests the buttons send
# (account, sign in and out, password, the wizard, alerts, categories, silence
# and allow, rebuild, blocking on and off, rules update, reload, logs, e-mail),
# then scripts/screenshots.py opens every screen in a headless browser and
# checks the layout. A fixture inside the guest makes harmless test traffic for
# the alerts to come from: the request whose user agent SID 2007961 matches.
#
# --inline is the same question asked of the inline layout, where the engine
# does the forwarding itself and NFQUEUE is not involved. The machine gets two
# point-to-point virtual cables instead of user-mode networks, because a user
# network is a NAT of its own and nothing can be sent through the guest from
# one to the other. One end of each cable is a pair port, the other end is moved
# into a network namespace inside the guest: a client on one side, a web server
# on the other. Traffic between them crosses the pair, so it can only arrive if
# something in this device forwards it.
#
# It walks the three states and the two ways between them that four reviews of
# the swap kept finding broken: the kernel bridge (traffic passes, the rule only
# reports), the engine pair (ordinary traffic passes, the matching request does
# not), and the bridge again (the way back carries traffic and blocks nothing).
#
# --ips answers the one question that decides whether any of the blocking work
# is real: does a rule loaded with `drop` actually stop a packet. It puts a
# fixture into the copy - not into the image - that turns SID 2007961 into a
# drop rule, switches the engine to reading a netfilter queue, and then makes
# the same request twice: once plainly, which must still arrive, and once with
# the user agent the rule matches, which must not. The control half matters as
# much as the other: without it a machine with no route out passes the test by
# failing to reach anything.
#
# --interactive runs no checks: it boots the same machine and hands you its
# serial console, which is the appliance's own console. Leave it with Ctrl-A
# then X. The disk is kept and reused, so an account created in the panel is
# still there on the next boot; --fresh starts from the image again.
#
# --nics decides how much of the layout wizard is reachable. With one interface
# only "This device only" is on offer, and correctly so: every other layout
# needs a second port, one for capture and one to reach the panel by. Two makes
# the mirror and bridge layouts selectable, which is the only way to exercise
# the wizard steps that write the capture interface and HOME_NET.
#
# scripts/test-image.sh boots the same image under systemd-nspawn and checks
# everything above the kernel. What it cannot reach is the boot path itself,
# because a container has no kernel, no block device and no partition table. So
# three things went untested there, and one of them - growing the root partition
# to the size of the card - is code that had never executed even once. It was
# broken. This is what found it.
#
# What this adds over the container:
#
#   * the root= line in cmdline.txt actually resolving and mounting,
#   * the root partition growing to the medium, and the filesystem to the
#     partition, on a real partition table on a real block device,
#   * the whole boot on a serial console, which is what a person staring at a
#     headless board through a USB-TTL adapter would see.
#
# What it still cannot reach, and only a card in a real board will tell you:
# the Pi firmware, config.txt, the kernel we actually ship, the initramfs that
# kernel gets, and interface naming.
#
# Why it is not the Pi kernel: QEMU has no Pi 5 machine - the newest board it
# models is raspi4b - so the image has to run on the generic `virt` machine,
# and `linux-image-rpi-2712` is built with no virtio support whatsoever (no
# CONFIG_VIRTIO_* at all, not one module), so on that machine it would find
# neither a disk nor a network. The kernel is therefore Debian's own arm64 one,
# from the same archive as everything else here, booted directly. The root
# filesystem under test is the image's, unmodified.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

IMAGE=""
DISK_GB=4
# Suricata's configuration test runs during the first boot and peaks around
# 1.3 GB with the full rule set loaded. At 2048 the OOM killer took it and the
# first boot never finished, which is a real warning about 2 GB boards but not
# what this script is for.
RAM_MB=4096
KEEP=0
CONSOLE=0
INTERACTIVE=0
FRESH=0
IPS=0
INLINE=0
GUI=0
DEMO=0
NICS=1
HOST_PORT=18443
# SSH into the guest, on the same address as the panel. The guest's rapi takes
# the panel password once an account is created, as on a real card.
SSH_PORT=18022
# Localhost by default: a freshly booted image has no account yet, and whoever
# reaches it first is the one who gets to create it. --bind 0.0.0.0 is for
# opening the panel from a browser on another machine, knowingly.
BIND=127.0.0.1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)   IMAGE="$2"; shift 2 ;;
    --disk-gb) DISK_GB="$2"; shift 2 ;;
    --ram-mb)  RAM_MB="$2"; shift 2 ;;
    --keep)    KEEP=1; shift ;;      # leave the disk image behind afterwards
    --console) CONSOLE=1; shift ;;   # print the whole serial log at the end
    --interactive|-i) INTERACTIVE=1; KEEP=1; shift ;;
    --bind)    BIND="$2"; shift 2 ;;
    --fresh)   FRESH=1; shift ;;     # interactive: start from the image again
    --nics)    NICS="$2"; shift 2 ;;
    --ips)     IPS=1; shift ;;
    --inline)  INLINE=1; shift ;;
    --gui)     GUI=1; shift ;;
    --demo)    DEMO=1; shift ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Each self test takes the engine over, restarts it and changes what it reads.
# Two of them in one machine would each be testing what the other left behind.
if [[ $(( IPS + INLINE + GUI )) -gt 1 ]]; then
  echo "--ips, --inline and --gui each take the engine over: run them one at a time" >&2
  exit 2
fi
# The interactive machine execs QEMU before any check runs, so the walkthrough
# would never start, and the traffic fixture would stay on the kept disk and
# raise test alerts on every later --interactive boot.
if [[ $DEMO -eq 1 && $GUI -eq 0 ]]; then
  echo "--demo only makes sense with --gui: it is the screens that are photographed" >&2
  exit 2
fi
if [[ $INTERACTIVE -eq 1 && $GUI -eq 1 ]]; then
  echo "--gui runs checks and --interactive runs none: pick one" >&2
  exit 2
fi

OUT="${RAPI_IMAGE_OUT:-$ROOT/build}"
if [[ -z "$IMAGE" ]]; then
  IMAGE="$(ls -t "$OUT"/rapi-ids-*.img 2>/dev/null | grep -v -- '-test\.img$' | head -1)"
fi
[[ -f "${IMAGE:-}" ]] || {
  # Worth naming the directory: on a machine where $HOME is not traversable the
  # build has to be told to put the image somewhere else, and then the default
  # here is the one place it certainly is not.
  echo "No image found in $OUT" >&2
  echo "Pass --image FILE, or set RAPI_IMAGE_OUT to the directory build-image.sh" >&2
  echo "was given with --out." >&2
  exit 2
}
command -v qemu-system-aarch64 >/dev/null || {
  echo "qemu-system-aarch64 missing (apt install qemu-system-arm)" >&2; exit 2; }
command -v mkinitramfs >/dev/null || {
  echo "mkinitramfs missing (apt install initramfs-tools)" >&2; exit 2; }

WORK="$OUT/vm-test"
KDIR="$WORK/kernel"
COPY="$WORK/disk.img"
SERIAL="$WORK/serial.log"
MON="$WORK/monitor.sock"
QEMU_PID=""
LOOP=""
PASS=0
FAIL=0

cleanup() {
  [[ -n "$QEMU_PID" ]] && kill -9 "$QEMU_PID" 2>/dev/null
  [[ -n "$LOOP" ]] && sudo losetup -d "$LOOP" 2>/dev/null
  rm -f "$MON"
  if [[ $KEEP -eq 0 ]]; then
    rm -f "$COPY"
  else
    echo
    echo "Disk left at:    $COPY"
    echo "Serial log:      $SERIAL"
  fi
}
trap cleanup EXIT

check() {  # check <description> <command...>
  if "${@:2}" >/dev/null 2>&1; then
    printf '  \033[32mok  \033[0m %s\n' "$1"; PASS=$((PASS + 1))
  else
    printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1))
  fi
}

note() { printf '        %s\n' "$1"; }

# --- a kernel QEMU can boot -------------------------------------------------
# Cached, because it is 130 MB of download and a minute of work, and it changes
# only when Debian ships a new one. The modules are bind-mounted into
# /lib/modules for as long as mkinitramfs needs them and then unmounted, so the
# machine running this keeps nothing it did not have before.
build_kernel() {
  [[ -s "$KDIR/vmlinuz" && -s "$KDIR/initrd.img" ]] && return 0

  echo "==> Fetching Debian's arm64 kernel (cached in $KDIR)"
  rm -rf "$KDIR"; mkdir -p "$KDIR/deb"
  ( cd "$KDIR/deb" && apt-get download linux-image-arm64 >/dev/null 2>&1 ) || {
    echo "could not download linux-image-arm64" >&2; return 1; }
  local versioned
  versioned="$(dpkg-deb -f "$KDIR"/deb/linux-image-arm64_*.deb Depends | tr -d ' ' | cut -d'(' -f1)"
  ( cd "$KDIR/deb" && apt-get download "$versioned" >/dev/null 2>&1 ) || {
    echo "could not download $versioned" >&2; return 1; }
  dpkg-deb -x "$KDIR"/deb/"$versioned"_*.deb "$KDIR/x" || return 1

  local kv
  kv="$(basename "$(echo "$KDIR"/x/boot/vmlinuz-*)")"; kv="${kv#vmlinuz-}"
  cp "$KDIR/x/boot/vmlinuz-$kv" "$KDIR/vmlinuz"
  # mkinitramfs looks for the config beside the modules or in /boot; give it the
  # first so nothing has to be written into this machine's /boot.
  cp "$KDIR/x/boot/config-$kv" "$KDIR/x/usr/lib/modules/$kv/config-$kv"

  # MODULES=dep would build an initramfs for the machine running this - a Pi,
  # with no virtio anything. The guest needs virtio_blk and virtio_pci to find
  # its own root filesystem.
  cp -a /etc/initramfs-tools "$KDIR/conf"
  sed -i 's/^MODULES=.*/MODULES=most/' "$KDIR/conf/initramfs.conf"

  echo "==> Building an initramfs for $kv"
  sudo mkdir -p "/lib/modules/$kv" || return 1
  sudo mount --bind "$KDIR/x/usr/lib/modules/$kv" "/lib/modules/$kv" || return 1
  sudo mkinitramfs -d "$KDIR/conf" -o "$KDIR/initrd.img" "$kv"
  local rc=$?
  sudo umount "/lib/modules/$kv"
  sudo rmdir "/lib/modules/$kv" 2>/dev/null
  return $rc
}

mkdir -p "$WORK"
build_kernel || { echo "could not prepare a kernel to boot with" >&2; exit 2; }

# --- the disk ---------------------------------------------------------------
echo "==> Image: $IMAGE ($(du -h "$IMAGE" | cut -f1))"
if [[ $INTERACTIVE -eq 1 && $FRESH -eq 0 && -s "$COPY" ]]; then
  echo "==> Reusing the disk from the last run (--fresh to start over)"
else
  # Says so because it does not look like work: a gigabyte to the SSD and a
  # sudo for the loop device, both silent, and the first line of the kernel is
  # half a minute away. It reads as a hang.
  echo "==> Copying it to a ${DISK_GB} GB disk (a moment, and sudo for the loop device)"
  cp "$IMAGE" "$COPY"
  # The whole point of the disk being bigger than the image: on a card, the
  # first boot has the rest of the card to grow into. Here it has this.
  truncate -s "${DISK_GB}G" "$COPY"
fi

partition_end() {  # last sector the root partition occupies, in the copy
  sfdisk -d "$COPY" 2>/dev/null \
    | awk -F'[ ,=]+' '/img2|disk\.img2/ {for (i=1;i<NF;i++) if ($i=="start") s=$(i+1);
                                          for (i=1;i<NF;i++) if ($i=="size") z=$(i+1);
                                          print s+z-1; exit}'
}
BEFORE_END="$(partition_end)"
DISK_SECTORS=$(( $(stat -c %s "$COPY") / 512 ))

# The root= string is taken from the image rather than written here, so a wrong
# PARTUUID in cmdline.txt fails this test instead of waiting for a card.
LOOP="$(sudo losetup -Pf --show "$COPY")"
FAT="$(mktemp -d)"
sudo mount -o ro "${LOOP}p1" "$FAT"
ROOT_ARG="$(grep -o 'root=[^ ]*' "$FAT/cmdline.txt")"
sudo umount "$FAT"; rmdir "$FAT"

# --- the answers Raspberry Pi Imager leaves on the card ----------------------
# The basic run boots the card the way a person makes one: written by Imager,
# with its settings file on the boot partition. On the first real card that
# file was never read: the unit that applies it is conditional on the file
# existing, the boot partition is "nofail" in fstab and so not waited for, and
# the condition was tested before the partition was mounted. No hostname, no
# Wi-Fi, no SSH password, and nothing in any log. Every test until then had
# run the script directly, with the directory handed to it.
PRESEED=0
if [[ $(( IPS + INLINE + GUI + INTERACTIVE )) -eq 0 ]]; then
  PRESEED=1
  PRESEED_HOST=rapi-vmtest
  PRESEED_SSID="Example Wi-Fi"
  FAT="$(mktemp -d)"
  sudo mount "${LOOP}p1" "$FAT"
  sudo tee "$FAT/rpi-preseed.toml" >/dev/null <<TOML
config_version = "1.0"

[system]
hostname = "$PRESEED_HOST"

[user]
name = "rapi"
password = "$(openssl passwd -6 "$(head -c 18 /dev/urandom | base64)")"
password_encrypted = true

[ssh]
enabled = true
password_authentication = true

[wlan]
ssid = "$PRESEED_SSID"
password = "example passphrase"
hidden = false
country = "GB"

[locale]
timezone = "Europe/London"
TOML
  sudo umount "$FAT"; rmdir "$FAT"
fi

# The machine boots Debian's generic kernel (see the header) and the image
# carries modules for ours. nf_tables and nfnetlink_queue are modules in that
# kernel, so without this the queue rule is refused with "Unable to initialize
# Netlink socket: Protocol not supported" and --ips cannot reach the thing it
# exists to test; the bridge is a module too, and --inline builds one. 94 MB
# into the 330 MB the image ships free. On a card this never arises: there the
# kernel and its modules are the same pair.
generic_modules_into() {
  local kv
  kv="$(basename "$(echo "$KDIR"/x/boot/vmlinuz-*)")"; kv="${kv#vmlinuz-}"
  # The contents, into the directory: cp -a DIR DIR on a directory that is
  # already there (a kept disk, or two callers in one run) nests it as
  # $kv/$kv, and depmod then sees every module twice.
  sudo mkdir -p "$1/usr/lib/modules/$kv"
  sudo cp -a "$KDIR/x/usr/lib/modules/$kv/." "$1/usr/lib/modules/$kv/"
  sudo depmod -b "$1" "$kv"
}

# The interactive machine needs them as much as the self tests do: without
# them "Detection and blocking" on "This device only" failed in the panel with
# exactly the Netlink error above, which read as a bug in the panel rather than
# in this harness. Copied on every start, so a disk kept from an earlier run
# gets them too (the copy goes into the directory, so repeating it is harmless).
# The run with Imager's settings needs them too: vfat is a module in the
# generic kernel, and without it the boot partition is never mounted at all.
if [[ $INTERACTIVE -eq 1 || $PRESEED -eq 1 ]]; then
  ROOTFS="$(mktemp -d)"
  sudo mount "${LOOP}p2" "$ROOTFS"
  generic_modules_into "$ROOTFS"
  sudo umount "$ROOTFS"; rmdir "$ROOTFS"
fi

# --- the blocking self test, injected into the copy -------------------------
# A fixture, not part of the image, for the same reason test-image.sh writes a
# network profile into its container: the machine has to do something the image
# would never do on its own. Everything below runs once, inside the guest, and
# says what happened on the console - which is the only way out of a machine
# nobody can log into.
if [[ $IPS -eq 1 ]]; then
  echo "==> Putting the blocking self test into the copy"
  ROOTFS="$(mktemp -d)"
  sudo mount "${LOOP}p2" "$ROOTFS"
  sudo tee "$ROOTFS/usr/local/sbin/rapi-ips-selftest" >/dev/null <<'SELFTEST'
#!/bin/sh
# Fixture written by scripts/test-image-vm.sh. Not part of the image.
set -u
DATA=/var/lib/rapi-panel
URL=http://deb.debian.org/debian/
say() { echo "ips-selftest: $*"; }

# python3 rather than curl, because the image does not ship curl and should not
# start shipping one for a test. The panel brings python3 anyway. Plain HTTP on
# purpose: the rule matches a request header, and there is nothing to match
# inside TLS.
reach() {
  python3 - "${1:-}" <<'REQ'
import sys, urllib.request
agent = sys.argv[1] if len(sys.argv) > 1 else ""
request = urllib.request.Request("http://deb.debian.org/debian/")
if agent:
    request.add_header("User-Agent", agent)
try:
    urllib.request.urlopen(request, timeout=25).read(1)
except Exception as problem:
    print(f"    ({type(problem).__name__}: {problem})")
    sys.exit(1)
REQ
}

command -v python3 >/dev/null || { say "SKIP no python3 to make a request with"; exit 0; }

# The panel, not the helper. This used to call rapi-ips-mode directly and
# proved that a drop rule drops, while the path the operator actually takes -
# the button, the API, set_mode, the helper - was only ever run against mocks.
# That is how "Detection and blocking" failing in the panel went unnoticed.
# Everything below goes through https://127.0.0.1/ with a session cookie, the
# same requests the page makes; the panel does its own rule rebuild first.
api() {  # api METHOD PATH [JSON]  -> prints the response body, exit 1 on HTTP error
  python3 - "$@" <<'API'
import json, ssl, sys, urllib.request
method, path = sys.argv[1], sys.argv[2]
body = sys.argv[3].encode() if len(sys.argv) > 3 else None
cookie_file = "/run/rapi-ips-selftest.cookie"
headers = {"Content-Type": "application/json"}
try:
    headers["Cookie"] = open(cookie_file).read().strip()
except OSError:
    pass
request = urllib.request.Request("https://127.0.0.1" + path, data=body,
                                 method=method, headers=headers)
context = ssl._create_unverified_context()   # the device's own CA, on loopback
try:
    with urllib.request.urlopen(request, timeout=600, context=context) as answer:
        for value in answer.headers.get_all("Set-Cookie") or []:
            if value.startswith("rapi_session="):
                open(cookie_file, "w").write(value.split(";", 1)[0])
        sys.stdout.write(answer.read().decode())
except urllib.error.HTTPError as problem:
    print(f"    (HTTP {problem.code}: {problem.read().decode()[:300]})")
    sys.exit(1)
except Exception as problem:
    print(f"    ({type(problem).__name__}: {problem})")
    sys.exit(1)
API
}

# The control comes first on purpose: a machine with no route out would pass
# every "was stopped" check below by failing to reach anything at all, so an
# unreachable internet is "not proven", not a failure of the device.
if reach; then
  say "ok the control request reached the internet"
else
  say "SKIP the control request did not arrive - nothing below would mean anything"
  exit 0
fi

for _ in $(seq 60); do
  api GET /api/auth/state >/dev/null 2>&1 && break
  sleep 2
done
PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
if out=$(api POST /api/auth/setup "{\"username\": \"selftest\", \"password\": \"$PASSWORD\"}"); then
  say "ok the panel account was created through the API"
else
  say "FAIL the panel account could not be created"
  echo "$out" | tail -2
  say "done"   # the host waits for this line; without it, the whole timeout
  exit 0
fi

if out=$(api POST /api/suricata/protection/mode '{"block": true}') \
    && echo "$out" | grep -q '"id": *"ips"'; then
  say "ok the panel switched to blocking"
else
  say "FAIL the panel's own switch did not turn blocking on"
  echo "$out" | tail -3
  say "done"
  exit 0
fi
if grep -q "^drop .*sid:2007961;" /var/lib/suricata/rules/suricata.rules; then
  say "ok 2007961 is loaded with a drop action"
else
  say "FAIL 2007961 is still an alert after the panel's rebuild"
fi
if api GET /api/suricata/protection | grep -q '"capture": *"nfqueue"'; then
  say "ok the engine is reading a netfilter queue"
else
  say "FAIL the panel does not report the engine on the queue"
fi
# The engine has 52 000 rules to load before it answers for a single packet,
# and until it does, `bypass` lets everything through - which would look
# exactly like a rule that does not work.
sleep 25

if reach; then
  say "ok ordinary traffic still passes with the engine in the path"
else
  say "FAIL queue mode stopped traffic that matches nothing"
fi

if reach "wget 3.0"; then
  say "FAIL the request matching a drop rule went through anyway"
else
  say "ok the request matching a drop rule was stopped"
fi

# And back, through the same button: blocking that cannot be turned off from
# the panel is worse than blocking that cannot be turned on.
if out=$(api POST /api/suricata/protection/mode '{"block": false}') \
    && echo "$out" | grep -q '"id": *"ids"'; then
  sleep 25
  if reach "wget 3.0"; then
    say "ok blocking is off again after switching back"
  else
    say "FAIL the matching request is still stopped after switching back"
  fi
else
  say "FAIL the panel's own switch did not turn blocking off"
  echo "$out" | tail -3
fi
say "done"
SELFTEST
  sudo chmod 0755 "$ROOTFS/usr/local/sbin/rapi-ips-selftest"
  sudo tee "$ROOTFS/etc/systemd/system/rapi-ips-selftest.service" >/dev/null <<'UNIT'
[Unit]
Description=Blocking self test (fixture, not part of the image)
After=rapi-panel.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/rapi-ips-selftest
# The console is the only way anything gets out of a machine nobody logs into.
StandardOutput=journal+console

[Install]
WantedBy=multi-user.target
UNIT
  generic_modules_into "$ROOTFS"

  sudo mkdir -p "$ROOTFS/etc/systemd/system/multi-user.target.wants"
  sudo ln -sf /etc/systemd/system/rapi-ips-selftest.service \
    "$ROOTFS/etc/systemd/system/multi-user.target.wants/rapi-ips-selftest.service"
  sudo umount "$ROOTFS"; rmdir "$ROOTFS"
fi

# --- the inline self test, injected into the copy ---------------------------
# The same kind of fixture as the one above, for the layout where the engine
# carries the link. Every card is found by the address given to it on the QEMU
# command line, not by the name the kernel happens to hand out in probe order:
# assuming the order is how this project kept being surprised.
if [[ $INLINE -eq 1 ]]; then
  echo "==> Putting the inline self test into the copy"
  ROOTFS="$(mktemp -d)"
  sudo mount "${LOOP}p2" "$ROOTFS"
  sudo tee "$ROOTFS/usr/local/sbin/rapi-inline-selftest" >/dev/null <<'SELFTEST'
#!/bin/sh
# Fixture written by scripts/test-image-vm.sh. Not part of the image.
set -u
DATA=/var/lib/rapi-panel
say() { echo "inline-selftest: $*"; }

by_mac() {
  for dev in /sys/class/net/*; do
    [ "$(cat "$dev/address" 2>/dev/null)" = "$1" ] && { basename "$dev"; return 0; }
  done
  return 1
}

A="$(by_mac 52:54:00:99:00:01)"      # pair port towards the client
B="$(by_mac 52:54:00:99:00:02)"      # pair port towards the server
CLIENT="$(by_mac 52:54:00:99:00:03)"  # the far end of the first cable
SERVER="$(by_mac 52:54:00:99:00:04)"  # the far end of the second
for name in "$A" "$B" "$CLIENT" "$SERVER"; do
  [ -n "$name" ] || { say "SKIP a card with the expected address is missing"; exit 0; }
done
command -v python3 >/dev/null || { say "SKIP no python3 to make a request with"; exit 0; }

# SID 2007961 is `$HOME_NET any -> $EXTERNAL_NET any`. With both hosts inside
# HOME_NET it can never fire, and every check below would pass or fail for a
# reason that has nothing to do with the swap. So HOME_NET is the client alone.
HOME="[10.99.0.1/32]"

# The far ends leave NetworkManager and this namespace, so nothing but the two
# cables connects them.
for name in "$CLIENT" "$SERVER"; do
  nmcli device set "$name" managed no >/dev/null 2>&1 || true
done
ip netns add client
ip netns add server
ip link set "$CLIENT" netns client
ip link set "$SERVER" netns server
ip -n client link set lo up
ip -n server link set lo up
ip -n client addr add 10.99.0.1/24 dev "$CLIENT"
ip -n server addr add 10.99.0.2/24 dev "$SERVER"
ip -n client link set "$CLIENT" up
ip -n server link set "$SERVER" up
# Checksums finished in software on the hosts' side. A virtio card left to
# offload them can put partial checksums on the cable, which the engine then
# treats as invalid, and ordinary traffic would fail for a reason unrelated to
# anything under test.
ip netns exec client ethtool -K "$CLIENT" tx off >/dev/null 2>&1 || true
ip netns exec server ethtool -K "$SERVER" tx off >/dev/null 2>&1 || true
ip netns exec server python3 -m http.server 80 --bind 10.99.0.2 >/dev/null 2>&1 &

reach() {  # reach [user-agent]
  ip netns exec client python3 - "${1:-}" <<'REQ'
import sys, urllib.request
agent = sys.argv[1]
request = urllib.request.Request("http://10.99.0.2/")
if agent:
    request.add_header("User-Agent", agent)
try:
    urllib.request.urlopen(request, timeout=8).read(1)
except Exception:
    sys.exit(1)
REQ
}

# Until the engine has loaded its rules, a pair forwards nothing at all. So the
# path is waited for, not slept for: a fixed sleep either wastes minutes or
# declares a working pair broken.
wait_for_path() {
  i=0
  while [ $i -lt 60 ]; do
    reach && return 0
    sleep 3; i=$((i + 1))
  done
  return 1
}

eve() {
  dir="$(suricata --dump-config 2>/dev/null | sed -n 's/^default-log-dir = //p' | tail -1)"
  echo "${dir:-/var/log/suricata}/eve.json"
}

swap() {  # swap bridge|pair
  if out=$(/usr/local/sbin/rapi-inline "$1" "$A" "$B" "$HOME" 2>&1); then
    say "ok the swap to $1 went through"
  else
    say "FAIL the swap to $1 was refused or fell back"
    # All of it, and the state NetworkManager had the ports in. A tail of four
    # lines cut away the one reason the last run had.
    echo "$out" | sed 's/^/    /'
    nmcli -t -f DEVICE,STATE,CONNECTION device 2>&1 | sed 's/^/    nm: /'
    ip -br link 2>&1 | sed 's/^/    link: /'
    return 1
  fi
}

[ -f "$DATA/disable.conf" ] || printf '# fixture\n' > "$DATA/disable.conf"
printf '# fixture\n2007961\n' > "$DATA/drop.conf"
if ! out=$(/usr/local/sbin/rapi-rules-update "$DATA/disable.conf" "$DATA/drop.conf" 2>&1); then
  say "FAIL the rule set would not rebuild"
  echo "$out" | tail -3 | sed 's/^/    /'
  exit 0
fi
if grep -q "^drop .*sid:2007961;" /var/lib/suricata/rules/suricata.rules; then
  say "ok 2007961 is loaded with a drop action"
else
  say "FAIL 2007961 is still an alert after the rebuild"
  exit 0
fi

# --- 1. the kernel bridge: traffic passes, the rule reports ------------------
if swap bridge; then
  if wait_for_path; then
    say "ok ordinary traffic crosses the kernel bridge"
  else
    say "FAIL nothing crosses the kernel bridge"
  fi
  # The kernel forwards before the engine has loaded, so the request is repeated
  # until the engine is there to see it, and then the alert has to exist.
  seen=0; i=0
  while [ $i -lt 40 ]; do
    reach "wget 3.0" >/dev/null 2>&1
    sleep 3
    if grep -q '"signature_id":2007961' "$(eve)" 2>/dev/null; then seen=1; break; fi
    i=$((i + 1))
  done
  if reach "wget 3.0"; then
    say "ok the bridge lets the matching request through"
  else
    say "FAIL the bridge stopped a request, and a bridge cannot block"
  fi
  if [ $seen -eq 1 ]; then
    say "ok the engine reported the matching request while only watching"
  else
    say "FAIL no alert for 2007961 while the bridge carried it"
  fi
fi

# --- 2. the engine pair: the same request stops ------------------------------
if swap pair; then
  if wait_for_path; then
    say "ok ordinary traffic crosses the engine pair"
  else
    say "FAIL nothing crosses the engine pair"
  fi
  if reach "wget 3.0"; then
    say "FAIL the request matching a drop rule went through the pair"
  else
    say "ok the request matching a drop rule was stopped by the pair"
  fi
fi

# --- 3. back to the bridge: the way back four reviews found closed -----------
if swap bridge; then
  if wait_for_path; then
    say "ok the way back carries traffic again"
  else
    say "FAIL nothing crosses after going back to the bridge"
  fi
  if reach "wget 3.0"; then
    say "ok blocking is really off after going back"
  else
    say "FAIL the request is still stopped after going back to the bridge"
  fi
fi
say "done"
SELFTEST
  sudo chmod 0755 "$ROOTFS/usr/local/sbin/rapi-inline-selftest"
  sudo tee "$ROOTFS/etc/systemd/system/rapi-inline-selftest.service" >/dev/null <<'UNIT'
[Unit]
Description=Inline blocking self test (fixture, not part of the image)
After=rapi-panel.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/rapi-inline-selftest
StandardOutput=journal+console
# Three swaps, each a full engine restart with the whole rule set, and a wait
# for the path after each. The default oneshot timeout is not that long.
TimeoutStartSec=1800

[Install]
WantedBy=multi-user.target
UNIT
  generic_modules_into "$ROOTFS"
  sudo mkdir -p "$ROOTFS/etc/systemd/system/multi-user.target.wants"
  sudo ln -sf /etc/systemd/system/rapi-inline-selftest.service \
    "$ROOTFS/etc/systemd/system/multi-user.target.wants/rapi-inline-selftest.service"
  sudo umount "$ROOTFS"; rmdir "$ROOTFS"
fi

# --- test traffic for the walkthrough, injected into the copy --------------
# The walkthrough needs alerts to review and a request to see blocked, and the
# image on its own makes neither. Every 20 seconds until the machine is powered
# off, not for a fixed time: without KVM the walkthrough reaches the blocking
# step long after half an hour, and blocking with no traffic left to block
# fails for a reason that has nothing to do with the panel. A plain
# HTTP request with the user agent SID 2007961 matches, and two DNS lookups of
# names the rule set flags. All of it from inside the guest, to the same Debian
# mirror the image updates from; nothing on the host's network is touched.
if [[ $GUI -eq 1 ]]; then
  echo "==> Putting the test traffic into the copy"
  ROOTFS="$(mktemp -d)"
  sudo mount "${LOOP}p2" "$ROOTFS"
  sudo tee "$ROOTFS/usr/local/sbin/rapi-gui-traffic" >/dev/null <<'TRAFFIC'
#!/bin/sh
# Fixture written by scripts/test-image-vm.sh. Not part of the image.
while :; do
  python3 - <<'REQ' 2>/dev/null
import urllib.request
request = urllib.request.Request("http://deb.debian.org/debian/")
request.add_header("User-Agent", "wget 3.0")
try:
    urllib.request.urlopen(request, timeout=15).read(1)
except Exception:
    pass
REQ
  getent hosts example.cc >/dev/null 2>&1
  getent hosts test.duckdns.org >/dev/null 2>&1
  sleep 20
done
TRAFFIC
  sudo chmod 0755 "$ROOTFS/usr/local/sbin/rapi-gui-traffic"
  sudo tee "$ROOTFS/etc/systemd/system/rapi-gui-traffic.service" >/dev/null <<'UNIT'
[Unit]
Description=Test traffic for the GUI walkthrough (fixture, not part of the image)
After=rapi-panel.service network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/rapi-gui-traffic

[Install]
WantedBy=multi-user.target
UNIT
  if [[ $DEMO -eq 1 ]]; then
    # The walkthrough's last change to the engine is moving the logs to
    # /var/log/rapi-walkthrough and back. That directory existing and the
    # override pointing home again is the sign that it is done with the alerts.
    sudo install -m 0755 "$ROOT/scripts/demo-alerts.py" "$ROOTFS/usr/local/sbin/rapi-demo-alerts"
    sudo tee "$ROOTFS/usr/local/sbin/rapi-demo-inject" >/dev/null <<'DEMO'
#!/bin/sh
# Fixture written by scripts/test-image-vm.sh. Not part of the image.
until [ -d /var/log/rapi-walkthrough ] \
    && grep -qs '^default-log-dir: /var/log/suricata$' /etc/suricata/rapi-overrides.yaml; do
  sleep 5
done
# The test traffic has done its job, and its alerts would fill the top of the
# list the screenshot is taken of.
systemctl stop rapi-gui-traffic.service
sleep 30
python3 /usr/local/sbin/rapi-demo-alerts >> /var/log/suricata/eve.json
echo "demo-alerts: done"
DEMO
    sudo chmod 0755 "$ROOTFS/usr/local/sbin/rapi-demo-inject"
    sudo tee "$ROOTFS/etc/systemd/system/rapi-demo-inject.service" >/dev/null <<'UNIT'
[Unit]
Description=Made-up alerts for screenshots (fixture, not part of the image)
After=rapi-panel.service

[Service]
Type=simple
ExecStart=/usr/local/sbin/rapi-demo-inject
StandardOutput=journal+console

[Install]
WantedBy=multi-user.target
UNIT
    sudo mkdir -p "$ROOTFS/etc/systemd/system/multi-user.target.wants"
    sudo ln -sf /etc/systemd/system/rapi-demo-inject.service \
      "$ROOTFS/etc/systemd/system/multi-user.target.wants/rapi-demo-inject.service"
  fi
  generic_modules_into "$ROOTFS"
  sudo mkdir -p "$ROOTFS/etc/systemd/system/multi-user.target.wants"
  sudo ln -sf /etc/systemd/system/rapi-gui-traffic.service \
    "$ROOTFS/etc/systemd/system/multi-user.target.wants/rapi-gui-traffic.service"
  sudo umount "$ROOTFS"; rmdir "$ROOTFS"
fi

sudo losetup -d "$LOOP"; LOOP=""
[[ -n "$ROOT_ARG" ]] || { echo "no root= in the image's cmdline.txt" >&2; exit 1; }

# --- boot -------------------------------------------------------------------
[[ "$NICS" =~ ^[1-4]$ ]] || { echo "--nics takes 1 to 4" >&2; exit 2; }

# The first card carries the forwarded panel port. The rest are there to be
# counted: the wizard decides what a layout needs from what the machine has, and
# a virtio card is "wired" to it for the same reason a USB adapter is - it has a
# device behind it in sysfs and it is not wireless. Each gets its own user-mode
# network so two DHCP servers do not hand out the same address.
NET=(-netdev "user,id=n0,hostfwd=tcp:$BIND:$HOST_PORT-:443,hostfwd=tcp:$BIND:$SSH_PORT-:22" -device virtio-net-pci,netdev=n0)
if [[ $INLINE -eq 1 ]]; then
  # Two cables, each a pair of unix datagram sockets pointed at each other: what
  # one card sends, the other receives, and nothing else is on the wire. No hub,
  # so no card hears its own frames come back, which on a pair port would be the
  # engine forwarding its own output in a loop. No root on this machine either.
  # The addresses are what the guest finds the cards by.
  CABLES="$WORK/cables"
  rm -rf "$CABLES"; mkdir -p "$CABLES"
  cable_end() {  # cable_end <id> <mac> <local> <remote>
    NET+=(-netdev "dgram,id=$1,local.type=unix,local.path=$CABLES/$3,remote.type=unix,remote.path=$CABLES/$4"
          -device "virtio-net-pci,netdev=$1,mac=$2")
  }
  cable_end pa 52:54:00:99:00:01 1a 1b   # pair port A
  cable_end pb 52:54:00:99:00:02 2a 2b   # pair port B
  cable_end cl 52:54:00:99:00:03 1b 1a   # the client, on A's cable
  cable_end sv 52:54:00:99:00:04 2b 2a   # the server, on B's cable
else
  for i in $(seq 2 "$NICS"); do
    NET+=(-netdev "user,id=n$i,net=10.$i.0.0/24,dhcpstart=10.$i.0.15"
          -device "virtio-net-pci,netdev=n$i")
  done
fi

ACCEL=(-cpu cortex-a76 -accel tcg)
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  ACCEL=(-cpu host -accel kvm)
else
  # Not just slower: under emulation the engine took three minutes of CPU to
  # load its rules and systemd killed it on TimeoutStartSec, so the run reports
  # a failed unit that has nothing wrong with it. Say so, because a red result
  # for that reason is worse than no result.
  note "no access to /dev/kvm - emulating, which is about ten times slower"
  note "service start-up timeouts will fire and the result will not be trustworthy"
  note "one-time fix:  sudo adduser $USER kvm   then log in again"
  note "or for one run:  sg kvm -c '''scripts/test-image-vm.sh'''"
fi

if [[ $INTERACTIVE -eq 1 ]]; then
  echo "==> Booting ${DISK_GB} GB disk, ${RAM_MB} MB RAM, $ROOT_ARG"
  echo
  echo "  Panel:    https://$BIND:$HOST_PORT/"
  echo "  SSH:      ssh -p $SSH_PORT rapi@$BIND   (the panel password, once an account exists)"
  if [[ "$BIND" == "0.0.0.0" ]]; then
    echo "            open to the network, and a fresh image has no account:"
    echo "            whoever opens it first is the one who creates one."
  fi
  echo "  Cards:    $NICS"
  [[ "$NICS" -eq 1 ]] && \
    echo "            one card means the wizard offers only \"This device only\";"
  [[ "$NICS" -eq 1 ]] && \
    echo "            --nics 2 makes the mirror and bridge layouts selectable"
  echo "  Console:  right here. Leave the machine with Ctrl-A then X."
  echo "  Login:    only if the image was given a userconf.txt on its FAT"
  echo "            partition; the panel makes its own account in a browser."
  echo
  exec qemu-system-aarch64 \
    -M virt "${ACCEL[@]}" -smp 4 -m "$RAM_MB" \
    -kernel "$KDIR/vmlinuz" -initrd "$KDIR/initrd.img" \
    -append "$ROOT_ARG rootfstype=ext4 rootwait console=ttyAMA0" \
    -drive file="$COPY",format=raw,if=none,id=hd0 -device virtio-blk-pci,drive=hd0 \
    "${NET[@]}" \
    -nographic
fi

echo "==> Booting ${DISK_GB} GB disk, ${RAM_MB} MB RAM, $ROOT_ARG"
rm -f "$SERIAL" "$MON"
qemu-system-aarch64 \
  -M virt "${ACCEL[@]}" -smp 4 -m "$RAM_MB" \
  -kernel "$KDIR/vmlinuz" -initrd "$KDIR/initrd.img" \
  -append "$ROOT_ARG rootfstype=ext4 rootwait console=ttyAMA0 systemd.journald.forward_to_console=1" \
  -drive file="$COPY",format=raw,if=none,id=hd0 -device virtio-blk-pci,drive=hd0 \
  "${NET[@]}" \
  -display none -serial file:"$SERIAL" -monitor unix:"$MON",server,nowait &
QEMU_PID=$!

started=$(date +%s)
for _ in $(seq 300); do
  curl -sk --max-time 2 "https://127.0.0.1:$HOST_PORT/api/auth/state" >/dev/null 2>&1 && break
  kill -0 "$QEMU_PID" 2>/dev/null || break
  sleep 1
done
elapsed=$(( $(date +%s) - started ))

if ! kill -0 "$QEMU_PID" 2>/dev/null; then
  echo "The machine stopped before the panel answered. Last of the console:"
  tail -30 "$SERIAL" | tr -d '\r'
  exit 1
fi

# --- checks while it runs ---------------------------------------------------
echo "==> Checks (panel answered after ${elapsed}s)"
logged() { grep -aq "$1" "$SERIAL"; }

check "the kernel mounted the root named in cmdline.txt" \
      logged "systemd\[1\]:"
check "first boot ran to the end"          logged "first-boot: done"
check "the root partition was grown"       logged "first-boot: growing"
check "no resize step reported a failure"  sh -c "! grep -aqE 'first-boot: (resizepart|resize2fs|growpart) failed' '$SERIAL'"
check "panel answers over HTTPS"           \
      sh -c "curl -sk https://127.0.0.1:$HOST_PORT/api/auth/state | grep -q configured"
# Not with --ips: there the machine creates its own account through the API
# as soon as the panel answers, and whether this question or that request got
# there first is a race, not a property of the image. The basic run asks it.
if [[ $IPS -eq 0 ]]; then
  check "the panel asks for an account"      \
        sh -c "curl -sk https://127.0.0.1:$HOST_PORT/api/auth/state | grep -q '\"configured\":false'"
fi
check "the API is behind the guard"        \
      sh -c "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:$HOST_PORT/api/health | grep -q 401"

# Capitals in the pattern: unit names have them, and without them
# NetworkManager-wait-online was reported as "anager-wait-online", which no
# exception could ever match.
EXPECTED='fake-hwclock-load|systemd-remount-fs'
if [[ $INLINE -eq 1 ]]; then
  # The four cable ends are cards NetworkManager tries DHCP on, and nothing on
  # a cable answers, so waiting for the network to be online times out. That is
  # this fixture's wiring, not the image, and the self test moves two of those
  # cards out of NetworkManager's sight anyway.
  EXPECTED="$EXPECTED|NetworkManager-wait-online"
fi
UNEXPECTED="$(grep -a 'Failed to start' "$SERIAL" | sed 's/\x1b\[[0-9;:]*m//g' \
  | grep -oE '[A-Za-z0-9@._-]+\.service' | sort -u \
  | grep -vE "^($EXPECTED)\.service$" | tr '\n' ' ')"
if [[ -z "$UNEXPECTED" ]]; then
  printf '  \033[32mok  \033[0m no unexpected failed units\n'; PASS=$((PASS + 1))
else
  printf '  \033[31mFAIL\033[0m failed units: %s\n' "$UNEXPECTED"; FAIL=$((FAIL + 1))
fi

# --- did anything actually get dropped --------------------------------------
if [[ $IPS -eq 1 ]]; then
  echo "==> Blocking (the machine testing itself)"
  # Rebuilding 52 000 rules, restarting the engine twice (on and back off
  # through the panel) and requests with a 25 second timeout each. Well over
  # ten minutes on an emulated machine is normal.
  for _ in $(seq 450); do
    grep -aqE "ips-selftest: (done|SKIP)" "$SERIAL" && break
    kill -0 "$QEMU_PID" 2>/dev/null || break
    sleep 2
  done

  if grep -aq "ips-selftest: SKIP" "$SERIAL"; then
    printf '  \033[33m?   \033[0m the self test could not run, so nothing was proven\n'
    note "$(grep -a 'ips-selftest: SKIP' "$SERIAL" | tail -1 | tr -d '\r')"
  elif ! grep -aq "ips-selftest: done" "$SERIAL"; then
    printf '  \033[31mFAIL\033[0m the self test did not finish\n'; FAIL=$((FAIL + 1))
    note "last it said: $(grep -a 'ips-selftest:' "$SERIAL" | tail -1 | tr -d '\r')"
  else
    said() { grep -aq "ips-selftest: ok $1" "$SERIAL"; }
    check "a panel account is created through the API" said "the panel account was created"
    check "the panel's own switch turns blocking on" said "the panel switched to blocking"
    check "the rule set loads 2007961 as a drop"   said "2007961 is loaded"
    check "the engine reads a netfilter queue"     said "the engine is reading"
    # Both halves, and the control is the one that makes the other mean
    # anything: a machine that can reach nothing passes the second on its own.
    check "traffic matching nothing still passes"  said "ordinary traffic still passes"
    check "traffic matching a drop rule is stopped" said "the request matching a drop rule was stopped"
    check "switching back through the panel stops blocking" said "blocking is off again"
  fi
fi

# --- did the engine carry the link, and stop what it should -----------------
if [[ $INLINE -eq 1 ]]; then
  echo "==> Inline blocking (the machine testing itself)"
  # A rule rebuild and three engine restarts with the whole rule set, each
  # followed by a wait for traffic to cross. Well over ten minutes is normal.
  for _ in $(seq 900); do
    grep -aqE "inline-selftest: (done|SKIP)" "$SERIAL" && break
    kill -0 "$QEMU_PID" 2>/dev/null || break
    sleep 2
  done

  if grep -aq "inline-selftest: SKIP" "$SERIAL"; then
    printf '  \033[33m?   \033[0m the self test could not run, so nothing was proven\n'
    note "$(grep -a 'inline-selftest: SKIP' "$SERIAL" | tail -1 | tr -d '\r')"
  elif ! grep -aq "inline-selftest: done" "$SERIAL"; then
    printf '  \033[31mFAIL\033[0m the self test did not finish\n'; FAIL=$((FAIL + 1))
    note "last it said: $(grep -a 'inline-selftest:' "$SERIAL" | tail -1 | tr -d '\r')"
  else
    inline_said() { grep -aq "inline-selftest: ok $1" "$SERIAL"; }
    check "the rule set loads 2007961 as a drop"        inline_said "2007961 is loaded"
    check "the link goes onto the kernel bridge"        inline_said "the swap to bridge went through"
    check "ordinary traffic crosses the bridge"         inline_said "ordinary traffic crosses the kernel bridge"
    # The bridge half matters as much as the pair half: it is what proves the
    # request is one the rule really matches, so that the pair stopping it
    # means something.
    check "the bridge lets the matching request through" inline_said "the bridge lets the matching request through"
    check "the engine reports it while only watching"   inline_said "the engine reported the matching request"
    check "the link goes onto the engine pair"          inline_said "the swap to pair went through"
    check "ordinary traffic crosses the pair"           inline_said "ordinary traffic crosses the engine pair"
    check "the pair stops the matching request"         inline_said "the request matching a drop rule was stopped by the pair"
    check "the way back carries traffic"                inline_said "the way back carries traffic again"
    check "blocking is really off after going back"     inline_said "blocking is really off after going back"
    if grep -aq "inline-selftest: FAIL" "$SERIAL"; then
      # The helper's own words come out as indented lines of the same unit, and
      # every console line starts with the kernel's timestamp, so they are found
      # by what follows the unit name and not by where the line starts.
      tr -d '\r' < "$SERIAL" \
        | grep -aE 'inline-selftest: FAIL|rapi-inline-selftest\[[0-9]+\]:     ' \
        | sed -E 's/^.*rapi-inline-selftest\[[0-9]+\]: //; s/^/        /'
    fi
  fi
fi

# --- every button, from the outside -----------------------------------------
if [[ $GUI -eq 1 ]]; then
  echo "==> Everything the screens can do (scripts/gui-walkthrough.py)"
  # The name a reader expects on a screenshot, and the one most panels have.
  GUI_USER=admin
  GUI_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(18))')"
  GUI_LOG="$WORK/gui-walkthrough.log"
  RAPI_PASS="$GUI_PASS" timeout 3600 python3 "$ROOT/scripts/gui-walkthrough.py" \
    --url "https://127.0.0.1:$HOST_PORT" --user "$GUI_USER" > "$GUI_LOG" 2>&1
  while IFS= read -r line; do
    case "$line" in
      "ok "*)   printf '  \033[32mok  \033[0m %s\n' "${line#ok }"; PASS=$((PASS + 1)) ;;
      "FAIL "*) printf '  \033[31mFAIL\033[0m %s\n' "${line#FAIL }"; FAIL=$((FAIL + 1)) ;;
      "skip "*) printf '  \033[33m?   \033[0m %s\n' "${line#skip }" ;;
      "    "*)  note "${line#    }" ;;
    esac
  done < "$GUI_LOG"
  if ! grep -q '^done$' "$GUI_LOG"; then
    # A traceback is not an "ok" or "FAIL" line, so the loop above shows none
    # of it: say where it is.
    note "the walkthrough stopped early; its whole output: $GUI_LOG"
    tail -5 "$GUI_LOG" | sed 's/^/        /'
  fi
  check "the walkthrough ran to the end" grep -q '^done$' "$GUI_LOG"

  if [[ $DEMO -eq 1 ]]; then
    echo "==> Waiting for the made-up alerts"
    for _ in $(seq 120); do
      grep -aq "demo-alerts: done" "$SERIAL" && break
      sleep 2
    done
    sleep 20   # for the panel to read what was appended
  fi

  echo "==> Every screen in a browser (scripts/screenshots.py)"
  SHOTS="$WORK/screenshots"
  SHOT_PY="$ROOT/backend/.venv/bin/python"
  if [[ -x "$SHOT_PY" ]] && command -v chromium >/dev/null; then
    rm -rf "$SHOTS"
    if RAPI_USER="$GUI_USER" RAPI_PASS="$GUI_PASS" "$SHOT_PY" "$ROOT/scripts/screenshots.py" \
        --url "https://127.0.0.1:$HOST_PORT" --out "$SHOTS" --theme both > "$WORK/screenshots.log" 2>&1; then
      printf '  \033[32mok  \033[0m every screen renders without overflow (%s)\n' "$SHOTS"; PASS=$((PASS + 1))
    else
      printf '  \033[31mFAIL\033[0m the screens: see %s\n' "$WORK/screenshots.log"; FAIL=$((FAIL + 1))
      tail -15 "$WORK/screenshots.log" | sed 's/^/        /'
    fi
  else
    printf '  \033[33m?   \033[0m no backend/.venv or chromium here, the screens were not opened\n'
  fi
fi

# --- shut it down and look at the disk --------------------------------------
# Cleanly, through the monitor, because an ext4 that was cut off mid-write says
# less about whether the resize worked than one that was unmounted properly.
echo "==> Powering down"
python3 - "$MON" <<'EOF' 2>/dev/null
import socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
time.sleep(0.5)
s.sendall(b"system_powerdown\n")
time.sleep(1)
s.close()
EOF
for _ in $(seq 60); do
  kill -0 "$QEMU_PID" 2>/dev/null || break
  sleep 1
done
kill -9 "$QEMU_PID" 2>/dev/null
QEMU_PID=""

AFTER_END="$(partition_end)"
# Within a megabyte of the end of the disk. Not exact equality: sfdisk aligns
# the end of a partition, and how much it leaves depends on the geometry it
# infers, which is not a thing worth pinning a test to.
SLACK=2048
echo "==> Checks on the disk afterwards"
if [[ -n "$AFTER_END" && "$AFTER_END" -gt $(( DISK_SECTORS - SLACK )) ]]; then
  printf '  \033[32mok  \033[0m root partition reaches the end of the disk\n'; PASS=$((PASS + 1))
  note "$(( BEFORE_END * 512 / 1024 / 1024 )) MB -> $(( AFTER_END * 512 / 1024 / 1024 )) MB"
else
  printf '  \033[31mFAIL\033[0m root partition did not grow\n'; FAIL=$((FAIL + 1))
  note "ends at sector ${AFTER_END:-unknown}, the disk has $DISK_SECTORS"
fi

LOOP="$(sudo losetup -Pf --show "$COPY")"
if [[ $PRESEED -eq 1 ]]; then
  # Read off the disk after a clean shutdown, not asked of the running
  # machine: this is what the next boot, and the person holding the card, get.
  FAT="$(mktemp -d)"; AFTER="$(mktemp -d)"
  sudo mount -o ro "${LOOP}p1" "$FAT"
  sudo mount -o ro,noload "${LOOP}p2" "$AFTER"
  check "the Imager settings were read at boot"        logged "imager-config: "
  check "the hostname from Imager is set"              \
        sudo grep -qx "$PRESEED_HOST" "$AFTER/etc/hostname"
  check "the Wi-Fi from Imager is a saved connection"  \
        sudo sh -c "grep -rqs 'ssid=$PRESEED_SSID' '$AFTER/etc/NetworkManager/system-connections/'"
  check "the account password from Imager is in use"   \
        sudo grep -qx "card rapi" "$AFTER/var/lib/rapi-ssh-login"
  check "the settings file is wiped off the card"      test ! -e "$FAT/rpi-preseed.toml"
  sudo umount "$FAT" "$AFTER"; rmdir "$FAT" "$AFTER"
fi
FS_BYTES="$(sudo dumpe2fs -h "${LOOP}p2" 2>/dev/null \
  | awk -F: '/Block count/ {c=$2} /Block size/ {b=$2} END {print c*b}')"
PART_BYTES=$(( (AFTER_END - $(sfdisk -d "$COPY" 2>/dev/null | awk -F'[ ,=]+' '/img2|disk\.img2/ {for (i=1;i<NF;i++) if ($i=="start") print $(i+1); exit}') + 1) * 512 ))
sudo losetup -d "$LOOP"; LOOP=""

# The filesystem never fills the partition exactly - ext4 rounds down to whole
# block groups - so this asks whether it followed, not whether it matched.
if [[ -n "$FS_BYTES" && "$FS_BYTES" -gt $(( PART_BYTES * 95 / 100 )) ]]; then
  printf '  \033[32mok  \033[0m filesystem grew to fill the partition\n'; PASS=$((PASS + 1))
  note "$(( FS_BYTES / 1024 / 1024 )) MB of a $(( PART_BYTES / 1024 / 1024 )) MB partition"
else
  printf '  \033[31mFAIL\033[0m filesystem did not follow the partition\n'; FAIL=$((FAIL + 1))
  note "$(( ${FS_BYTES:-0} / 1024 / 1024 )) MB of a $(( PART_BYTES / 1024 / 1024 )) MB partition"
fi

if [[ $CONSOLE -eq 1 ]]; then
  echo
  echo "==> Serial console"
  tr -d '\r' < "$SERIAL"
fi

echo
if [[ $FAIL -eq 0 ]]; then
  printf '\033[32m%d checks passed.\033[0m The image is fine above the firmware.\n' "$PASS"
  echo "Still only a card in a real board tests: firmware, config.txt, our own"
  echo "kernel and its initramfs, and interface naming."
else
  printf '\033[31m%d of %d checks failed.\033[0m Console: %s\n' "$FAIL" "$((PASS + FAIL))" "$SERIAL"
  echo "Read it with:  tr -d '\\r' < $SERIAL | less"
fi

[[ $FAIL -eq 0 ]]
