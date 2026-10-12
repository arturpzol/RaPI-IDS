#!/usr/bin/env bash
# Build the appliance image: a minimal Debian for the Raspberry Pi 5 with the
# engine, the panel and nothing else.
#
# Why these tools: mmdebstrap and the e2fsprogs/dosfstools/mtools trio are all
# packaged in Debian, so the build needs nothing downloaded from anywhere but
# the archives the appliance itself uses. mmdebstrap also builds unprivileged,
# in a user namespace, so this script must NOT be run as root.
#
# Not rpi-image-gen: it wants bdebstrap, which trixie does not package, and a
# git clone of the tool itself. Not pi-gen: it starts from the Raspberry Pi OS
# package set, which is the opposite of the goal here.
#
#   scripts/build-image.sh [--work DIR] [--out DIR] [--compress] [--no-rules]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="${RAPI_IMAGE_WORK:-$ROOT/build/image-work}"
OUT="${RAPI_IMAGE_OUT:-$ROOT/build}"
SUITE=trixie
ARCH=arm64
BOOT_MB=256
# Free space left in the root filesystem as shipped. The first boot grows it to
# the whole card, so this only has to survive until then.
SLACK_MB=300
COMPRESS=0
FETCH_RULES=1
REUSE=0
MIRROR="http://deb.debian.org/debian"
SECURITY="http://deb.debian.org/debian-security"
RPI="http://archive.raspberrypi.com/debian"
# The identifier is written into the partition table, so root=PARTUUID in
# cmdline.txt and /etc/fstab are true no matter what the image is written to.
DISK_ID=0x52415049

while [[ $# -gt 0 ]]; do
  case "$1" in
    --work)      WORK="$2"; shift 2 ;;
    --out)       OUT="$2"; shift 2 ;;
    --compress)  COMPRESS=1; shift ;;
    --no-rules)  FETCH_RULES=0; shift ;;
    --reuse)     REUSE=1; shift ;;   # keep the root filesystem from the last run
    -h|--help)   sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

die() { echo "build-image: $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] || die "run this as an ordinary user - mmdebstrap unshares its own namespace"
for tool in mmdebstrap mke2fs mkfs.vfat mcopy sfdisk unshare tar; do
  command -v "$tool" >/dev/null || die "$tool missing (apt install mmdebstrap e2fsprogs dosfstools mtools util-linux)"
done
[[ -d frontend/dist/rapi-panel/browser ]] || die "frontend is not built - run scripts/build.sh"
KEYRING_RPI=/usr/share/keyrings/raspberrypi-archive-keyring.pgp
KEYRING_DEB=/usr/share/keyrings/debian-archive-keyring.pgp
[[ -f "$KEYRING_RPI" ]] || die "$KEYRING_RPI missing (apt install raspberrypi-archive-keyring)"
[[ -f "$KEYRING_DEB" ]] || die "$KEYRING_DEB missing (apt install debian-archive-keyring)"

# The build hooks run as a subuid that is nobody here, so every directory on the
# way to the work tree has to be traversable by "other". A checkout in a 0700
# home is the normal case, which is why the work tree defaults elsewhere.
mkdir -p "$WORK"
probe="$(cd "$WORK" && pwd -P)"
while [[ "$probe" != / ]]; do
  [[ "$(stat -c %A "$probe" | cut -c10)" = x ]] \
    || die "$probe is not traversable by other, so the build hooks cannot read the work tree. Pass --work somewhere else (e.g. --work /mnt/ssd/rapi-image)"
  probe="$(dirname "$probe")"
done

STAMP="$(date -u +%Y%m%d)"
IMG="$OUT/rapi-ids-$SUITE-arm64-$STAMP.img"
mkdir -p "$WORK" "$OUT"
if [[ $REUSE -eq 0 ]]; then
  rm -rf "$WORK/rootfs.tar" "$WORK/boot"
fi
# Not $WORK/rootfs: it is owned by subuids from the last run and only the
# namespace can delete it, which is where it is removed.
rm -rf "$WORK/root.ext4" "$WORK/boot.vfat"

# One package per line, comments stripped.
PACKAGES="$(sed -e 's/#.*//' -e '/^\s*$/d' image/packages.list | tr -s '[:space:]' ',' | sed 's/,$//')"
echo "==> Packages: $(tr ',' '\n' <<<"$PACKAGES" | wc -l) named (dependencies come on top)"

# The two archives that need a keyring of their own are added before apt runs.
# Written as .sources files because the appliance keeps them for its updates.
read -r -d '' SETUP_HOOK <<'HOOK' || true
set -e
install -d "$1/usr/share/keyrings" "$1/etc/apt/sources.list.d"
cp /usr/share/keyrings/debian-archive-keyring.pgp "$1/usr/share/keyrings/"
cp /usr/share/keyrings/raspberrypi-archive-keyring.pgp "$1/usr/share/keyrings/"
cat > "$1/etc/apt/sources.list.d/backports.sources" <<EOF
# Suricata 8.x. Priority 100 by default, so nothing else is pulled from here.
Types: deb
URIs: http://deb.debian.org/debian/
Suites: trixie-backports
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.pgp
EOF
cat > "$1/etc/apt/sources.list.d/raspberrypi.sources" <<EOF
# The kernel and the GPU firmware for the Pi 5. Debian's own trixie kernel does
# not boot this board.
Types: deb
URIs: http://archive.raspberrypi.com/debian/
Suites: trixie
Components: main
Signed-By: /usr/share/keyrings/raspberrypi-archive-keyring.pgp
EOF
HOOK

# The hooks run in a user namespace where this user is not mapped at all (uid 0
# inside is a subuid, 100000 here), so a checkout under a 0700 home directory is
# unreadable to them. Everything the hook needs is staged where it can be read.
echo "==> Staging the panel for the build hooks"
rm -rf "$WORK/src"
install -d -m 0755 "$WORK/src"
# The English README, never the Polish one: the image is published too. In
# this repository that is README.en.md; on a public checkout the export has
# already named it README.md. Neither may be missing without ending the build.
OPTIONAL=()
if [[ -f "$ROOT/README.en.md" ]]; then OPTIONAL+=(README.en.md)
elif [[ -f "$ROOT/README.md" ]]; then OPTIONAL+=(README.md); fi
tar -C "$ROOT" -cf - \
    backend/app backend/requirements.txt \
    deploy scripts image \
    frontend/dist/rapi-panel/browser \
    LICENSE \
    "${OPTIONAL[@]}" \
  | tar -C "$WORK/src" -xf -
chmod -R a+rX "$WORK/src"

CUSTOMIZE="PANEL_SRC=$WORK/src FETCH_RULES=$FETCH_RULES $WORK/src/image/customize.sh"

if [[ $REUSE -eq 1 && -f "$WORK/rootfs.tar" ]]; then
  echo "==> Reusing the root filesystem from $WORK/rootfs.tar"
else
echo "==> Building the root filesystem (mmdebstrap, unprivileged)"
mmdebstrap \
  --mode=unshare \
  --variant=minbase \
  --architectures="$ARCH" \
  --components='main contrib non-free-firmware' \
  --aptopt='Apt::Install-Recommends "false"' \
  --dpkgopt='path-exclude=/usr/share/man/*' \
  --dpkgopt='path-exclude=/usr/share/doc/*' \
  --dpkgopt='path-include=/usr/share/doc/*/copyright' \
  --dpkgopt='path-exclude=/usr/share/locale/*' \
  --dpkgopt='path-include=/usr/share/locale/locale.alias' \
  --include="$PACKAGES" \
  --setup-hook="$SETUP_HOOK" \
  --customize-hook="$CUSTOMIZE \"\$1\"" \
  --customize-hook="copy-out /boot/firmware $WORK/boot" \
  --customize-hook='rm -rf "$1"/boot/firmware/* "$1"/boot/vmlinuz* "$1"/boot/initrd.img*' \
  --format=tar \
  "$SUITE" "$WORK/rootfs.tar" \
  "deb $MIRROR $SUITE main contrib non-free-firmware" \
  "deb $MIRROR $SUITE-updates main contrib non-free-firmware" \
  "deb $SECURITY $SUITE-security main contrib non-free-firmware"
fi

echo "==> Boot partition"
# copy-out drops the directory itself into the target, so the files are one
# level down.
BOOTDIR="$WORK/boot/firmware"
install -m 0644 image/config.txt  "$BOOTDIR/config.txt"
install -m 0644 image/cmdline.txt "$BOOTDIR/cmdline.txt"
[[ -f "$BOOTDIR/kernel_2712.img" ]] \
  || die "no Pi 5 kernel on the boot partition - the raspi-firmware hook did not run"

mkfs.vfat -F 32 -n RAPIBOOT -C "$WORK/boot.vfat" $((BOOT_MB * 1024)) >/dev/null
(cd "$BOOTDIR" && mcopy -s -i "$WORK/boot.vfat" ./* ::)
echo "    boot partition: $(du -sh "$BOOTDIR" | cut -f1) of ${BOOT_MB} MiB"

echo "==> Root filesystem image"
# The extraction and mke2fs run inside one namespace: file ownership is only
# meaningful in there, and mke2fs -d writes what it sees.
unshare --user --map-auto --map-root-user --mount \
  sh -ec '
    rm -rf "$1/rootfs"; mkdir -p "$1/rootfs"
    # No device nodes: mknod is refused in a user namespace, and none are
    # needed. The kernel mounts devtmpfs on /dev before userspace starts, so a
    # /dev in the image would be hidden a moment later anyway.
    tar -C "$1/rootfs" --numeric-owner --exclude="./dev/*" -xf "$1/rootfs.tar"
    size=$(du -sm "$1/rootfs" | cut -f1)
    total=$(( size + size / 10 + '"$SLACK_MB"' ))
    echo "    content ${size} MiB, filesystem ${total} MiB"
    mke2fs -q -t ext4 -L RAPIROOT -m 1 -d "$1/rootfs" -F "$1/root.ext4" "${total}M"
  ' -- "$WORK"

echo "==> Partition table"
BOOT_SECTORS=$((BOOT_MB * 2048))
ROOT_SECTORS=$(( $(stat -c %s "$WORK/root.ext4") / 512 ))
START=8192
rm -f "$IMG"
truncate -s $(( (START + BOOT_SECTORS + ROOT_SECTORS) * 512 )) "$IMG"
sfdisk --quiet "$IMG" <<EOF
label: dos
label-id: $DISK_ID
unit: sectors
start=$START, size=$BOOT_SECTORS, type=c, bootable
start=$((START + BOOT_SECTORS)), size=$ROOT_SECTORS, type=83
EOF

dd if="$WORK/boot.vfat" of="$IMG" bs=1M seek=$((START / 2048)) conv=notrunc status=none
dd if="$WORK/root.ext4" of="$IMG" bs=1M seek=$(( (START + BOOT_SECTORS) / 2048 )) conv=notrunc status=none

echo "==> Done: $IMG ($(du -h "$IMG" | cut -f1))"
if [[ $COMPRESS -eq 1 ]]; then
  # Hashed before compressing, so the manifest needs no second pass over a
  # gigabyte of xz to learn what Imager will check the written card against.
  EXTRACT_SIZE=$(stat -c %s "$IMG")
  EXTRACT_SHA=$(sha256sum "$IMG" | cut -d' ' -f1)
  echo "==> Compressing (this takes a while on a Pi)"
  xz -T0 -6 -f "$IMG"
  echo "==> Done: $IMG.xz ($(du -h "$IMG.xz" | cut -f1))"
  # Without it Imager treats the file as "Use custom" and shows no settings,
  # so the Wi-Fi typed into its wizard never reaches the card.
  echo "==> Imager manifest"
  python3 "$ROOT/scripts/imager-manifest.py" "$IMG.xz" \
    --extract-sha256 "$EXTRACT_SHA" --extract-size "$EXTRACT_SIZE"
  install -m 0755 "$ROOT/scripts/imager-manifest.py" "$OUT/imager-manifest.py"
fi

cat <<EOF

Write it with Raspberry Pi Imager 2.0.11 or later: App Options, Content
Repository, "Use custom file", pick $OUT/rapi-ids.rpi-imager-manifest (with
--compress), then "RaPi IDS". Its settings step (Wi-Fi, account, SSH) reaches
the card. Moved the files elsewhere? Run imager-manifest.py next to them again.

Or with:  dd if=$IMG of=/dev/sdX bs=8M status=progress conv=fsync
Before the first boot, to be able to log in over SSH, put on the FAT partition:
  userconf.txt       one line, user:\$(openssl passwd -6)
  authorized_keys    a public key for the rapi account
The panel itself asks for its own account when it is first opened.
EOF
