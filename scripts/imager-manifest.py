#!/usr/bin/env python3
"""Write the Raspberry Pi Imager manifest that offers this image with its wizard.

Imager 2.x shows its settings step (hostname, account, SSH, Wi-Fi, locale) only
for an image a repository manifest describes with an init_format. An image
picked with "Use custom" gets init_format "none" and no settings at all, which
is why the Wi-Fi typed into the wizard never reached the card. This writes a
manifest with init_format "rpi-preseed" (Imager v2.0.11 and later): Imager then
leaves rpi-preseed.toml on the boot partition, and the first boot applies it
(image/first-boot/rapi-imager-config).

    python3 imager-manifest.py rapi-ids-trixie-arm64-YYYYMMDD.img.xz

writes rapi-ids.rpi-imager-manifest next to the image. Imager reads it through
App Options, Content Repository, "Use custom file", or by double-clicking it.
The image is named by an absolute file:// URL, the way Raspberry Pi's own
create_local_json.py does it, so the manifest belongs to the folder it was
written in: moved together with the image, run this again there.

For a release the image is downloaded, not read from a folder:

    python3 imager-manifest.py IMAGE.img.xz \
        --base-url https://github.com/ACCOUNT/REPO/releases/download/v0.5.0 \
        --output release/rapi-ids.rpi-imager-manifest

names the image as BASE-URL/IMAGE.img.xz. Imager fetches the manifest from
the address pasted into it and the image from the address in the manifest, so
both files go into the same release.

Only the standard library, so it runs on the machine with the card reader as
well as on the Pi. The two hashes Imager checks against are computed from the
file; --extract-sha256 and --extract-size let the build pass what it already
knows instead of decompressing a gigabyte again.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import re
import sys
from pathlib import Path

MANIFEST = "rapi-ids.rpi-imager-manifest"
CHUNK = 4 * 1024 * 1024

# The Raspberry Pi 5 entry as the official repository has it. Pi 5 only: the
# kernel in this image is linux-image-rpi-2712.
PI5 = {
    "name": "Raspberry Pi 5",
    "tags": ["pi5-64bit"],
    "description": "Raspberry Pi 5, 500 / 500+, and Compute Module 5",
    "matching_type": "exclusive",
    "capabilities": [],
}


def _sha256(path: Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _extracted_sha256(path: Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with lzma.open(path, "rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def manifest(image: Path, extract_sha256: str | None = None,
             extract_size: int | None = None, base_url: str | None = None) -> dict:
    image = image.resolve()
    download_sha256, download_size = _sha256(image)
    if extract_sha256 is None or extract_size is None:
        extract_sha256, extract_size = _extracted_sha256(image)
    found = re.search(r"(\d{4})(\d{2})(\d{2})", image.name)
    release = "-".join(found.groups()) if found else ""
    entry = {
        "name": "RaPi IDS",
        # A referential phrase ("for") and the acknowledgement, both required
        # by Raspberry Pi's trademark rules (4(i), 4(ii)) wherever the name is
        # used; Imager shows this text under the image.
        "description": ("Suricata IDS/IPS appliance with a web panel, for Raspberry Pi 5. "
                        "Independent project. Raspberry Pi is a trademark of Raspberry Pi Ltd."),
        "url": f"{base_url.rstrip('/')}/{image.name}" if base_url else image.as_uri(),
        "extract_size": extract_size,
        "extract_sha256": extract_sha256,
        "image_download_size": download_size,
        "image_download_sha256": download_sha256,
        "release_date": release,
        "init_format": "rpi-preseed",
        "devices": ["pi5-64bit"],
    }
    return {"imager": {"devices": [PI5]}, "os_list": [entry]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("image", type=Path, help="the .img.xz to describe")
    parser.add_argument("--extract-sha256", help="SHA-256 of the uncompressed image")
    parser.add_argument("--extract-size", type=int, help="size of the uncompressed image")
    parser.add_argument("--base-url",
                        help="where the image will be downloaded from, without the file name")
    parser.add_argument("--output", type=Path,
                        help=f"the manifest to write (default: {MANIFEST} next to the image)")
    args = parser.parse_args()
    if args.base_url and not args.base_url.startswith("https://"):
        # Imager refuses plain HTTP for an image, and a card written from an
        # address anyone on the path can rewrite is not one to boot.
        print("--base-url has to start with https://", file=sys.stderr)
        return 2
    if not args.image.is_file() or args.image.suffix != ".xz":
        print(f"{args.image}: not an .img.xz file", file=sys.stderr)
        return 2
    data = manifest(args.image, args.extract_sha256, args.extract_size, args.base_url)
    out = args.output or args.image.resolve().parent / MANIFEST
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
