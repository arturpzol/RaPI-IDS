"""Where the engine writes its logs - directory choice (e.g. USB stick instead
of the SD card).

How it works: the packaged `/etc/suricata/suricata.yaml` is **left alone**. A
single `include:` line pointing at the panel override file is appended to it
once (see scripts/setup-suricata-override.sh). The panel writes exactly one key
in that override - `default-log-dir` - and values from a later include win.

Two constraints come from the engine systemd unit (`ProtectHome=true`,
`ProtectSystem=full`): it cannot see home directories and cannot write to /etc
or /usr. The panel checks both before saving, so it never takes the service down.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import psutil

from ... import config, settings

log = logging.getLogger(__name__)

SURICATA_YAML = Path(os.environ.get("RAPI_SURICATA_YAML", "/etc/suricata/suricata.yaml"))
# Long enough for the engine to load the whole rule set on a Pi, and the same
# number the other restart paths use.
RESTART_TIMEOUT = 180

OVERRIDE_PATH = Path(
    os.environ.get("RAPI_SURICATA_OVERRIDE", "/etc/suricata/rapi-overrides.yaml")
)

# The engine requires this header in every configuration file.
YAML_HEADER = "%YAML 1.1\n---\n"

# Where logrotate keeps its per-package configuration. A constant, not a literal
# in the function below, so the rotation check can be pointed at a fixture.
LOGROTATE_DIR = Path(os.environ.get("RAPI_LOGROTATE_DIR", "/etc/logrotate.d"))

# Directories the engine cannot write to (systemd unit), or where logs simply
# have no business being. Checked after resolving symlinks.
FORBIDDEN = (
    "/home", "/root", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/boot", "/proc", "/sys", "/dev", "/run", "/var/lib", "/snap",
)


def _resolve(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def forbidden_reason(path: Path) -> str | None:
    """Why this directory cannot be used, or None when it is fine."""
    text = str(path)
    if not path.is_absolute():
        return "the path has to be absolute"
    for bad in FORBIDDEN:
        if text == bad or text.startswith(bad + "/"):
            if bad in ("/home", "/root"):
                return (
                    "the engine runs with ProtectHome=true in its systemd unit, so "
                    "it cannot see home directories"
                )
            return f"{bad} is no place for logs (or the engine cannot write there)"
    return None


# --- configuration state ---


def include_wired() -> bool:
    """Whether suricata.yaml includes the panel override file.

    Two spellings, because the engine changed its mind about the first. A file
    used to be wired in with its own `include:` line; several of those at the
    same level are deprecated ("will not work in Suricata 8", said by Suricata
    8), so deploy/rapi-include now keeps one array of them. Devices set up
    before that carry the old form and are not rewritten until something
    regenerates the configuration, so both have to be recognised.
    """
    try:
        text = SURICATA_YAML.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    path = re.escape(str(OVERRIDE_PATH))
    return bool(
        re.search(rf"^\s*include:\s*{path}\s*$", text, re.M)
        or re.search(rf"^\s*-\s*{path}\s*$", text, re.M)
    )


def override_writable() -> bool:
    return os.access(OVERRIDE_PATH, os.W_OK)


def configured_dir() -> Path | None:
    """Directory set by the panel (from the override file), if any."""
    try:
        text = OVERRIDE_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = re.search(r"^\s*default-log-dir:\s*(\S+)\s*$", text, re.M)
    return Path(match.group(1)) if match else None


def engine_dir() -> Path:
    """Directory the engine actually uses (override beats the packaged file)."""
    if include_wired():
        configured = configured_dir()
        if configured:
            return configured
    try:
        text = SURICATA_YAML.read_text(encoding="utf-8", errors="replace")
        match = re.search(r"^default-log-dir:\s*(\S+)\s*$", text, re.M)
        if match:
            return Path(match.group(1))
    except OSError:
        pass
    return config.EVE_PATH.parent


# --- where the logs could go instead ---

FSTAB = Path(os.environ.get("RAPI_FSTAB", "/etc/fstab"))

# Mount points that are storage in name only. /boot/firmware is the one that
# actually turns up on a Pi: a small VFAT partition the bootloader reads, which
# would fill in a day and take the machine down with it.
SKIP_MOUNTS = ("/boot", "/run", "/dev", "/sys", "/proc", "/snap", "/var/lib")

# Filesystems that cannot hold a growing log, or lose it on reboot.
SKIP_FSTYPES = ("tmpfs", "devtmpfs", "squashfs", "overlay", "iso9660", "vfat",
                "msdos", "exfat", "ramfs")

# Under a volume, not at its root: a mount point usually has lost+found and
# whatever else the disk was used for, and dropping eve.json among it makes the
# directory hard to recognise later.
LOG_SUBDIR = "suricata"


def _fstab_mounts() -> set[str]:
    """Mount points /etc/fstab will restore on the next boot."""
    mounts: set[str] = set()
    try:
        text = FSTAB.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return mounts
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        fields = line.split()
        if len(fields) >= 2 and fields[1].startswith("/"):
            mounts.add(fields[1].rstrip("/") or "/")
    return mounts


def candidates() -> list[dict[str, Any]]:
    """Mounted volumes that could hold the logs, best first.

    This module used to refuse to suggest anything, on the grounds that what is
    mounted now says nothing about what will be mounted after a reboot, and a
    suggestion reads as a recommendation. The objection was right and the answer
    was wrong: the fix is to check `/etc/fstab` and say which volumes will still
    be there, not to leave the operator typing paths. A volume that is mounted
    by hand is still offered - with `persistent` false, because a log directory
    that disappears on reboot leaves the engine writing to the mount point on
    the card instead, silently, which is exactly the failure worth naming.
    """
    current = _resolve(engine_dir())
    try:
        root_dev = os.stat("/").st_dev
    except OSError:
        root_dev = None

    persistent = _fstab_mounts()
    out: list[dict[str, Any]] = []
    for part in psutil.disk_partitions(all=False):
        mount = part.mountpoint.rstrip("/") or "/"
        if part.fstype in SKIP_FSTYPES:
            continue
        if any(mount == bad or mount.startswith(bad + "/") for bad in SKIP_MOUNTS):
            continue
        if "ro" in part.opts.split(","):
            continue
        # The card the system runs from is the thing we are trying to move off.
        try:
            if root_dev is not None and os.stat(mount).st_dev == root_dev:
                continue
        except OSError:
            continue
        if forbidden_reason(Path(mount)):
            continue

        target = Path(mount) / LOG_SUBDIR
        usage = _disk(Path(mount))
        out.append({
            "path": str(target),
            "mount": mount,
            "device": part.device,
            "fstype": part.fstype,
            "free": usage["free"],
            "total": usage["total"],
            "persistent": mount in persistent,
            # "already here" means the same volume, not the same path. Whether
            # the directory is called suricata or suricata3 is nobody's
            # business; whether the writes are off the card is the question.
            "current": current == Path(mount) or Path(mount) in current.parents,
        })
    out.sort(key=lambda c: (-c["persistent"], -c["free"]))
    return out


def on_root_filesystem(directory: Path) -> bool:
    """Whether the logs sit on the same volume the system boots from.

    Which is the whole question this screen exists to answer: events are the
    most frequent writes on the device, and on a Pi that volume is usually an
    SD card with a finite number of them.
    """
    try:
        return os.stat(directory).st_dev == os.stat("/").st_dev
    except OSError:
        return False


# --- what is there now ---


def _disk(path: Path) -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(path)
        return {
            "total": usage.total,
            "free": usage.free,
            "used": usage.used,
            "percent": round(usage.used / usage.total * 100, 1) if usage.total else 0.0,
        }
    except OSError:
        return {"total": 0, "free": 0, "used": 0, "percent": 0.0}


def files() -> list[dict[str, Any]]:
    """What currently sits in the engine log directory and how big it is."""
    directory = engine_dir()
    out: list[dict[str, Any]] = []
    try:
        entries = sorted(directory.iterdir())
    except OSError:
        return out
    for entry in entries:
        try:
            st = entry.stat()
        except OSError:
            continue
        if entry.is_file():
            out.append({"name": entry.name, "size_bytes": st.st_size, "modified": st.st_mtime})
    return out


# The same pattern the root-side helper enforces (deploy/rapi-log-dir).
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")

LOG_DIR_HELPER = "/usr/local/sbin/rapi-log-dir"


def prepare_dir(directory: Path) -> tuple[bool, str]:
    """Create the directory and set up its rotation, through a root-side helper.

    Two jobs, one helper, because the panel can do neither. logrotate ignores
    configuration files not owned by root, and a disk mounted at /mnt/ssd
    belongs to root, so an unprivileged mkdir inside it fails. The panel used to
    answer that second one by printing a `sudo mkdir` line for the operator to
    paste into a shell, which on a device that promises no shell is not an error
    message but a broken feature.

    The panel passes only a path, and one that has already been validated on
    both sides: a logrotate file may carry a section executed as root.
    """
    if not Path(LOG_DIR_HELPER).exists():
        return False, f"{LOG_DIR_HELPER} is missing. Run scripts/setup-suricata-override.sh"
    try:
        proc = subprocess.run(
            ["sudo", "-n", LOG_DIR_HELPER, str(directory)],
            capture_output=True, text=True, timeout=60,
        )
    except (subprocess.SubprocessError, OSError) as err:
        return False, str(err)
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


def rotation_covered(directory: Path) -> bool:
    """Whether any logrotate entry covers eve.json in this directory.

    Once logs move outside /var/log/suricata the packaged rotation stops
    applying and eve.json grows without bound - better to say so out loud.
    """
    probe = directory / config.EVE_PATH.name
    for conf in sorted(LOGROTATE_DIR.glob("*")):
        try:
            text = conf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for block in text.split("}"):
            head = block.split("{", 1)[0]
            for token in head.split():
                if not token.startswith("/"):
                    continue
                try:
                    if probe.full_match(token):   # Python 3.13: * does not cross /
                        return True
                except AttributeError:            # older Pythons
                    if fnmatch(str(probe), token):
                        return True
    return False


def status() -> dict[str, Any]:
    directory = engine_dir()
    panel_dir = settings.log_dir()
    warnings: list[str] = []
    if not rotation_covered(directory):
        warnings.append(
            f"no logrotate entry covers {directory}, so the logs will grow without "
            "bound. Saving the directory from the panel adds an entry for it."
        )
    if not include_wired():
        warnings.append(
            "suricata.yaml does not include the panel override file. Run "
            "scripts/setup-suricata-override.sh to change the directory from the panel."
        )
    elif not override_writable():
        warnings.append(
            f"the panel cannot write to {OVERRIDE_PATH}. Fix the file owner."
        )
    if _resolve(panel_dir) != _resolve(directory):
        warnings.append(
            f"the panel reads events from {panel_dir}, but the engine writes to {directory}."
        )
    return {
        "log_dir": str(directory),
        "panel_reads_from": str(settings.eve_path()),
        "can_change": include_wired() and override_writable(),
        "warnings": warnings,
        "disk": _disk(directory if directory.exists() else Path("/")),
        "files": files(),
        "on_root": on_root_filesystem(directory),
        "candidates": candidates(),
    }


# --- changing the directory ---


def set_dir(path: str) -> dict[str, Any]:
    """Move the engine log directory and point the panel reader at it.

    Returns a dict describing what happened. A ValueError means the user made an
    invalid choice (as opposed to something in the system failing).
    """
    target = _resolve(path)
    reason = forbidden_reason(target)
    if reason:
        raise ValueError(reason)
    # fullmatch, not match: in Python '$' also matches just before a trailing
    # newline, so '/mnt/x\n' used to get through the pattern.
    if not SAFE_PATH_RE.fullmatch(str(target)):
        raise ValueError(
            "the path may only contain letters, digits and . _ - /"
        )
    if not include_wired():
        raise ValueError(
            "suricata.yaml does not include the panel override file. Run "
            "scripts/setup-suricata-override.sh"
        )
    if not override_writable():
        raise ValueError(f"no write permission for {OVERRIDE_PATH}")

    # Before anything is written down: the helper creates the directory and its
    # rotation, and it runs as root because the panel cannot do either. A disk
    # mounted at /mnt/ssd belongs to root, so the panel's own mkdir fails there
    # - which used to end in the panel telling the operator to open a shell.
    prepared, helper_output = prepare_dir(target)
    if not prepared:
        raise ValueError(
            f"could not prepare {target}: {helper_output or 'the helper failed'}"
        )
    if not target.is_dir():
        raise ValueError(f"{target} is not a directory")
    if not os.access(target, os.R_OK):
        raise ValueError(f"the panel cannot read in {target}, so it would not see any events")

    previous = engine_dir()
    OVERRIDE_PATH.write_text(
        YAML_HEADER
        + "# Generated by RaPi IDS Panel. Do not edit by hand.\n"
        + f"default-log-dir: {target}\n",
        encoding="utf-8",
    )

    # The log directory is read at engine startup - a rule reload is not enough,
    # a restart is required.
    #
    # 180 s and caught, the same as every other place that restarts the engine.
    # Loading 68,000 rules on a Pi takes as long as it takes, and letting
    # TimeoutExpired out of here answered with a 500 and a traceback after the
    # override file had already been written: the engine goes to the new
    # directory, the panel keeps reading the old one, and no alert reaches the
    # screen again until somebody restarts the panel.
    try:
        proc = subprocess.run(
            ["sudo", "-n", "systemctl", "restart", "suricata"],
            capture_output=True, text=True, timeout=RESTART_TIMEOUT,
        )
        restarted = proc.returncode == 0
        output = (proc.stdout + proc.stderr).strip()
    except subprocess.TimeoutExpired:
        restarted = False
        output = (f"the engine did not finish restarting within {RESTART_TIMEOUT}s. "
                  "The panel is now reading the new directory either way.")
    except FileNotFoundError:
        restarted = False
        output = "systemctl is not installed"

    settings.set("log_dir", str(target))
    # Imported here, not at module level - the tailer imports this module indirectly.
    from .tailer import restart_tailer

    restart_tailer()

    return {
        "ok": restarted,
        "log_dir": str(target),
        "previous_dir": str(previous),
        "restarted": restarted,
        "rotation": True,
        "rotation_output": helper_output,
        "output": output,
    }
