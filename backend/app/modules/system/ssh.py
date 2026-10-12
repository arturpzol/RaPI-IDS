"""The SSH login of the device, as far as the panel is concerned.

The image ships its account locked, so without this a card nobody prepared has
no way in over SSH. The panel password is the one the operator has just chosen,
so it becomes the SSH password too, through the root-owned helper
deploy/rapi-login-password. The helper decides whether it may: a password that
came with the card, or one the account already had, is never replaced.
"""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

HELPER = "/usr/local/sbin/rapi-login-password"
SOURCES = {"card", "key", "panel", "other", "none"}


def _installed() -> bool:
    # A checkout that never ran install-service.sh has no helper; asking sudo
    # for a command it was never granted only costs a fork to be told so.
    return Path(HELPER).exists()


def _parse(stdout: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in stdout.splitlines():
        key, _, value = line.partition("=")
        if key in ("source", "login") and value.strip():
            out[key] = value.strip()
    if out.get("source") not in SOURCES:
        out.pop("source", None)
    return out


def _active() -> bool:
    """Whether anything answers on port 22: the service, or the socket that starts it."""
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", "ssh.service", "ssh.socket"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "active" in proc.stdout.split()


def status() -> dict[str, Any]:
    result: dict[str, Any] = {"active": _active(), "source": None, "login": None}
    if not _installed():
        return result
    try:
        proc = subprocess.run(["sudo", "-n", HELPER, "status"],
                              capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return result
    if proc.returncode == 0:
        result.update(_parse(proc.stdout))
    return result


def follow_panel_password(password: str) -> None:
    """Make the SSH password the panel's, where the helper allows it.

    Never raises: the panel account exists by now, and an SSH password that
    could not follow is reported on the System screen, not by refusing the
    panel password the operator just typed.
    """
    if not _installed():
        return
    try:
        # On stdin, never in argv, where `ps` would show it to every account.
        proc = subprocess.run(["sudo", "-n", HELPER, "set"], input=password + "\n",
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as err:
        log.warning("SSH password not updated: %s", err)
        return
    if proc.returncode == 0:
        log.info("SSH password now follows the panel password")
    elif proc.returncode in (3, 4):
        # Not the panel's to change: set with the card, or somebody's own.
        log.info("SSH password left alone: %s", proc.stderr.strip())
    else:
        log.warning("SSH password not updated (exit %s): %s",
                    proc.returncode, proc.stderr.strip()[:200])
