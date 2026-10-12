"""Settings changed from the panel at runtime (data/settings.json).

Split of responsibility against `config.py`: that one holds values coming from
the environment (RAPI_* vars, fixed at startup), this one holds what the user
flips in the GUI. The JSON file is small and written rarely, so the SD card
does not suffer.
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any

from . import config

log = logging.getLogger(__name__)

SETTINGS_PATH = config.DATA_DIR / "settings.json"

# Engine log directory. Derived from the eve.json path by default so that
# RAPI_EVE_PATH keeps working exactly as before.
DEFAULTS: dict[str, Any] = {
    "log_dir": str(config.EVE_PATH.parent),
    # How the device is wired into the network it watches. Empty profile means
    # nobody has been through the wizard yet, which is not the same as "this
    # device only" - one is a choice, the other is nothing having been decided.
    # Alert notifications by e-mail. The password sits in this file, which is
    # why the file is written 0600 and why the API never sends it back out.
    "email": {
        "enabled": False,
        "host": "",
        "port": 587,
        "security": "starttls",       # none | starttls | ssl
        "username": "",
        "password": "",
        "sender": "",
        "recipients": [],
        # Suricata numbers severity the other way round: 1 is the most serious.
        # This is the highest number that still gets sent.
        "min_severity": 2,
        # Alerts are collected for this long and sent as one message. A mirror
        # port can produce hundreds an hour, and a mailbox with one message per
        # alert is a mailbox nobody reads.
        "digest_seconds": 300,
        "max_per_hour": 6,
    },
    "topology": {
        "profile": "",
        "roles": {},
        "chosen_at": "",
        # Written by the engine, not by the wizard: "applied" says the capture
        # interface and HOME_NET were actually put in place and the engine
        # accepted them, which is a different claim from "somebody clicked".
        "applied": False,
        "applied_at": "",
        "home_net": "",
    },
}

# RLock because set() calls all() - both need to take the same lock.
_lock = threading.RLock()
_cache: dict[str, Any] | None = None


def all() -> dict[str, Any]:
    global _cache
    with _lock:
        if _cache is None:
            data = dict(DEFAULTS)
            try:
                stored = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
                data.update({k: v for k, v in stored.items() if k in DEFAULTS})
            except FileNotFoundError:
                pass
            except (OSError, ValueError):
                log.warning("Unreadable %s, falling back to defaults", SETTINGS_PATH)
            _cache = data
        return dict(_cache)


def get(key: str) -> Any:
    return all().get(key, DEFAULTS.get(key))


def set(key: str, value: Any) -> None:
    if key not in DEFAULTS:
        raise KeyError(f"unknown setting: {key}")
    global _cache
    with _lock:
        current = all()
        current[key] = value
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH.write_text(json.dumps(current, indent=2), encoding="utf-8")
        # The file holds an SMTP password. The data directory is already 0700,
        # but the file itself should not be readable by anything that gets in.
        SETTINGS_PATH.chmod(0o600)
        _cache = current


def harden() -> None:
    """Take the settings file away from everyone but its owner.

    Called at startup because the file predates the SMTP password living in it,
    and an install that has been running since before that stayed 0644.
    """
    try:
        if SETTINGS_PATH.exists() and SETTINGS_PATH.stat().st_mode & 0o077:
            SETTINGS_PATH.chmod(0o600)
            log.info("Tightened permissions on %s", SETTINGS_PATH)
    except OSError as err:
        log.warning("Could not tighten %s: %s", SETTINGS_PATH, err)


# --- paths derived from settings ---


def log_dir() -> Path:
    return Path(get("log_dir"))


def eve_path() -> Path:
    """Event source for the tailer. The file name is fixed by the engine."""
    return log_dir() / config.EVE_PATH.name


def engine_log_path() -> Path:
    return log_dir() / config.SURICATA_LOG.name
