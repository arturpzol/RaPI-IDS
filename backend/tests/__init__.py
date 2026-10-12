"""Test suite for the panel backend.

Standard library `unittest` and nothing else. The panel is installed from
Debian packages only, and a test suite that needs a package the image does not
carry is a suite nobody runs on the device it is meant to protect.

**This module runs before any test is imported**, and that is the point: every
path the panel writes to is fixed by a RAPI_* environment variable read at
import time, so pointing them at a throwaway directory here is the one moment
that can keep the tests away from the real database, the real settings file and
the real engine configuration.
"""
from __future__ import annotations

import atexit
import logging
import os
import shutil
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

TMP_ROOT = Path(tempfile.mkdtemp(prefix="rapi-panel-tests-"))
atexit.register(shutil.rmtree, TMP_ROOT, ignore_errors=True)

for _sub in ("data", "logs", "rules", "etc", "etc/logrotate.d"):
    (TMP_ROOT / _sub).mkdir(parents=True, exist_ok=True)

os.environ.update({
    "RAPI_DATA_DIR": str(TMP_ROOT / "data"),
    "RAPI_EVE_PATH": str(TMP_ROOT / "logs" / "eve.json"),
    "RAPI_SURICATA_LOG": str(TMP_ROOT / "logs" / "suricata.log"),
    "RAPI_RULES_DIR": str(TMP_ROOT / "rules"),
    "RAPI_SURICATA_YAML": str(TMP_ROOT / "etc" / "suricata.yaml"),
    "RAPI_SURICATA_OVERRIDE": str(TMP_ROOT / "etc" / "rapi-overrides.yaml"),
    "RAPI_LOGROTATE_DIR": str(TMP_ROOT / "etc" / "logrotate.d"),
    "RAPI_SERVE_TLS": "0",
    "RAPI_ENABLE_DOCS": "0",
})

# The panel logs a warning on every path a test deliberately walks into (a
# corrupt settings file, a malformed hash). Silenced so a failure is the only
# thing that shows up in the output.
logging.disable(logging.CRITICAL)

# Nothing below this line may import app.* before the block above has run.
from app import config  # noqa: E402

# The suite deletes rows and rewrites configuration files. If any of that ever
# pointed at the running panel it would be found out the hard way, so it is
# checked here instead.
assert config.DATA_DIR.is_relative_to(TMP_ROOT), config.DATA_DIR
assert config.DB_PATH.is_relative_to(TMP_ROOT), config.DB_PATH

# No test may reach root. The panel calls sudo by name, and on a device where
# the account also holds a broad sudoers grant, a test that forgot to replace
# one call ran it for real: on 2026-09-14 a test of the signature download ran
# `sudo suricata-update` with this suite's throwaway disable.conf and
# drop.conf, and rewrote the engine's live rule file. A `sudo` first on PATH
# that refuses turns the same mistake into a failing test.
_NO_SUDO = TMP_ROOT / "no-sudo"
_NO_SUDO.mkdir()
(_NO_SUDO / "sudo").write_text(
    "#!/bin/sh\n"
    "echo 'sudo: refused inside the test suite' >&2\n"
    "exit 1\n")
(_NO_SUDO / "sudo").chmod(0o755)
os.environ["PATH"] = f"{_NO_SUDO}{os.pathsep}{os.environ.get('PATH', '')}"
