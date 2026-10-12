"""Fixtures shared by the tests: a throwaway database, a fake /sys/class/net.

The fakes exist because the things they stand in for cannot be arranged on a
build machine. There is no second network card to plug in, no switch to mirror
a port, and no way to ask a kernel for a link with no carrier. The panel reads
all of that from files under /sys, so a directory of files is a faithful stand
in - and the code under test never learns the difference.
"""
from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import psutil

from app import config, db, settings
from app.modules.network import capture
from app.modules.suricata import protection

from . import PROJECT_ROOT, TMP_ROOT

# README.md and docs/ are Polish and stay in the private repository:
# scripts/export-public.sh leaves them out. Tests that read them skip there, and
# only there, rather than fail on files that are absent on purpose.
PRIVATE_DOCS = (PROJECT_ROOT / "README.md").is_file() and (PROJECT_ROOT / "docs").is_dir()
PRIVATE_DOCS_SKIP = "README.md and docs/ are private; the public export leaves them out"

__all__ = [
    "PROJECT_ROOT", "PRIVATE_DOCS", "PRIVATE_DOCS_SKIP", "TMP_ROOT", "BackendTestCase", "alert", "link", "hardware",
    "write_sysfs", "if_addr", "if_stats", "run_helper",
]


def alert(**overrides: Any) -> dict[str, Any]:
    """One row as the tailer would hand it over, already normalised.

    Not raw EVE: insert_alerts() takes what the tailer produced, so a fixture
    shaped like an EVE line would only be testing the fixture.
    """
    row: dict[str, Any] = {
        "ts": int(datetime.now(timezone.utc).timestamp()),
        "event_type": "alert",
        "src_ip": "203.0.113.7",
        "src_port": 44321,
        "dest_ip": "192.168.1.10",
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
        "signature": "ET MALWARE Test Signature",
        "signature_id": 2000001,
        "category": "A Network Trojan was detected",
        "severity": 1,
        # ET's own rating, which is the one the panel filters and colours by.
        "et_severity": "Major",
        "iface": "eth0",
        "src_cc": "US",
        "raw": {"event_type": "alert"},
    }
    row.update(overrides)
    # Keep the raw event agreeing with the column, so a test that exercises the
    # backfill is not fed a row the tailer could never have produced.
    if row.get("et_severity"):
        raw = dict(row["raw"])
        alert = dict(raw.get("alert") or {})
        alert["metadata"] = {**(alert.get("metadata") or {}),
                             "signature_severity": [row["et_severity"]]}
        raw["alert"] = alert
        row["raw"] = raw
    return row


class BackendTestCase(unittest.TestCase):
    """Every test starts with an empty database and empty settings.

    Both are process-global (a cached connection, a cached settings dict), so
    leaving one test's state behind would show up as another test failing
    somewhere else entirely.
    """

    def setUp(self) -> None:
        super().setUp()
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.reset_db()
        self.reset_settings()
        self.isolate_nm_config()
        self.reset_rule_dates()

    def reset_db(self) -> None:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
        config.DB_PATH = TMP_ROOT / "data" / f"test-{id(self)}.db"
        self.addCleanup(self._drop_db, config.DB_PATH)
        db.init()

    @staticmethod
    def _drop_db(path: Path) -> None:
        conn = getattr(db._local, "conn", None)
        if conn is not None:
            conn.close()
            db._local.conn = None
        for suffix in ("", "-wal", "-shm"):
            Path(str(path) + suffix).unlink(missing_ok=True)

    def reset_settings(self) -> None:
        settings.SETTINGS_PATH.unlink(missing_ok=True)
        settings._cache = None
        self.addCleanup(setattr, settings, "_cache", None)

    def isolate_nm_config(self) -> None:
        """The panel reads which interfaces it holds from NetworkManager's own
        configuration directory. Left pointing at the real one, every test on
        this machine sees the interface this machine happens to have stripped,
        and the same test passes or fails depending on the host it runs on.
        """
        conf = self.tmp / "nm-conf.d"
        conf.mkdir(exist_ok=True)
        self.enterContext(patch.object(capture, "NM_CONF_DIR", conf))
        # The interfaces themselves, for the same reason. Once this machine ran
        # its own inline bridge, br-rapi existed in the real /sys/class/net and
        # every passive apply under test took down a bridge it did not have.
        # A test that needs interfaces makes its own and patches over this.
        sys_net = self.tmp / "no-class-net"
        sys_net.mkdir(exist_ok=True)
        self.enterContext(patch.object(capture, "SYS_NET", sys_net))
        self.enterContext(patch.object(protection, "SYS_NET", sys_net))

    def reset_rule_dates(self) -> None:
        """No sudo out of a test, and no answer carried over from the last one.

        The vendor build date comes from a root-owned helper. Pointed at a path
        that is not there, the panel answers "unknown" without forking, which is
        what a machine that has not installed the helper should see anyway.
        """
        self.enterContext(patch.object(protection, "RULES_DATE_HELPER",
                                       str(self.tmp / "no-rules-date-helper")))
        protection._source_cache = None
        self.addCleanup(setattr, protection, "_source_cache", None)


# --- network hardware fakes ---


def if_addr(address: str, netmask: str = "255.255.255.0", family: int = socket.AF_INET):
    return psutil._common.snicaddr(
        family=family, address=address, netmask=netmask, broadcast=None, ptp=None,
    )


def if_stats(isup: bool = True, speed: int = 1000, mtu: int = 1500):
    return psutil._common.snicstats(isup=isup, duplex=2, speed=speed, mtu=mtu, flags="")


def write_sysfs(root: Path, name: str, *, kind: str = "wired", carrier: bool = True,
                speed: int | None = 1000, mac: str = "de:ad:be:ef:00:01",
                usb: bool = False) -> None:
    """One interface as the kernel would present it under /sys/class/net."""
    path = root / name
    path.mkdir(parents=True, exist_ok=True)
    (path / "address").write_text(mac + "\n")
    (path / "carrier").write_text("1\n" if carrier else "0\n")
    (path / "type").write_text("772\n" if kind == "loopback" else "1\n")
    if speed is not None:
        (path / "speed").write_text(f"{speed}\n")
    if kind == "wireless":
        (path / "wireless").mkdir(exist_ok=True)
    if kind == "bridge":
        (path / "bridge").mkdir(exist_ok=True)
    if kind in ("wired", "wireless"):
        # A real interface has a device directory with a driver symlink; a veth
        # or a tun device has neither, which is how _kind() tells them apart.
        bus = root / ("usb-bus" if usb else "pci-bus") / name
        bus.mkdir(parents=True, exist_ok=True)
        driver = root / "drivers" / ("cdc_ether" if usb else "bcmgenet")
        driver.mkdir(parents=True, exist_ok=True)
        (bus / "driver").symlink_to(driver)
        (path / "device").symlink_to(bus)


def link(name: str, **overrides: Any) -> dict[str, Any]:
    """One entry of interfaces.detect()["links"], with sane defaults."""
    base = {
        "name": name,
        "kind": "wired",
        "driver": "bcmgenet",
        "usb": False,
        "is_up": True,
        "carrier": True,
        "speed_mbps": 1000,
        "mtu": 1500,
        "mac": "de:ad:be:ef:00:01",
        "ipv4": ["192.168.1.10/24"],
        "ipv6": [],
        "subnets": ["192.168.1.0/24"],
        "blocked": False,
        "is_management": False,
    }
    base.update(overrides)
    return base


def hardware(links: list[dict[str, Any]], management: str = "") -> dict[str, Any]:
    """A canned interfaces.detect() result, counted the way the real one counts."""
    for entry in links:
        entry["is_management"] = entry["name"] == management
    usable = [l for l in links if l["kind"] in ("wired", "wireless")]
    wired = [l for l in usable if l["kind"] == "wired"]
    return {
        "links": links,
        "management": management,
        "counts": {
            "usable": len(usable),
            "wired": len(wired),
            "wireless": len(usable) - len(wired),
        },
        "wireless_blocked": any(l["blocked"] for l in links),
    }


# --- root-owned helper scripts ---


def run_helper(name: str, *args: str, env: dict[str, str] | None = None,
               path_prefix: Path | None = None) -> subprocess.CompletedProcess:
    """Run one of the deploy/ scripts as the current user.

    They are installed root-owned and called over sudo, but every path they
    touch comes from an environment variable, so the interesting half - argument
    validation and the file they generate - runs perfectly well unprivileged.
    """
    environment = dict(os.environ)
    environment.update(env or {})
    if path_prefix is not None:
        environment["PATH"] = f"{path_prefix}:{environment['PATH']}"
    return subprocess.run(
        [str(PROJECT_ROOT / "deploy" / name), *args],
        capture_output=True, text=True, timeout=60, env=environment,
    )
