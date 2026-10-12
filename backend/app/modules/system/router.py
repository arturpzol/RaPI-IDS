"""REST for the 'system' module - health of the Raspberry Pi itself."""
from __future__ import annotations

import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import psutil
from fastapi import APIRouter, Query

from . import history, ssh

router = APIRouter(prefix="/system", tags=["system"])

_THERMAL = Path("/sys/class/thermal/thermal_zone0/temp")
_MODEL = Path("/proc/device-tree/model")


def _cpu_temperature() -> float | None:
    try:
        return round(int(_THERMAL.read_text().strip()) / 1000.0, 1)
    except (OSError, ValueError):
        return None


def _throttled() -> dict[str, Any] | None:
    """What vcgencmd says about power and heat, limited to what is true now.

    The board also carries four sticky bits for "this happened at some point
    since boot", and they were reported here until one quarter of an hour at
    81.6 C during an image build left "There was throttling since the last boot"
    standing for three days on a machine that had been at 54 C ever since. The
    line could not say when it happened or how hot it got, and nothing but a
    reboot could clear it.

    A warning nobody can act on and nobody can clear teaches people to ignore
    the box it lives in, and the live under-voltage warning - the one that
    catches the usual cause of strange failures on a Pi - lives in that same
    box. So the sticky half is gone and the live half stays.

    The raw value is still returned, so nothing is lost from the API.
    """
    try:
        out = subprocess.run(
            ["vcgencmd", "get_throttled"], capture_output=True, text=True, timeout=5
        )
        if out.returncode != 0:
            return None
        raw = out.stdout.strip().split("=")[1]
        bits = int(raw, 16)
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        return None
    return {
        "raw": raw,
        "under_voltage_now": bool(bits & 0x1),
        "frequency_capped_now": bool(bits & 0x2),
        "throttled_now": bool(bits & 0x4),
        "soft_temp_limit_now": bool(bits & 0x8),
    }


@router.get("/info")
def system_info() -> dict[str, Any]:
    """Values that do not change while the panel runs."""
    # Printed straight into the page header, so it has to be a name and not an
    # empty gap. Anything that is not a Pi has no device-tree model file at all.
    model = "unknown model"
    try:
        model = _MODEL.read_text().strip("\x00").strip()
    except OSError:
        pass
    return {
        "hostname": socket.gethostname(),
        "model": model,
        "cpu_count": psutil.cpu_count(logical=True),
        "boot_time": psutil.boot_time(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
        "kernel": subprocess.run(
            ["uname", "-r"], capture_output=True, text=True
        ).stdout.strip(),
    }


@router.get("/metrics")
def system_metrics() -> dict[str, Any]:
    """Reading for right now. The frontend polls this; the chart uses /history."""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = shutil.disk_usage("/")
    load1, load5, load15 = psutil.getloadavg()
    # One measurement for both figures. The cores used to be read with
    # interval=None, which measures since the previous call and returns 0.0
    # for every core when there was none: the first request after a start
    # showed "CPU 71%" above four cores at 0%.
    per_core = psutil.cpu_percent(interval=0.2, percpu=True)
    total = round(sum(per_core) / len(per_core), 1) if per_core else 0.0

    return {
        "timestamp": time.time(),
        "cpu": {
            "percent": total,
            "per_core": per_core,
            "temperature_c": _cpu_temperature(),
            "load_avg": {"1m": load1, "5m": load5, "15m": load15},
        },
        "memory": {
            "total": mem.total,
            "used": mem.used,
            "available": mem.available,
            "percent": mem.percent,
        },
        "swap": {"total": swap.total, "used": swap.used, "percent": swap.percent},
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": round(disk.used / disk.total * 100, 1),
        },
        "throttling": _throttled(),
        "uptime_seconds": int(time.time() - psutil.boot_time()),
    }


# Five years of hourly rows is 43800 of them, which is both more than anyone
# will ask for and small enough to hold. Zero means everything on record.
MAX_HISTORY_HOURS = 24 * 365 * 5


@router.get("/history")
def load_history(hours: int = Query(1, ge=0, le=MAX_HISTORY_HOURS)) -> dict[str, Any]:
    """Device load over time, sampled by the panel itself.

    hours=0 asks for everything the device has recorded, which after a fresh
    install means "since it was first switched on". Minute detail is kept for a
    week (RAPI_LOAD_SAMPLE_DAYS), hourly averages for good - see history.py.
    """
    return history.sampler.window(hours)


@router.get("/ssh")
def ssh_access() -> dict[str, Any]:
    """Whether SSH answers, the account to log in as, and whose password it takes."""
    return ssh.status()


@router.get("/network")
def network_info() -> dict[str, Any]:
    """Interfaces with addresses and counters - groundwork for a network module."""
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)

    interfaces = []
    for name, if_stats in stats.items():
        ipv4 = [a.address for a in addrs.get(name, []) if a.family == socket.AF_INET]
        ipv6 = [a.address for a in addrs.get(name, []) if a.family == socket.AF_INET6]
        mac = next(
            (a.address for a in addrs.get(name, []) if a.family == psutil.AF_LINK), None
        )
        io = counters.get(name)
        interfaces.append({
            "name": name,
            "is_up": if_stats.isup,
            "speed_mbps": if_stats.speed,
            "mtu": if_stats.mtu,
            "mac": mac,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "bytes_sent": io.bytes_sent if io else 0,
            "bytes_recv": io.bytes_recv if io else 0,
            "packets_sent": io.packets_sent if io else 0,
            "packets_recv": io.packets_recv if io else 0,
            "errors_in": io.errin if io else 0,
            "errors_out": io.errout if io else 0,
            "drops_in": io.dropin if io else 0,
        })
    interfaces.sort(key=lambda i: (not i["is_up"], i["name"]))
    return {"interfaces": interfaces}
