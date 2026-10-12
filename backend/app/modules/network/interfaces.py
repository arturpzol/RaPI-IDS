"""What network hardware this device actually has.

The topology wizard cannot assume anything about the machine it runs on. The
image goes to other people's networks and other people's boards: a Pi 5 has one
gigabit port, a Pi 3 has a hundred megabits sharing the USB bus, a Zero W has no
Ethernet at all, and a Compute Module carrier can have two. So every question
the wizard asks is answered from what is plugged in right now, never from a
model number.

Everything here is read from /sys and from psutil. No shelling out, nothing that
needs root, so this stays cheap enough to call on every page load.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from pathlib import Path
from typing import Any

import psutil

log = logging.getLogger(__name__)

SYS_NET = Path("/sys/class/net")
RFKILL = Path("/sys/class/rfkill")

# ARPHRD_* from linux/if_arp.h. Only the two that matter here.
ARPHRD_ETHER = 1
ARPHRD_LOOPBACK = 772


def _read(path: Path) -> str:
    """A /sys attribute, or "" when it cannot be read.

    Missing files are normal here, and so are read errors: `speed` and `carrier`
    return EINVAL rather than a value while the link is down.
    """
    try:
        return path.read_text().strip()
    except (OSError, ValueError):
        return ""


def _read_int(path: Path) -> int | None:
    value = _read(path)
    try:
        return int(value)
    except ValueError:
        return None


def _driver(name: str) -> str:
    """The kernel module behind an interface, or "" where there is none.

    Path.resolve() is not strict: on a missing symlink it hands back the path
    unchanged, so this used to answer with the literal string "driver" for
    every interface that has no device behind it. Verified on this machine:
    lo, and with it veth, tun and the panel's own bridge, all came out as a
    driver called "driver" in the wizard's interface list.
    """
    link = SYS_NET / name / "device" / "driver"
    try:
        if not link.is_symlink():
            return ""
        return link.resolve().name
    except OSError:
        return ""


def _is_usb(name: str) -> bool:
    """True for an interface hanging off the USB bus.

    Worth telling apart: a USB adapter is the cheap way to give a single-port Pi
    a second interface, so the wizard can suggest it, and on the older boards the
    onboard Ethernet is itself behind USB and shares bandwidth with everything
    else plugged in.
    """
    try:
        return "/usb" in str((SYS_NET / name / "device").resolve())
    except OSError:
        return False


def _kind(name: str) -> str:
    path = SYS_NET / name
    if (path / "wireless").exists() or (path / "phy80211").exists():
        return "wireless"
    if (path / "bridge").exists():
        return "bridge"
    if _read_int(path / "type") == ARPHRD_LOOPBACK:
        return "loopback"
    if _read_int(path / "type") == ARPHRD_ETHER:
        # No device symlink means the kernel made it up: veth, tun, a docker
        # bridge. Those are not somewhere traffic can be captured from.
        return "wired" if (path / "device").exists() else "virtual"
    return "other"


def _wireless_blocked() -> bool:
    """Whether the radio is switched off in software.

    A soft block is the quiet way a Wi-Fi management path fails: the interface
    exists, the driver is loaded, and nothing will ever associate. The wizard has
    to catch it before it tells anyone to move the panel onto Wi-Fi.
    """
    for entry in sorted(RFKILL.glob("rfkill*")):
        if _read(entry / "type") != "wlan":
            continue
        if _read(entry / "soft") == "1" or _read(entry / "hard") == "1":
            return True
    return False


def _addresses(name: str, addrs: dict[str, list]) -> tuple[list[str], list[str], list[str]]:
    """(ipv4 with prefix, ipv6, subnets in CIDR)."""
    ipv4: list[str] = []
    ipv6: list[str] = []
    subnets: list[str] = []
    for addr in addrs.get(name, []):
        if addr.family == socket.AF_INET:
            try:
                network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            except ValueError:
                ipv4.append(addr.address)
                continue
            ipv4.append(f"{addr.address}/{network.prefixlen}")
            if not network.is_link_local:
                subnets.append(str(network))
        elif addr.family == socket.AF_INET6:
            # Link-local addresses say nothing about where the machine is
            # connected, and every interface has one.
            if not addr.address.lower().startswith("fe80"):
                ipv6.append(addr.address)
    return ipv4, ipv6, subnets


def default_route_interface() -> str:
    """The interface with the default route, read from /proc/net/route."""
    try:
        lines = Path("/proc/net/route").read_text().splitlines()[1:]
    except OSError:
        return ""
    for line in lines:
        fields = line.split()
        # Destination 00000000 with a gateway is the default route.
        if len(fields) > 2 and fields[1] == "00000000":
            return fields[0]
    return ""


def _management_interface(client_ip: str | None, links: list[dict[str, Any]],
                          local_ip: str | None = None) -> str:
    """Which interface the person configuring the panel is talking through.

    This is the one piece of detection that exists purely to stop someone from
    cutting the branch they are sitting on. Handing the management interface to
    packet capture takes its address away, and the browser that issued the change
    never sees the response.

    Three sources, best first:

    1. The address the browser dialled. It belongs to exactly one interface, so
       it is the only source that cannot be ambiguous.
    2. The subnet the browser's own address falls in. Right whenever the
       interfaces are on different networks, and wrong when they are not: with
       the LAN port and Wi-Fi both in 198.51.100.0/24 this matched both and
       returned whichever came first alphabetically, which is how the wizard came
       to refuse a change made from Wi-Fi, saying the browser was on eth0.
    3. The default route, for a session that arrived through a router or a VPN
       where neither of the above says anything.
    """
    if local_ip:
        for link in links:
            for address in link["ipv4"]:
                if address.split("/")[0] == local_ip:
                    return link["name"]
    if client_ip:
        try:
            address = ipaddress.ip_address(client_ip)
        except ValueError:
            address = None
        if address is not None:
            for link in links:
                for cidr in link["subnets"]:
                    try:
                        if address in ipaddress.ip_network(cidr):
                            return link["name"]
                    except ValueError:
                        continue
    # Reached over a VPN, or through a router, so no subnet matches. The default
    # route is then the best guess available.
    return default_route_interface()


def detect(client_ip: str | None = None, local_ip: str | None = None) -> dict[str, Any]:
    """Every interface, with what the wizard needs to reason about it."""
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    links: list[dict[str, Any]] = []
    for name in sorted(set(addrs) | set(stats)):
        kind = _kind(name)
        if kind == "loopback":
            continue

        ipv4, ipv6, subnets = _addresses(name, addrs)
        if_stats = stats.get(name)
        carrier = _read_int(SYS_NET / name / "carrier")
        speed = _read_int(SYS_NET / name / "speed")

        links.append({
            "name": name,
            "kind": kind,
            "driver": _driver(name),
            "usb": _is_usb(name),
            "is_up": bool(if_stats.isup) if if_stats else False,
            # Carrier is the honest answer to "is there a cable in it": an
            # interface can be administratively up with nothing on the other end.
            "carrier": carrier == 1,
            # The kernel reports a negative speed when it has no idea.
            "speed_mbps": speed if speed and speed > 0 else None,
            "mtu": if_stats.mtu if if_stats else 0,
            "mac": _read(SYS_NET / name / "address") or None,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "subnets": subnets,
            "blocked": kind == "wireless" and _wireless_blocked(),
        })

    management = _management_interface(client_ip, links, local_ip)
    for link in links:
        link["is_management"] = link["name"] == management

    # Usable for capture or for a link: what is left once the made-up interfaces
    # and the bridges the panel itself might have created are out of the way.
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
        "wireless_blocked": _wireless_blocked(),
    }
