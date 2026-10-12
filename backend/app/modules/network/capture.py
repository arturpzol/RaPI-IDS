"""Putting the chosen layout into effect, and checking that it worked.

Two operations, and the second is the one that matters. Writing an interface
name into the engine configuration is easy and proves nothing: a switch that was
supposed to mirror a port and does not looks exactly like a quiet network. So
the panel listens on the interface afterwards and counts frames addressed to
somebody else. That number is the difference between a working sensor and one
watching itself, and nothing short of listening can establish it.

Everything privileged happens in root-owned helpers under /usr/local/sbin, each
validating its own arguments. The panel passes strings and reads results.
"""
from __future__ import annotations

import ipaddress
import os
import re
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from ... import geoip, settings
from . import interfaces, topology

log = logging.getLogger(__name__)

APPLY = "/usr/local/sbin/rapi-capture-apply"
IFACE = "/usr/local/sbin/rapi-capture-iface"
# Where rapi-capture-iface records that an interface is a sensor and not a
# port NetworkManager should touch. Read only, and read rather than remembered:
# see held_interfaces().
NM_CONF_DIR = Path(os.environ.get("RAPI_NM_CONF_DIR", "/etc/NetworkManager/conf.d"))
CAPTURE_CONF_PREFIX = "99-rapi-capture-"
BRIDGE = "/usr/local/sbin/rapi-bridge"
# The only thing that swaps who forwards an inline link. See its header: it
# stops and starts the engine inside one validated swap, which the panel is
# deliberately not allowed to do on its own.
INLINE = "/usr/local/sbin/rapi-inline"
SYS_NET = Path(os.environ.get("RAPI_SYS_NET", "/sys/class/net"))
# The queue mode's drop-in, which starts the engine with -q instead of
# --af-packet. Owned by rapi-ips-mode; read here only to know it is there.
IPS_MODE = "/usr/local/sbin/rapi-ips-mode"
QUEUE_DROPIN = Path(os.environ.get(
    "RAPI_QUEUE_DROPIN", "/etc/systemd/system/suricata.service.d/10-rapi-nfqueue.conf"))

# The name the inline bridge gets. Fixed rather than generated: it ends up in
# the engine configuration, in the interface list and in what the operator sees
# with `ip link`, and a name that changes between runs is a name nobody can
# recognise later.
BRIDGE_NAME = "br-rapi"

# The engine reads its capture interface once, at startup.
RESTART_TIMEOUT = 180


class ApplyError(RuntimeError):
    """Refused before anything was changed, or rolled back after a failure."""


def _run(command: list[str], timeout: int = 120) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["sudo", "-n", *command], capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"{command[0]} did not finish within {timeout} s"
    except OSError as err:
        return False, str(err)
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


def normalise_home_net(values: list[str]) -> str:
    """Turn what the wizard collected into the string the engine expects.

    Validated here as well as in the helper. The helper's check is what stops a
    compromised panel writing YAML into suricata.yaml; this one exists so that a
    person who mistypes a subnet gets told which one, rather than a rolled back
    configuration and a shell error.
    """
    cleaned: list[str] = []
    for raw in values:
        text = (raw or "").strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as err:
            raise ApplyError(f"{text!r} is not a network in CIDR form: {err}") from err
        entry = str(network)
        if entry not in cleaned:
            cleaned.append(entry)

    if not cleaned:
        raise ApplyError(
            "Name at least one home network. Without it the engine treats every "
            "address as external, and most rules only fire on traffic that ends "
            "inside HOME_NET."
        )
    return "[" + ",".join(cleaned) + "]"


def suggest_home_net(client_ip: str | None = None, local_ip: str | None = None) -> list[str]:
    """The subnets this machine is on, as a starting point.

    A starting point and not an answer: a mirror port carries VLANs this machine
    has no address on, and the wizard has to say so rather than quietly
    monitoring a third of the network.
    """
    hardware = interfaces.detect(client_ip, local_ip)
    found: list[str] = []
    for link in hardware["links"]:
        for cidr in link["subnets"]:
            if cidr not in found:
                found.append(cidr)
    return found


def _guard(profile: topology.Profile, roles: dict[str, str],
           hardware: dict[str, Any]) -> None:
    """Refuse the two ways this could take the panel off the network.

    Both are recoverable - the layout can be undone from the switch, or from a
    keyboard - but recovering means walking to the device, and the panel knows
    enough to stop it happening.
    """
    if profile.capture_has_address:
        return  # the capture interface keeps its address, nothing to lose

    by_name = {link["name"]: link for link in hardware["links"]}
    members = [roles.get(role) or "" for role in ("capture", "bridge_a", "bridge_b")]
    members = [name for name in members if name]
    capture = members[0] if members else ""
    management = roles.get("management") or ""

    if len(set(members)) != len(members):
        raise ApplyError("the same interface cannot play two parts in this layout.")
    if management and management in members:
        raise ApplyError(
            f"{management} cannot carry the traffic being inspected and the way into "
            "the panel at the same time in this layout: it loses its address."
        )

    link = by_name.get(management)
    if link is None:
        raise ApplyError("No interface was chosen to keep the panel reachable.")
    if not link["ipv4"]:
        raise ApplyError(
            f"{management} has no address, so it cannot carry the panel yet. Connect "
            "it to the network first and check that the panel answers on it, then "
            "come back. Applying now would leave this device unreachable."
        )
    for name in members:
        if by_name.get(name, {}).get("is_management"):
            raise ApplyError(
                f"This browser is talking to the panel through {name}, which this "
                "layout turns into a capture interface. Reach the panel on "
                f"{management} first, then apply the change from there."
            )


def held_interfaces() -> set[str]:
    """Interfaces this panel has taken out of NetworkManager, by their name today.

    Read from disk and not from the stored layout: the wizard replaces profile
    and roles together, so by the time a new layout is applied nothing is left
    saying which ports the old one stripped.

    Resolved through the card's address rather than the file name. The helper
    matches the card by MAC because a USB adapter's name moves between boots,
    so a file written as eth1 can be holding the card that is eth2 today. Asked
    to release eth1, the helper fails with "no such interface" and eth2 stays
    unmanaged, which is the failure releasing exists to prevent. A file whose
    card is not in this machine any more names nothing and is left alone.
    """
    try:
        files = [path for path in NM_CONF_DIR.iterdir()
                 if path.name.startswith(CAPTURE_CONF_PREFIX)
                 and path.name.endswith(".conf")]
    except OSError:
        return set()

    by_mac: dict[str, str] = {}
    try:
        for link in SYS_NET.iterdir():
            try:
                mac = (link / "address").read_text(encoding="utf-8").strip().lower()
            except OSError:
                continue
            if mac and mac != "00:00:00:00:00:00":
                by_mac[mac] = link.name
    except OSError:
        pass

    held: set[str] = set()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        match = re.search(r"^match-device=mac:([0-9A-Fa-f:]{17})\s*$", text, re.M)
        if match and match.group(1).lower() in by_mac:
            held.add(by_mac[match.group(1).lower()])
            continue
        name = path.name[len(CAPTURE_CONF_PREFIX):-len(".conf")]
        if name and (SYS_NET / name).exists():
            held.add(name)
    return held


def _release_unused(profile: topology.Profile,
                    roles: dict[str, str]) -> list[dict[str, Any]]:
    """Hand back every port this panel holds and this layout does not want.

    `rapi-capture-iface <name> capture` writes an unmanaged rule and enables a
    unit that reapplies it after a reboot. Right while the port is a sensor,
    wrong the moment it is not, and nothing else ever undoes it.

    Returns the steps rather than discarding them. A release that failed is the
    reason the next step fails, and the operator reading only the second error
    has no way to find the first.
    """
    keep = ({roles.get("capture", "")} - {""}
            if not profile.capture_has_address else set())
    steps = []
    for name in sorted(held_interfaces() - keep):
        ok, output = _run([IFACE, name, "restore"])
        steps.append({"step": f"release {name}", "ok": ok, "output": output})
    return steps


def _home_net_changed() -> None:
    """Drop the panel's copy of HOME_NET after the helper has rewritten it.

    geoip.home_networks() is cached for the life of the process, and the helper
    writes the new value to a file this process already read. Only the engine is
    restarted here, never the panel, so without this every alert classified
    between the wizard finishing and the next panel restart is bucketed against
    the old HOME_NET. That is not a display fault: src_cc is worked out once and
    stored on the row, so the map keeps showing this network as a foreign
    country for those alerts for good.
    """
    geoip.home_networks.cache_clear()


def apply(home_net: list[str], client_ip: str | None = None,
          local_ip: str | None = None) -> dict[str, Any]:
    """Put the recorded layout into effect. Raises ApplyError before changing anything."""
    stored = settings.get(topology.SETTINGS_KEY) or {}
    profile = topology.PROFILES_BY_ID.get(stored.get("profile", ""))
    if profile is None:
        raise ApplyError("No layout has been chosen yet.")
    if not profile.can_apply:
        raise ApplyError(
            f"The panel cannot set up {profile.name!r} on its own yet. It needs a "
            "bridge or routing configuration that is a bigger change than a "
            "capture interface, and doing it half way would take the network down."
        )

    roles: dict[str, str] = stored.get("roles", {})
    hardware = interfaces.detect(client_ip, local_ip)
    present = {link["name"] for link in hardware["links"]}

    if profile.id == "bridge":
        members = [roles.get("bridge_a", ""), roles.get("bridge_b", "")]
        if not all(members):
            raise ApplyError("Both sides of the link have to be chosen.")
        for name in members:
            if name not in present:
                raise ApplyError(
                    f"{name} is not there any more. Check the wiring and choose again.")
        _guard(profile, roles, hardware)
        value = normalise_home_net(home_net)
        # Detection: the kernel forwards and the engine reads a copy. Blocking
        # is the same two cables with the forwarding handed to the engine, and
        # that belongs to the Detection mode switch. Both go through the same
        # helper, which releases the two ports itself, in the one safe order.
        return _apply_bridge(stored, members, value)

    capture = roles.get("capture", "")
    if not capture:
        raise ApplyError("No capture interface was chosen.")
    if capture not in present:
        raise ApplyError(f"{capture} is not there any more. Check the wiring and choose again.")

    _guard(profile, roles, hardware)
    value = normalise_home_net(home_net)

    # Engine configuration first. It verifies itself and rolls back, so a
    # rejected configuration costs nothing. That stays true only while nothing
    # else has been touched yet, which is why every other change waits for it:
    # releasing ports before this check handed a port back to NetworkManager,
    # DHCP and offloads included, and then reported that nothing had changed.
    ok, output = _run([APPLY, capture, value])
    if not ok:
        raise ApplyError(output or "the engine configuration could not be written")
    _home_net_changed()

    steps = [{"step": "engine configuration", "ok": True, "output": output}]

    # Leaving an inline layout: its bridge has no place in a passive one.
    if (SYS_NET / BRIDGE_NAME).exists():
        ok, output = _run([BRIDGE, BRIDGE_NAME, "down"])
        steps.append({"step": "bridge removed", "ok": ok, "output": output})

    steps.extend(_release_unused(profile, roles))

    if not profile.capture_has_address:
        ok, output = _run([IFACE, capture, "capture"])
        steps.append({"step": "capture interface", "ok": ok, "output": output})

    # Leaving the queue behind on a mirror. The drop-in outlives a change of
    # layout: "This device only" with blocking on, then the mirror applied,
    # restarted the engine with -q, so it read the netfilter queue (this Pi's
    # own packets) and never the mirror port, and Apply reported success. The
    # file rather than the running engine is the test, because a stopped
    # engine carries the drop-in just the same.
    if profile.id == "mirror" and QUEUE_DROPIN.exists():
        ok, output = _run([IPS_MODE, "ids"], RESTART_TIMEOUT)
        steps.append({"step": "blocking switched off", "ok": ok, "output": output})

    ok, output = _run(["/usr/bin/systemctl", "restart", "suricata"], RESTART_TIMEOUT)
    steps.append({"step": "engine restart", "ok": ok, "output": output})

    settings.set(topology.SETTINGS_KEY, {
        **stored,
        "home_net": value,
        "applied": all(s["ok"] for s in steps),
        "applied_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    })
    log.info("Capture applied: interface=%s home_net=%s", capture, value)
    return {"ok": all(s["ok"] for s in steps), "interface": capture,
            "home_net": value, "steps": steps}


def inline_members() -> list[str]:
    """The two ports of an inline layout that is in effect, or an empty list.

    In effect, not merely chosen. The wizard stores a layout the moment its step
    is saved, with nothing written to the engine and no home networks recorded.
    Reading that as inline told the Protection screen the kernel was forwarding
    while the engine was still on the previous interface, and the switch then
    failed with "no home networks are recorded for this layout".
    """
    stored = settings.get(topology.SETTINGS_KEY) or {}
    if stored.get("profile") != "bridge":
        return []
    if not stored.get("applied") or not stored.get("home_net"):
        return []
    roles = stored.get("roles") or {}
    members = [roles.get("bridge_a", ""), roles.get("bridge_b", "")]
    return members if all(members) else []


def _inline(mode: str, members: list[str], value: str) -> tuple[bool, str, str]:
    """Run the swap helper. Returns (ok, fell_back, output).

    The helper answers in three ways and the panel needs all three: in place;
    failed and converged on the kernel bridge, so the link carries traffic and
    nothing is blocked; failed with the link down.

    Any line, not the last one. The helper follows its fallback line with the
    words of the step that failed, and _run appends stderr after stdout, so the
    last line was almost never the fallback: every real fallback reached the
    operator as raw output, without being told the link still carries traffic.
    """
    ok, output = _run([INLINE, mode, members[0], members[1], value], RESTART_TIMEOUT)
    fell_back = any(line.startswith("fallback bridge") for line in output.splitlines())
    return ok, fell_back, output


def set_inline_blocking(block: bool) -> tuple[bool, str]:
    """Hand the forwarding to the engine, or give it back to the kernel bridge.

    What "Detection and blocking" means on an inline layout. NFQUEUE, which is
    what it means everywhere else, cannot do it here: its rules hang on the IP
    forward hook and bridged frames never reach it without br_netfilter.

    Every step of the swap lives in rapi-inline, including the rollback, so this
    never raises: the route that calls it turns an exception into a 500 and
    loses the helper's own words at the moment they are most needed.
    """
    members = inline_members()
    if not members:
        return False, "this is not an inline layout in effect"
    stored = settings.get(topology.SETTINGS_KEY) or {}
    value = stored.get("home_net") or ""

    ok, fell_back, output = _inline("pair" if block else "bridge", members, value)
    if ok:
        _home_net_changed()
        return True, output
    if fell_back:
        return False, ("Blocking could not be turned on, so the link was put back "
                       "on the kernel bridge: traffic flows and nothing is blocked.\n\n"
                       + output)
    return False, output


def _apply_bridge(stored: dict[str, Any], members: list[str], value: str) -> dict[str, Any]:
    """Put the device in the path of a link, detecting.

    Through the same helper as the blocking switch, in its bridge mode, so there
    is one implementation of how the link is built and one order it happens in.
    """
    ok, _, output = _inline("bridge", members, value)
    steps = [{"step": "inline bridge", "ok": ok, "output": output}]
    if ok:
        _home_net_changed()
        # Ports some earlier layout stripped that this one does not use. After
        # the bridge is up and never the two members: releasing a live bridge
        # member turns its offloads back on and nothing turns them off again.
        for name in sorted(held_interfaces() - set(members)):
            released, detail = _run([IFACE, name, "restore"])
            steps.append({"step": f"release {name}", "ok": released, "output": detail})

    # Applied means the bridge is in effect, which only the helper's step says.
    # A port of an earlier layout that would not let go is reported through
    # "ok", and nothing more: counted here, it made inline_members() answer
    # "not inline" for a live bridge, and the blocking switch then turned on the
    # queue, which bridged frames never reach, and reported blocking.
    applied = ok
    done = all(step["ok"] for step in steps)
    settings.set(topology.SETTINGS_KEY, {
        **stored,
        "home_net": value,
        "applied": applied,
        "applied_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    })
    log.info("Bridge applied: %s over %s, home_net=%s, ok=%s",
             BRIDGE_NAME, members, value, done)
    return {"ok": done, "interface": BRIDGE_NAME, "home_net": value,
            "steps": steps, "members": members}
