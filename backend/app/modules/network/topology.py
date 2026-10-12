"""The ways a Pi can be wired into the network it is supposed to watch.

Suricata listening on the interface the panel is reached through sees the
device's own traffic and nothing else, which is a perfectly working IDS
monitoring a network of one. Getting it to see anything else is a decision about
cables, not a switch in the panel, and it is the decision most people never make
because nothing ever tells them it exists.

So the panel states the options, says what each one costs, and refuses to
pretend it knows which one applies. No vendor names anywhere: the same feature is
called port mirroring, SPAN or monitor mode depending on who built the switch,
and a panel that names one brand is wrong for everyone else and stale within two
firmware releases.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ... import settings
from . import interfaces

log = logging.getLogger(__name__)

SETTINGS_KEY = "topology"


@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    summary: str            # one line, shown on the card
    sees: str               # what reaches the engine in this layout
    blind_to: str           # what does not, stated plainly
    hardware: str           # what has to exist for it to work at all
    steps: tuple[str, ...]  # vendor-neutral instructions
    # Interface roles the wizard has to fill in, in the order they are asked for.
    roles: tuple[str, ...] = ("capture",)
    wired_needed: int = 1
    # How many interfaces the machine has to have for this layout to be offered.
    # Never fewer than there are roles - see __post_init__, which is there
    # because two layouts declared fewer and the wizard offered them on hardware
    # that could not finish them.
    usable_needed: int = 1
    passive: bool = True    # false = traffic passes through the Pi
    # Whether the configuration THIS PANEL writes can drop a packet, which is
    # not the same question as whether the traffic passes through the Pi. It
    # said otherwise until 2026-08-28 and that was a straight untruth: the
    # inline layout builds a Linux bridge and points af-packet at it, and a
    # kernel bridge forwards frames whatever the engine thinks of them. Suricata
    # sees a copy, raises the alert, and the packet is long gone. The packaged
    # suricata.yaml says it in one line: "none: IDS mode only - disables IPS
    # functionality". Dropping needs copy-mode: ips with a paired copy-iface, or
    # NFQUEUE - and neither is what a bridge is.
    can_block: bool = False
    # What it would take, for the layouts where the traffic does pass through.
    # Empty where the question does not arise.
    blocking_needs: str = ""
    # What blocking costs on a layout that can do it. The opposite field to the
    # one above: that one says why a layout cannot block, this one says what it
    # gives up when it does.
    blocking_cost: str = ""
    # Capture interface carries no address of its own, so HOME_NET cannot be
    # derived from it and has to be asked for.
    capture_has_address: bool = True
    # Whether the panel can put this layout into effect on its own. A capture
    # interface is a line in a configuration file; a bridge or a router is a
    # working network, and half of one is an outage.
    can_apply: bool = False

    def __post_init__(self) -> None:
        """A layout needs one interface per role, and nothing less will do.

        `bridge` and `gateway` each name three roles - two for the traffic and
        one to reach the panel by - and each asked for two interfaces. So a Pi
        with exactly two, which is a Pi plus one USB adapter and no Wi-Fi, was
        offered a layout it could not complete: the wizard filled the two
        traffic roles, had nothing left for the third, and the save was refused
        with "no interface chosen for: Panel access" the moment the step opened.
        Derived rather than corrected in place, because the next layout added
        here would have the same chance of getting it wrong by hand.
        """
        object.__setattr__(self, "usable_needed", max(self.usable_needed, len(self.roles)))


PROFILES: tuple[Profile, ...] = (
    Profile(
        id="self",
        name="This device only",
        summary="No extra hardware. The engine sees the traffic of this Pi.",
        sees="Traffic sent and received by this device, plus broadcast and "
             "multicast reaching it.",
        blind_to="Everything else on the network. Two other machines talking to "
                 "each other never reach this Pi, so no rule can match them.",
        hardware="Nothing. This is how the device works out of the box.",
        can_apply=True,
        # Explicitly none. It inherited wired_needed=1 and was then refused on a
        # board with no Ethernet - the one layout that always works, turned down
        # with "a USB Ethernet adapter adds one" printed under a card that says
        # it needs nothing. A Zero W watching its own traffic over Wi-Fi is a
        # sensor, and this is the layout it has.
        wired_needed=0,
        steps=(
            "Nothing to do. This is the layout you already have.",
            "Useful for trying rules out and for watching a single exposed host.",
            "Move to one of the other layouts once you want to watch the network.",
        ),
        roles=("capture",),
    ),
    Profile(
        id="mirror",
        name="Mirror port on a switch",
        summary="A managed switch sends a copy of the traffic to the Pi.",
        sees="A copy of everything on the mirrored ports or VLAN, in both "
             "directions if the switch is set up for it.",
        blind_to="Ports that were not put in the mirror, and anything the switch "
                 "drops while it is busy. The copy is made in software.",
        hardware="A switch that can mirror, and a second way into the panel, "
                 "because the mirror port usually stops carrying normal traffic.",
        steps=(
            "Find the feature in the switch. It is called port mirroring, SPAN "
            "or monitor mode depending on the make.",
            "Pick what to copy. The uplink port shows everything going in and "
            "out of the network; individual ports show what those machines say "
            "to each other.",
            "Set the destination to the port this Pi is plugged into.",
            "Make sure the mirror covers both directions. Copying only inbound "
            "traffic hides half of every conversation and most rules will never "
            "match.",
            "Keep a second way into the panel: Wi-Fi or a USB Ethernet adapter.",
            "No managed switch? A network tap in the cable makes the same copy "
            "in hardware, and this device is set up for it exactly the same way. "
            "Get an aggregating one: a tap with a monitor output per direction "
            "needs two capture interfaces, and this panel configures one.",
        ),
        roles=("capture", "management"),
        usable_needed=2,
        capture_has_address=False,
        can_apply=True,
    ),
    Profile(
        id="bridge",
        name="Inline bridge",
        # The engine can still fall behind on a busy link; the wiring does not
        # change that, and the capture loss counter is where it shows.
        # Not "the only layout that can stop a packet": "This device only"
        # blocks too, through the queue, for this Pi's own traffic.
        summary="Traffic passes through the Pi rather than a copy of it. The "
                "only layout that can stop traffic for the whole network.",
        sees="Everything crossing the link, in both directions. Whether the "
             "engine kept up with all of it is in its capture loss counter on "
             "the IDS screen.",
        blind_to="Traffic that does not cross this link, the same as a tap.",
        hardware="Two wired interfaces for the traffic, and a third way into the "
                 "panel: Wi-Fi or a USB Ethernet adapter. The link runs through "
                 "this device, so the port you administer it on cannot be one of "
                 "the two carrying it.",
        steps=(
            "Unplug the cable between the router and the switch.",
            "Run it into the first interface of the Pi, and a second cable from "
            "the Pi to the switch.",
            "The panel builds the bridge itself and points the engine at it: the "
            "device forwards between the two while the engine inspects.",
            "To block, switch Detection mode on the Protection screen. The "
            "forwarding moves from the kernel to the engine, the two cables stay "
            "where they are, and rules loaded with drop start stopping packets.",
            "Know the cost: the link now depends on this Pi. A reboot or a wedged "
            "engine is an outage unless a fail-open relay is fitted.",
        ),
        roles=("bridge_a", "bridge_b", "management"),
        wired_needed=2,
        usable_needed=2,
        passive=False,
        can_block=True,
        blocking_cost="While it only watches, the kernel forwards the frames and "
                      "the engine reads a copy: a stopped engine costs inspection "
                      "and nothing else. Switch it to blocking and the forwarding "
                      "becomes the engine's, so a stopped, restarting or upgrading "
                      "engine is a link that carries nothing. That swap is the "
                      "Detection mode switch, not a different set of cables.",
        capture_has_address=False,
        can_apply=True,
    ),
)

# The layout that was here and is not any more: "The Pi is the router".
# It was the only profile the panel could not put into effect, so picking it
# led to a step that said so and a stored value whose one effect was to make
# Apply refuse. Two of its own sentences were false as well - the card showed
# a "watch only" pill above a summary reading "which can block", and it said
# the panel writes no NFQUEUE rule when rapi-ips-mode writes exactly that. The
# knowledge worth keeping - what real blocking needs, and which way it fails -
# lives on the protection screen, where somebody actually asks the question.

PROFILES_BY_ID = {p.id: p for p in PROFILES}

ROLE_LABELS = {
    "capture": "Capture",
    "management": "Panel access",
    "bridge_a": "Towards the router",
    "bridge_b": "Towards the network",
    "wan": "Towards the modem",
    "lan": "Towards the network",
}


def _availability(profile: Profile, counts: dict[str, int]) -> dict[str, Any]:
    """Whether this hardware can do this layout, and if not, exactly why.

    Unavailable layouts are still returned and still drawn. Hiding the inline
    bridge on a one-port Pi saves a line of screen and costs the reader the one
    fact they needed: that a cheap USB adapter is the whole difference.
    """
    if counts["wired"] < profile.wired_needed:
        return {
            "available": False,
            "reason": (
                f"Needs {profile.wired_needed} wired "
                f"{'interface' if profile.wired_needed == 1 else 'interfaces'}, "
                f"this device has "
                f"{counts['wired']}. A USB Ethernet adapter adds one."
            ),
        }
    if counts["usable"] < profile.usable_needed:
        return {
            "available": False,
            "reason": (
                "Needs a second interface for the panel itself, so that capture "
                "can have the wired port to itself. Wi-Fi counts, and so does a "
                "USB Ethernet adapter."
            ),
        }
    return {"available": True, "reason": ""}


def _stored() -> dict[str, Any]:
    stored = settings.get(SETTINGS_KEY) or {}
    return dict(settings.DEFAULTS[SETTINGS_KEY], **stored)


def state(client_ip: str | None = None, local_ip: str | None = None) -> dict[str, Any]:
    """Everything the wizard needs: the hardware, the layouts, the choice made."""
    hardware = interfaces.detect(client_ip, local_ip)
    counts = hardware["counts"]

    profiles = []
    for profile in PROFILES:
        entry = {
            "id": profile.id,
            "name": profile.name,
            "summary": profile.summary,
            "sees": profile.sees,
            "blind_to": profile.blind_to,
            "hardware": profile.hardware,
            "steps": list(profile.steps),
            "roles": [{"id": r, "label": ROLE_LABELS[r]} for r in profile.roles],
            "passive": profile.passive,
            "can_block": profile.can_block,
            "blocking_needs": profile.blocking_needs,
            "blocking_cost": profile.blocking_cost,
            "capture_has_address": profile.capture_has_address,
            "can_apply": profile.can_apply,
        }
        entry.update(_availability(profile, counts))
        profiles.append(entry)

    current = _stored()
    # A layout that has since been removed - "Network tap" and "The Pi is the
    # router" both were - would otherwise come back as a choice the wizard
    # cannot find a card for: the first step shows nothing selected and every
    # step after it renders blank. Reported as no choice at all, which is what
    # it now is. Nothing on the engine side is touched: the capture interface
    # and HOME_NET stay exactly as they were written.
    if current.get("profile") and current["profile"] not in PROFILES_BY_ID:
        current = {**current, "profile": "", "roles": {},
                   "retired": _stored().get("profile", "")}

    return {
        "hardware": hardware,
        "profiles": profiles,
        "current": current,
    }


def assign(profile_id: str, roles: dict[str, str], client_ip: str | None = None,
           persist: bool = True, local_ip: str | None = None) -> dict[str, Any]:
    """Record which interface plays which part in the chosen layout.

    With persist off this is a dry run: same validation, same warnings, nothing
    written. The wizard uses it to show the consequences of a choice while the
    choice is still being made, which is the only moment the warning about
    handing away the management interface is any use.

    Validated against the hardware as it is right now rather than against what
    was there when the page was opened: an adapter can be pulled out between the
    two, and the panel should say so instead of writing a role for an interface
    that has gone.
    """
    profile = PROFILES_BY_ID.get(profile_id)
    if profile is None:
        raise ValueError(f"unknown layout: {profile_id}")

    hardware = interfaces.detect(client_ip, local_ip)
    by_name = {link["name"]: link for link in hardware["links"]}

    cleaned: dict[str, str] = {}
    for role in profile.roles:
        name = (roles.get(role) or "").strip()
        if not name:
            raise ValueError(f"no interface chosen for: {ROLE_LABELS[role]}")
        if name not in by_name:
            raise ValueError(f"no such interface: {name}")
        if name in cleaned.values():
            raise ValueError(f"{name} cannot fill two roles at once")
        cleaned[role] = name

    warnings = _warnings(profile, cleaned, hardware)
    if persist:
        stored = _stored()
        # The same layout with the same interfaces, saved again, is still the
        # one the engine runs: walking back through the wizard and pressing
        # "Save and continue" used to mark it unapplied, and blocking then
        # refused with "apply the layout first" on a device running exactly
        # that layout. Anything that differs is a new choice, not yet live.
        unchanged = (stored.get("applied") and stored.get("profile") == profile_id
                     and (stored.get("roles") or {}) == cleaned)
        if unchanged:
            record = {**stored, "chosen_at": datetime.now().astimezone()
                      .isoformat(timespec="seconds")}
        else:
            record = {
                "profile": profile_id,
                "roles": cleaned,
                "chosen_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                # Nothing has been written to the engine yet. Kept explicit so
                # the panel never reports a layout as live on the strength of
                # someone having clicked through a wizard.
                "applied": False,
            }
        settings.set(SETTINGS_KEY, record)
        log.info("Topology set to %r: %s (%s)", profile_id, cleaned,
                 "unchanged, still applied" if unchanged else "not applied yet")
    return {"profile": profile_id, "roles": cleaned, "warnings": warnings, "saved": persist}


def _warnings(profile: Profile, roles: dict[str, str],
              hardware: dict[str, Any]) -> list[str]:
    """Things that are allowed but will bite.

    Not errors. Someone rewiring a device on purpose knows more about their desk
    than the panel does, so the panel says what it sees and lets them proceed.
    """
    by_name = {link["name"]: link for link in hardware["links"]}
    management = hardware["management"]
    notes: list[str] = []

    capture_roles = [r for r in ("capture", "bridge_a", "bridge_b", "wan") if r in roles]

    # Only layouts that strip the address can cut anybody off. "This device only"
    # captures on an interface that keeps working normally, and warning about it
    # there would train people to click past the warning that matters.
    if not profile.capture_has_address:
        for role in capture_roles:
            if roles[role] == management:
                notes.append(
                    f"{management} is how this browser is talking to the panel. Giving "
                    f"it the {ROLE_LABELS[role].lower()} role takes its address away, so "
                    "the panel becomes unreachable at the address you are using now. "
                    "Have the other way in working first."
                )

    mgmt = roles.get("management")
    if mgmt and (link := by_name.get(mgmt)):
        if link["kind"] == "wireless" and link["blocked"]:
            notes.append(
                f"{mgmt} is a radio that is switched off in software. Turn it on and "
                "connect it to a network before this layout is applied, or there will "
                "be no way back into the panel."
            )
        elif link["kind"] == "wireless" and not link["ipv4"]:
            notes.append(
                f"{mgmt} has no address yet. Connect it to a network before this "
                "layout is applied."
            )
        elif not link["carrier"]:
            notes.append(f"{mgmt} has no link. Check that the cable is in.")

    for role in capture_roles:
        link = by_name.get(roles[role])
        if link and not link["carrier"]:
            notes.append(
                f"{roles[role]} has no link at the moment, so nothing will arrive on "
                "it until the cable is connected."
            )
        if link and link["kind"] == "wireless":
            notes.append(
                f"{roles[role]} is a Wi-Fi interface. A Wi-Fi client only receives "
                "its own traffic, so it cannot be used to watch a network."
            )

    return notes
