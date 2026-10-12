"""The "intrusion prevention" view - categories instead of 68k individual rules.

The idea (same as UniFi): a user does not want to manage rule files, only to
switch a handful of understandable detection groups on and off. Categories are
built from the `msg` prefix of Emerging Threats rules ("ET MALWARE ...",
"GPL NETBIOS ..."), because that is the only grouping that survives merging the
rule set into a single `suricata.rules`.

Disabling a category = one `re:` line in disable.conf + `suricata-update
--offline` (a rebuild from the previously downloaded cache, no network access).
We never hand-edit the rules themselves.
"""
from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ... import config

log = logging.getLogger(__name__)

# Read, never written: the mode view answers "what is the engine actually doing",
# and that answer lives in the packaged file. Same env var as logdir.py uses.
SURICATA_YAML = Path(os.environ.get("RAPI_SURICATA_YAML", "/etc/suricata/suricata.yaml"))

# Link state of the capture interfaces is read from here. Overridable for the
# same reason the file above is: the tests need a machine they can describe.
# linux/if.h. The flag that makes a mirror port worth having.
IFF_PROMISC = 0x100

SYS_NET = Path(os.environ.get("RAPI_SYS_NET", "/sys/class/net"))

STATE_PATH = config.DATA_DIR / "protection.json"
DISABLE_CONF = config.DATA_DIR / "disable.conf"
# The other half of the same idea. disable.conf decides which rules exist;
# drop.conf decides which of them are loaded with `drop` instead of `alert`.
# Written on every rebuild whether or not anything is in it, because
# suricata-update without it rebuilds every rule as `alert` and says nothing -
# the same silent undo that disable.conf exists to prevent.
DROP_CONF = config.DATA_DIR / "drop.conf"

# msg prefix: rule set marker (ET/GPL/SURICATA) + group. Commented-out rules are
# matched too, so we know both the total and the active count per category.
#
# The group accepts lower case and a dot because Emerging Threats writes one
# that way: "ET Threatview.io High Confidence Cobalt Strike C2". With the group
# limited to [A-Z0-9_] that matched a bare "T", fell out of the index and left
# 22 high confidence C2 rules sitting in the residual bucket - detecting
# perfectly well, filed under nothing. Widening this on its own moves no rule
# anywhere: checked over the whole set, same 68 572 rules matched and zero
# changed category. It only makes the group below reachable.
_RULE_RE = re.compile(
    rb'^(#\s*)?(?:alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s'
    rb'.*?msg:\s*"([A-Z0-9_]+)(?: ([A-Za-z0-9_.]+))?'
)

# Emerging Threats rates every rule it ships in `metadata: signature_severity`,
# on a scale of its own: "we do not reference suricata's own alert.severity".
# Informational means "activity which may not be malicious in and of itself, but
# useful to record to add context to other events" - 15 023 of the 68 556 rules
# in the set here, and most of the volume on a quiet network.
#
# This cuts across the categories above rather than sitting inside one of them:
# the rating is in the metadata, the categories come from the msg prefix, and a
# rule ET calls Informational can carry any prefix at all. So it gets its own
# switch and its own line in disable.conf.
INFORMATIONAL_METADATA = ("signature_severity", "Informational")
_INFORMATIONAL_RE = re.compile(
    rb'metadata:[^;]*\bsignature_severity\s+Informational\b', re.IGNORECASE
)


@dataclass(frozen=True)
class Category:
    id: str
    name: str
    description: str
    # ("ET", "MALWARE") - a None second element means "the whole family", e.g. SURICATA
    groups: tuple[tuple[str, str | None], ...] = ()
    locked: bool = False   # the "other" bucket - cannot be expressed as a regex


CATEGORIES: list[Category] = [
    Category(
        id="botnet",
        name="Botnets and threat intelligence",
        description="Reputation lists, C2 servers, abused services and dynamic DNS",
        groups=(
            ("ET", "DROP"), ("ET", "CINS"), ("ET", "COMPROMISED"), ("ET", "CNC"),
            ("ET", "TA_ABUSED_SERVICES"), ("ET", "DYN_DNS"), ("ET", "JA3"),
            # Written in lower case with a dot, unlike every other group ET
            # ships. UniFi lists the same one as THREATVIEW_CS_C2.
            ("ET", "Threatview.io"),
        ),
    ),
    Category(
        id="malware",
        name="Viruses, malware and spyware",
        description="Malicious software, phishing, adware, coin miners, remote access",
        groups=(
            ("ET", "MALWARE"), ("ET", "MOBILE_MALWARE"), ("ET", "ADWARE_PUP"),
            ("ET", "PHISHING"), ("ET", "COINMINER"), ("ET", "WORM"),
            ("ET", "REMOTE_ACCESS"), ("GPL", "MALWARE"), ("GPL", "WORM"),
            ("GPL", "REMOTE_ACCESS"),
        ),
    ),
    Category(
        id="exploit",
        name="Hacking and exploits",
        description="Web application attacks, exploit kits, SQL injection, shellcode",
        groups=(
            ("ET", "EXPLOIT"), ("ET", "EXPLOIT_KIT"), ("ET", "WEB_SPECIFIC_APPS"),
            ("ET", "WEB_SERVER"), ("ET", "WEB_CLIENT"), ("ET", "ACTIVEX"),
            ("ET", "SHELLCODE"), ("ET", "SQL"), ("GPL", "EXPLOIT"),
            ("GPL", "WEB_SERVER"), ("GPL", "WEB_CLIENT"), ("GPL", "WEB_SPECIFIC_APPS"),
            ("GPL", "SQL"), ("GPL", "ACTIVEX"), ("GPL", "SHELLCODE"),
        ),
    ),
    Category(
        id="p2p",
        name="Peer to peer and dark web",
        description="Torrents, file sharing, the Tor network, chat clients and games",
        groups=(
            ("ET", "P2P"), ("GPL", "P2P"), ("ET", "FILE_SHARING"), ("ET", "TOR"),
            ("ET", "GAMES"), ("GPL", "GAMES"), ("ET", "CHAT"), ("GPL", "CHAT"),
            ("ET", "INAPPROPRIATE"), ("GPL", "INAPPROPRIATE"),
        ),
    ),
    Category(
        id="attack",
        name="Attacks and reconnaissance",
        description="Port scanning, responses from compromised hosts, DoS, industrial systems",
        groups=(
            ("ET", "SCAN"), ("GPL", "SCAN"), ("ET", "ATTACK_RESPONSE"),
            ("GPL", "ATTACK_RESPONSE"), ("ET", "DOS"), ("GPL", "DOS"), ("ET", "SCADA"),
        ),
    ),
    Category(
        id="protocol",
        name="Protocol vulnerabilities",
        description="DNS, SMB/NetBIOS, mail, FTP, SNMP and VoIP abuse, plus the "
                    "engine's own stream and decoder events (SURICATA STREAM ...)",
        groups=(
            ("ET", "DNS"), ("GPL", "DNS"), ("ET", "FTP"), ("GPL", "FTP"),
            ("GPL", "IMAP"), ("GPL", "POP3"), ("ET", "SMTP"), ("GPL", "SMTP"),
            ("ET", "SNMP"), ("GPL", "SNMP"), ("ET", "TELNET"), ("GPL", "TELNET"),
            ("ET", "TFTP"), ("GPL", "TFTP"), ("ET", "VOIP"), ("GPL", "VOIP"),
            ("ET", "NETBIOS"), ("GPL", "NETBIOS"), ("ET", "RPC"), ("GPL", "RPC"),
            ("GPL", "ICMP"), ("GPL", "MISC"), ("ET", "MISC"), ("SURICATA", None),
        ),
    ),
    Category(
        id="info",
        # Not "Informational ...": the switch below the categories is about the
        # rule set's own severity rating, this is about the name a rule carries,
        # and two controls with the same word on one screen is one control
        # nobody can predict.
        name="Advisory, hunting and current events",
        description="Records what happened rather than that something is wrong: "
                    "STUN, DNS lookups of known services, package manager "
                    "User-Agents. Nearly every chatty signature lives here",
        groups=(
            ("ET", "INFO"), ("GPL", "INFO"), ("ET", "HUNTING"), ("ET", "USER_AGENTS"),
            ("ET", "CURRENT_EVENTS"), ("ET", "RETIRED"),
        ),
    ),
    Category(
        id="other",
        name="Everything else",
        description="Signatures outside the groups above. They stay enabled",
        locked=True,
    ),
]

CATEGORY_BY_ID = {c.id: c for c in CATEGORIES}

# ("ET","MALWARE") -> category id; ("SURICATA", None) goes into _FAMILY_INDEX
_GROUP_INDEX: dict[tuple[str, str], str] = {}
_FAMILY_INDEX: dict[str, str] = {}
for _cat in CATEGORIES:
    for _vendor, _group in _cat.groups:
        if _group is None:
            _FAMILY_INDEX[_vendor] = _cat.id
        else:
            _GROUP_INDEX[(_vendor, _group)] = _cat.id

# What only ever alerts, in the mode that blocks. Everything else an enabled
# category loads is written as `drop`, which is how a UniFi gateway does it: its
# rule file, read on 2026-09-14, had 32 628 rules as drop and 315 as alert, and
# the 315 were all noalert rules. suricata-update never turns a noalert rule into
# a drop on its own (DropRuleFilter.match), so those need nothing here.
#
# The two below are ours. The advisory category records what happened rather
# than that something is wrong, and the gateway does not get it on its tier at
# all. The engine's own protocol events (SURICATA STREAM, decoder) are anomalies
# of ordinary traffic: 106 857 of them in thirty days on this device, every one
# of which would have been a connection cut. The gateway loads none of them.
#
# In a mode that only reads a copy, a rule loaded as `drop` behaves exactly like
# `alert` and the event says "allowed" (checked with suricata -r on a capture
# file), so the policy is written whatever the mode, and switching the mode
# never needs a rebuild.
ALERT_ONLY_CATEGORIES = ("info",)
ALERT_ONLY_FAMILIES = ("SURICATA",)


def _alert_only(vendor: str, cat_id: str) -> bool:
    return vendor in ALERT_ONLY_FAMILIES or cat_id in ALERT_ONLY_CATEGORIES


def _alert_only_prefixes() -> list[str]:
    """The msg prefixes of everything that only alerts, as they start a rule name."""
    prefixes = list(ALERT_ONLY_FAMILIES)
    for cat in CATEGORIES:
        if cat.id in ALERT_ONLY_CATEGORIES:
            prefixes += [vendor if group is None else f"{vendor} {group}"
                         for vendor, group in cat.groups]
    return prefixes


@dataclass
class RuleScan:
    total: int = 0
    enabled: int = 0
    # Unix seconds, which is what st_mtime already is. It was turned into an ISO
    # string here and back into a Date in the browser, for no reader in between.
    updated_at: float | None = None
    per_category: dict[str, dict[str, int]] = field(default_factory=dict)
    # Counted alongside the categories, not inside them: a rule appears in
    # exactly one category and, independently, may or may not be informational.
    # So these numbers overlap the ones above and must not be added to them.
    informational: dict[str, int] = field(default_factory=lambda: {"total": 0, "enabled": 0})
    # Enabled rules the blocking policy says should be `drop` and the file still
    # has as `alert`: the rule set has not been rebuilt since the policy
    # changed. A panel upgraded from before the policy existed starts with
    # every one of them here, and the screen says so instead of reporting
    # blocking that stops only what the vendor ships as drop.
    blocking_pending: int = 0
    # Enabled rules loaded as `drop` and marked noalert: a packet stopped with no
    # alert to show for it, so nothing to find and nothing to allow. They come
    # from suricata-update itself. It turns a rule into a drop before it
    # resolves flowbits, and then switches on the rules another rule's flowbit
    # needs, which ET ships disabled, adding noalert to each. 125 of them on
    # this device on the first rebuild with the policy, 113 of them ET
    # EXPLOIT_KIT and one that drops RDP resets. Counted as pending too.
    silent_drops: frozenset[int] = frozenset()


_scan_cache: tuple[tuple[int, int, frozenset[int]], RuleScan] | None = None

_SID_RE = re.compile(rb'[\s;(]sid:\s*(\d+)\s*;')


def _sid_of(line: bytes) -> int | None:
    match = _SID_RE.search(line)
    return int(match.group(1)) if match else None


def _rules_file() -> Path:
    return config.SURICATA_RULES_DIR / "suricata.rules"


RULES_DATE_HELPER = "/usr/local/sbin/rapi-rules-date"

_source_cache: tuple[tuple[int, int] | None, dict[str, float | None]] | None = None


def _read_source_dates() -> dict[str, float | None]:
    """Ask the root-owned helper for the vendor build date and the fetch date."""
    unknown: dict[str, float | None] = {"built": None, "fetched": None}
    # A checkout that has never run install-service.sh has no helper, and asking
    # sudo about a command it was never granted costs a fork per rebuild to be
    # told so. Checked here rather than swallowed as a non-zero exit.
    if not Path(RULES_DATE_HELPER).exists():
        return unknown
    try:
        proc = subprocess.run(["sudo", "-n", RULES_DATE_HELPER],
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return unknown
    if proc.returncode != 0:
        return unknown
    dates = dict(unknown)
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in dates:
            try:
                dates[parts[0]] = float(parts[1])
            except ValueError:
                pass
    return dates


def source_dates() -> dict[str, float | None]:
    """When the vendor built this signature set, and when we downloaded it.

    The screen used to date the rules by the mtime of the merged rule file. That
    file is rewritten from the local cache by every category switch and every
    silenced signature, so one click made a month old set look like today's.

    Cached against the same rule file: nothing can change these two dates without
    also rebuilding it. A failure is deliberately not cached - the usual cause is
    a helper that has not been installed yet, and installing it does not touch
    the rule file, so a cached "unknown" would outlive its own fix.
    """
    global _source_cache
    path = _rules_file()
    key: tuple[int, int] | None = None
    if path.is_file():
        st = path.stat()
        key = (st.st_mtime_ns, st.st_size)
    if _source_cache is not None and _source_cache[0] == key:
        return _source_cache[1]
    dates = _read_source_dates()
    if dates["built"] is not None:
        _source_cache = (key, dates)
    return dates


def scan_rules(force: bool = False) -> RuleScan:
    """Count signatures in the merged rule file, split by category.

    Scanning 45 MB takes about 0.2 s on a Pi 5, but the endpoint is polled
    often, so the result is cached until the file changes (mtime + size).
    """
    global _scan_cache
    path = _rules_file()
    if not path.is_file():
        return RuleScan()

    st = path.stat()
    # Allowed signatures change what counts as pending without touching the
    # file, so they are part of what makes a cached scan stale.
    allowed = frozenset(int(sid) for sid in load_state()["allowed"])
    key = (st.st_mtime_ns, st.st_size, allowed)
    if not force and _scan_cache is not None and _scan_cache[0] == key:
        return _scan_cache[1]

    scan = RuleScan(updated_at=st.st_mtime)
    silent: set[int | None] = set()
    counters: dict[str, dict[str, int]] = {
        c.id: {"total": 0, "enabled": 0, "informational": 0} for c in CATEGORIES
    }

    with path.open("rb") as handle:
        for line in handle:
            match = _RULE_RE.match(line)
            if not match:
                continue
            commented, vendor_b, group_b = match.groups()
            vendor = vendor_b.decode()
            group = group_b.decode() if group_b else ""
            cat_id = _GROUP_INDEX.get((vendor, group)) or _FAMILY_INDEX.get(vendor) or "other"
            bucket = counters[cat_id]
            bucket["total"] += 1
            scan.total += 1
            informational = _INFORMATIONAL_RE.search(line) is not None
            if informational:
                scan.informational["total"] += 1
                # Counted over the whole category, enabled or not, because this
                # is what answers "what does that switch cost me here" - and it
                # has to answer it while the rules are still switched off.
                bucket["informational"] += 1
            if not commented:
                bucket["enabled"] += 1
                scan.enabled += 1
                if informational:
                    scan.informational["enabled"] += 1
                if (line.startswith(b"alert") and b"noalert" not in line
                        and not _alert_only(vendor, cat_id)
                        and (not allowed or _sid_of(line) not in allowed)):
                    scan.blocking_pending += 1
                if line.startswith(b"drop") and b"noalert" in line:
                    silent.add(_sid_of(line))

    scan.per_category = counters
    silent.discard(None)
    scan.silent_drops = frozenset(silent)  # type: ignore[arg-type]
    scan.blocking_pending += len(scan.silent_drops)
    _scan_cache = (key, scan)
    return scan


# --- user selection state ------------------------------------------------


def _default_state() -> dict[str, Any]:
    # Everything on by default - that is what a fresh suricata-update set looks
    # like, so the panel does not lie before the user touches anything.
    return {
        "categories": {c.id: True for c in CATEGORIES if not c.locked},
        # On, for the same reason the categories are: it is what a fresh
        # suricata-update set looks like, and a panel whose switches disagree
        # with the rule file is worse than one that starts noisy.
        "informational": True,
        # Individually silenced signatures: {"2200121": "SURICATA Ethertype unknown"}.
        # Keyed by string because that is what JSON gives back anyway.
        "muted": {},
        # Signatures loaded with `drop` instead of `alert`, same shape as muted.
        # Empty by default and deliberately so: a rule set where something drops
        # is a decision, not a default, and on an engine that only watches these
        # behave exactly like `alert` anyway.
        "dropped": {},
        # Signatures that alert and are never dropped, same shape again. The
        # exception to the blocking policy, for a signature that matches
        # something wanted: a remote access tool, a service a rule mistakes.
        "allowed": {},
        # Signatures suricata-update switches on only for another rule's
        # flowbit. Kept out of the policy by SID, so they load as the silent
        # helpers they are and never as silent drops. Found in the merged
        # file after a rebuild. A SID leaves the list only when the file shows
        # it as an ordinary enabled alert: dropped while it is still a helper,
        # the next rebuild would turn it back into a silent drop.
        "flowbit_only": {},
        "applied_at": None,
        "applied": True,
    }


def load_state() -> dict[str, Any]:
    state = _default_state()
    try:
        stored = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return state
    for key, value in (stored.get("categories") or {}).items():
        if key in state["categories"]:
            state["categories"][key] = bool(value)
    for sid, label in (stored.get("muted") or {}).items():
        if str(sid).isdigit():
            state["muted"][str(sid)] = str(label or "")
    for key in ("dropped", "allowed", "flowbit_only"):
        for sid, label in (stored.get(key) or {}).items():
            if str(sid).isdigit():
                state[key][str(sid)] = str(label or "")
    if "informational" in stored:
        state["informational"] = bool(stored["informational"])
    state["applied_at"] = stored.get("applied_at")
    state["applied"] = bool(stored.get("applied", True))
    return state


def save_state(state: dict[str, Any]) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2), encoding="utf-8")


def write_disable_conf(state: dict[str, Any] | None = None) -> Path:
    """disable.conf for suricata-update: disabled groups plus silenced SIDs.

    Takes the whole state rather than its pieces on purpose: a caller that
    passed only the categories used to wipe every silenced signature out of the
    file, which quietly un-silenced them on the next rule update.
    """
    state = state if state is not None else load_state()
    selection = state["categories"]
    muted = state["muted"]
    lines = [
        "# Generated by RaPi IDS Panel. Do not edit by hand.",
        "# Each line disables one signature group (matched on the msg field),",
        "# one rating (matched on the rule metadata), or one signature by SID.",
    ]

    if not state.get("informational", True):
        key, value = INFORMATIONAL_METADATA
        lines.append("# Signatures the rule set rates as informational")
        lines.append(f"metadata: {key} {value}")
    for cat in CATEGORIES:
        if cat.locked or selection.get(cat.id, True):
            continue
        lines.append(f"# {cat.name}")
        for vendor, group in cat.groups:
            # These go into a file suricata-update reads as regular expressions,
            # and one group name contains a dot. Unescaped it would match
            # "Threatview.ionosphere" as happily as "Threatview.io". The
            # trailing class is what stops "ET DNS" from also disabling
            # "ET DNS_FOO", and it excludes lower case and the dot for the same
            # reason now that a group can end in either.
            if group is None:
                lines.append(rf're:msg:\s*"{re.escape(vendor)}[^A-Za-z0-9_.]')
            else:
                lines.append(
                    rf're:msg:\s*"{re.escape(vendor)} {re.escape(group)}[^A-Za-z0-9_.]'
                )

    if muted:
        lines.append("# Signatures silenced one by one from the alert view")
        for sid in sorted(muted, key=int):
            # The comment is for whoever reads the file; suricata-update only
            # needs the bare number.
            label = muted[sid].replace("\n", " ").strip()
            lines.append(f"# {label}" if label else "#")
            lines.append(sid)

    DISABLE_CONF.parent.mkdir(parents=True, exist_ok=True)
    DISABLE_CONF.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return DISABLE_CONF


def blocking_pattern(excluded: Iterable[str] | None = None) -> str:
    """The one drop.conf line that is the blocking policy.

    Every rule, except the ones that only alert and the allowed signatures.
    One line with two exclusions rather than a line per category: a line per
    category cannot reach the signatures that belong to none, and a rule set
    that grows a group tomorrow would load it as `alert` until somebody noticed.

    suricata-update compiles it case-insensitively and searches the rule text,
    which starts at the action, so both lookaheads scan the whole rule. It also
    cuts a line at " #", which is why nothing in here may contain a hash.
    """
    names = "|".join(re.escape(prefix) for prefix in _alert_only_prefixes())
    pattern = rf'^(?!.*msg:\s*"(?:{names})[^A-Za-z0-9_.])'
    sids = sorted({sid for sid in (excluded or ()) if sid.isdigit()}, key=int)
    if sids:
        pattern += rf'(?!.*[\s;(]sid:\s*(?:{"|".join(sids)})\s*;)'
    return "re:" + pattern


def write_drop_conf(state: dict[str, Any] | None = None) -> Path:
    """drop.conf for suricata-update: the rules loaded as `drop`, not `alert`.

    Always written, and always with the policy in it. suricata-update given no
    --drop-conf rebuilds every rule as `alert` and reports success, so a file
    that stops being passed is a rule set that quietly stops blocking. The
    daily refresh reads this same file, so what it says survives the night.

    What makes a packet stop is `drop` in the rule set and the engine being in
    the forwarding path. Neither implies the other: on an engine reading a copy
    every one of these behaves like `alert`.
    """
    state = state if state is not None else load_state()
    allowed = state.get("allowed") or {}
    lines = [
        "# Generated by RaPi IDS Panel. Do not edit by hand.",
        "# Every signature an enabled category loads is a drop, except:",
        "#   rules marked noalert, which suricata-update never turns into drops,",
        "#   the engine's own protocol events and the advisory category, which",
        "#   only alert, and the signatures allowed one by one below.",
        "# On an engine that only reads a copy of the traffic a drop behaves",
        "# exactly like an alert.",
        blocking_pattern([*allowed, *(state.get("flowbit_only") or {})]),
    ]
    flowbit_only = state.get("flowbit_only") or {}
    if flowbit_only:
        lines.append(f"# Kept out by SID: {len(flowbit_only)} rules suricata-update "
                     "enables only for flowbits, as noalert")
    if allowed:
        lines.append("# Allowed: alerted, never dropped")
        for sid in sorted(allowed, key=int):
            label = allowed[sid].replace("\n", " ").strip()
            lines.append(f"#   {sid} {label}".rstrip())

    dropped = {sid: label for sid, label in (state.get("dropped") or {}).items()
               if sid not in allowed}
    if dropped:
        lines.append("# Set to drop one by one")
    for sid in sorted(dropped, key=int):
        label = dropped[sid].replace("\n", " ").strip()
        lines.append(f"# {label}" if label else "#")
        lines.append(sid)

    DROP_CONF.parent.mkdir(parents=True, exist_ok=True)
    DROP_CONF.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return DROP_CONF


def rebuild_command(offline: bool) -> list[str]:
    """Rule set rebuild command - must match deploy/sudoers-rapi-panel exactly."""
    cmd = ["sudo", "-n", "suricata-update"]
    if offline:
        cmd.append("--offline")
    else:
        # Without it a download that fails is not an error to the tool: it
        # writes the 445 rules that ship with the engine, reports success, and
        # 68 000 signatures are gone. Seen on a live device the night after an
        # engine upgrade, which also empties the cache (kept per version).
        cmd.append("--fail")
    # We reload the engine ourselves (/service/reload) so that a failed reload
    # does not look like a failed rule update.
    cmd += ["--no-reload", "--disable-conf", str(DISABLE_CONF),
            "--drop-conf", str(DROP_CONF)]
    return cmd


def rebuild(offline: bool = True, timeout: int = 900) -> tuple[bool, str]:
    """Rebuild suricata.rules honouring the disabled categories."""
    # Both files have to exist before the tool is handed their paths: a fresh
    # checkout, and any device upgraded from before drop.conf existed, has
    # neither, and suricata-update refuses a path it cannot read. Writing them
    # from the stored state rather than touching them empty keeps a rebuild
    # after a manual deletion from silently un-silencing everything.
    if not DISABLE_CONF.exists() or not DROP_CONF.exists():
        state = load_state()
        write_disable_conf(state)
        write_drop_conf(state)
    cmd = rebuild_command(offline)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"the signature rebuild did not finish within {timeout}s"
    except FileNotFoundError:
        return False, "the signature update tool is missing"
    output = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        if "sudo" in output and "password" in output.lower():
            output += (
                "\n\nThe panel is not allowed to run this command. Install the sudoers entry: "
                "scripts/install-service.sh (or deploy/sudoers-rapi-panel by hand)."
            )
        elif offline and "has not yet been downloaded" in output:
            # suricata-update keys its cache by the exact engine version, so any
            # engine upgrade leaves the offline rebuild with nothing to work from.
            output += (
                "\n\nThe signature set has not been downloaded for this engine version yet. "
                "Press \"Update signatures\" once. After that, changing categories "
                "works without network again."
            )
        return False, output
    scan_rules(force=True)
    return True, output


def apply_selection(selection: dict[str, bool], informational: bool | None = None,
                    offline: bool = True) -> tuple[bool, str]:
    """Store what the protection screen has selected and rebuild the rule set.

    Categories and the informational rating go through here together because
    they end in the same file and the same rebuild: two calls would mean two
    rebuilds of 68 556 rules for one visit to one screen.
    """
    def change(state: dict[str, Any]) -> None:
        state["categories"].update(
            {k: bool(v) for k, v in selection.items() if k in state["categories"]})
        if informational is not None:
            state["informational"] = bool(informational)

    return _change_and_rebuild(change, offline)


# --- silencing one signature at a time ------------------------------------

# `sid:2200121;` inside a rule line, commented out or not.
_SID_RE_TEMPLATE = rb'^(#\s*)?(?:alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s.*?msg:\s*"([^"]*)".*?\bsid:\s*%d\s*;'


def lookup_signature(sid: int) -> str | None:
    """The msg of a rule with this SID, straight from the merged rule file.

    Taking the name from the rules rather than from the caller keeps the stored
    label honest - it is what the engine would actually print.
    """
    pattern = re.compile(_SID_RE_TEMPLATE % sid, re.MULTILINE)
    try:
        with _rules_file().open("rb") as fh:
            for line in fh:
                match = pattern.match(line)
                if match:
                    return match.group(2).decode("utf-8", "replace")
    except OSError:
        return None
    return None


def _add(key: str, sid: int) -> Callable[[dict[str, Any]], None]:
    def change(state: dict[str, Any]) -> None:
        state[key][str(sid)] = lookup_signature(sid) or ""
    return change


def _remove(key: str, sid: int) -> Callable[[dict[str, Any]], None]:
    def change(state: dict[str, Any]) -> None:
        if state[key].pop(str(sid), None) is None:
            raise KeyError(sid)
    return change


def mute(sid: int, offline: bool = True) -> tuple[bool, str]:
    """Silence one signature and rebuild the rule set without it."""
    return _change_and_rebuild(_add("muted", sid), offline)


def unmute(sid: int, offline: bool = True) -> tuple[bool, str]:
    return _change_and_rebuild(_remove("muted", sid), offline)


def _recovered_helpers(listed: Iterable[str]) -> set[str]:
    """Listed flowbit helpers the file now has as an ordinary enabled alert.

    Read here rather than carried on RuleScan: the scan is cached on the rule
    file alone, and this answer depends on the stored list as well, so a cached
    scan would hand a later reader a stale one.

    suricata-update only switches on a rule that is disabled, so a rule that got
    on the list while something here had it off (a mute, the informational
    switch, a category) is back as itself once that is undone, and has to block
    again.
    """
    wanted = {int(sid) for sid in listed if sid.isdigit()}
    if not wanted:
        return set()
    found: set[str] = set()
    try:
        with _rules_file().open("rb") as handle:
            for line in handle:
                if line.startswith(b"alert") and b"noalert" not in line:
                    sid = _sid_of(line)
                    if sid in wanted:
                        found.add(str(sid))
    except OSError:
        return set()
    return found


def record_silent_drops(state: dict[str, Any]) -> bool:
    """Bring the flowbit helper list in line with the merged file.

    Adds the silent drops, and takes out the SIDs that are ordinary alerts
    again. True if the list changed, which means the policy did too.
    """
    listed = state["flowbit_only"]
    new = {str(sid) for sid in scan_rules(force=True).silent_drops} - set(listed)
    back = _recovered_helpers(listed)
    for sid in sorted(new, key=int):
        listed[sid] = ""
    for sid in back:
        listed.pop(sid, None)
    if new or back:
        save_state(state)
    return bool(new or back)


# One suricata-update at a time from this process, and one change to the
# stored state around it: the screen and the check that keeps the rule set on
# the policy can both start one, and two writing the same merged file is a rule
# set that is neither.
#
# The state is read inside the lock, never before it. A change read before a
# download finished waited minutes with its copy, and a download read before
# the changes saved its old copy over them when it finished, so a signature
# muted during "Update signatures" could vanish from the state and from the
# next disable.conf.
_REBUILD_LOCK = threading.Lock()


def ensure_disable_conf() -> bool:
    """disable.conf from the stored state if there is none yet. True if written.

    The daily refresh refuses to run without it (a rebuild without it would
    switch every disabled category back on), and until now only a rebuild from
    the panel wrote it. A fresh device therefore never refreshed its rules on
    its own: with no signatures in the image it stayed without any at all, and
    the policy loop, which needs a rule file to look at, could not start it
    either. An existing file is never rewritten here: it was written from a
    state that was read successfully, and that is not known of this one.
    """
    with _REBUILD_LOCK:
        if DISABLE_CONF.exists():
            return False
        write_disable_conf(load_state())
        return True


def refresh_drop_conf() -> None:
    """drop.conf from the stored state and the rule file on disk, no rebuild.

    For the panel starting up: the daily refresh reads this file as it is, so
    a policy change or a silent drop found in last night's file is in effect by
    the next morning without anybody pressing anything.
    """
    with _REBUILD_LOCK:
        state = load_state()
        record_silent_drops(state)
        write_drop_conf(state)


def _change_and_rebuild(change: Callable[[dict[str, Any]], None],
                        offline: bool) -> tuple[bool, str]:
    """Apply one change to the stored state, save it, then rebuild.

    Saved before the rebuild, so a rebuild that fails does not lose the choice.
    A change that raises leaves the state as it was.
    """
    with _REBUILD_LOCK:
        state = load_state()
        change(state)
        state["applied"] = False
        save_state(state)
        return _write_and_rebuild_locked(state, offline)


def _write_and_rebuild_locked(state: dict[str, Any], offline: bool) -> tuple[bool, str]:
    write_disable_conf(state)
    write_drop_conf(state)
    ok, output = rebuild(offline=offline)
    # The silent drops are only visible in what suricata-update wrote, so the
    # first rebuild that produces them is followed by one that keeps them out,
    # and the one that shows a helper back as an ordinary alert by one that
    # lets it block. A second pass is needed again only when one of those
    # changes. Always from the cache: a download has just filled it.
    if ok and record_silent_drops(state):
        write_drop_conf(state)
        ok, again = rebuild(offline=True)
        output = f"{output}\n{again}"
    if ok:
        state["applied"] = True
        state["applied_at"] = datetime.now(timezone.utc).isoformat()
        save_state(state)
    return ok, output


def _listed(key: str) -> list[dict[str, Any]]:
    state = load_state()
    return [
        {"signature_id": int(sid), "signature": label or None}
        for sid, label in sorted(state[key].items(), key=lambda kv: int(kv[0]))
    ]


def muted_signatures() -> list[dict[str, Any]]:
    """Silenced signatures, newest SID last - stable order for the GUI."""
    return _listed("muted")


def allow(sid: int, offline: bool = True) -> tuple[bool, str]:
    """Keep alerting on one signature and never drop it."""
    return _change_and_rebuild(_add("allowed", sid), offline)


def unallow(sid: int, offline: bool = True) -> tuple[bool, str]:
    return _change_and_rebuild(_remove("allowed", sid), offline)


def allowed_signatures() -> list[dict[str, Any]]:
    return _listed("allowed")


def rebuild_from_state(offline: bool = True) -> tuple[bool, str]:
    """Rebuild with what is stored, for a rule set that fell behind the policy."""
    with _REBUILD_LOCK:
        return _write_and_rebuild_locked(load_state(), offline)


def reload_engine() -> tuple[bool, str]:
    """Have the running engine read the rule file again.

    reload-rules over suricatasc is cheaper than restarting the process, and it
    keeps the flow table, so a reload costs no visibility. systemctl is the
    fallback for a build without the unix socket enabled.
    """
    ok, output = False, ""
    for command in (["sudo", "-n", "suricatasc", "-c", "reload-rules"],
                    ["sudo", "-n", "systemctl", "reload", "suricata"]):
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            output = f"{' '.join(command)} did not finish within 120 s"
            continue
        except FileNotFoundError:
            output = f"command not found: {command[0]}"
            continue
        ok, output = proc.returncode == 0, (proc.stdout + proc.stderr).strip()
        if ok:
            break
    return ok, output


# The rule file a catch-up was last attempted on, by mtime and size.
_catch_up_tried: tuple[int, int] | None = None


def _file_key(path: Path) -> tuple[int, int] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return st.st_mtime_ns, st.st_size


def keep_rules_on_policy() -> str | None:
    """Rebuild and reload when the running rule set has fallen behind the policy.

    Without it the screen carried a button somebody had to find: after an
    upgrade of the policy, after a fix to it, and after a signature update that
    brings a rule suricata-update only enables for a flowbit. The panel knows
    each of those the moment it scans the file, so it does the rebuild itself.

    Once per rule file. A rebuild that fails, or one whose result still does not
    follow the policy, is not repeated every few minutes on the same file: the
    next attempt waits for a file that changed, which is the nightly refresh or
    a change on the screen. The warning on the screen stays for that case.

    Returns what it did, for the log, or None when nothing was needed.
    """
    global _catch_up_tried
    path = _rules_file()
    key = _file_key(path)
    if key is None or key == _catch_up_tried:
        return None
    if scan_rules().blocking_pending == 0:
        return None
    _catch_up_tried = key
    ok, output = rebuild_from_state()
    _catch_up_tried = _file_key(path)
    if not ok:
        tail = output.strip().splitlines()[-1] if output.strip() else "no output"
        return f"the rule set is behind the blocking policy and the rebuild failed: {tail}"
    reloaded, said = reload_engine()
    if not reloaded:
        return ("the rule set was rebuilt to follow the blocking policy, but the "
                f"engine would not reload it: {said}")
    return "the rule set was rebuilt to follow the blocking policy and the engine reloaded"


# --- operating mode and monitored interfaces ------------------------------


def _suricata_cmdline() -> str:
    try:
        proc = subprocess.run(
            ["systemctl", "show", "suricata", "-p", "MainPID", "--value"],
            capture_output=True, text=True, timeout=10,
        )
        pid = int((proc.stdout or "0").strip() or 0)
    except (subprocess.SubprocessError, ValueError):
        return ""
    if pid <= 0:
        return ""
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode()
    except OSError:
        return ""


def _config_files() -> list[Path]:
    """suricata.yaml and every file it includes, in the order the engine reads.

    `include:` does not merge. A key defined in an included file replaces the
    one above it, and the panel writes its own af-packet block into one of
    those files: verified against the engine, `suricata --dump-config` on a
    yaml that says eth0 and includes a file that says eth1 answers eth1.

    Both spellings of an include, because rapi-include preserves a site's own
    single-line `include: file` next to the block it writes, and an af-packet
    key in one of those would otherwise be invisible. And followed into the
    included files, depth first, because that is where the engine reads an
    include written inside one: at that point in the stream.
    """
    ordered: list[Path] = []
    seen: set[Path] = set()

    def walk(path: Path, depth: int) -> None:
        # A file that includes itself, or two that include each other, would
        # otherwise recurse until the interpreter gives up.
        resolved = path.resolve() if path.exists() else path
        if resolved in seen or depth > 8:
            return
        seen.add(resolved)
        ordered.append(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        in_block = False
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            if not raw[:1].isspace():
                in_block = False
                if raw.startswith("include:"):
                    value = raw.split(":", 1)[1].strip().strip('"\'')
                    if value:
                        walk(_include_path(path, value), depth + 1)
                    else:
                        in_block = True
                continue
            if in_block:
                stripped = raw.strip()
                if stripped.startswith("- "):
                    name = stripped[2:].strip().strip('"\'')
                    if name:
                        walk(_include_path(path, name), depth + 1)

    walk(SURICATA_YAML, 0)
    return ordered


def _include_path(parent: Path, name: str) -> Path:
    """Relative names are relative to the file that included them, which is how
    the engine resolves them."""
    return Path(name) if name.startswith("/") else parent.parent / name


def _yaml_capture() -> dict[str, Any]:
    """Extract af-packet interfaces and copy mode from the engine's config.

    Deliberately without a YAML parser: we need two fields, while the file is
    87 kB and carries its own macros that plain YAML does not fully understand.

    Every file in the include chain is read, last definition winning, because
    that is what the engine does with them.
    """
    info: dict[str, Any] = {"interfaces": [], "copy_mode_ips": False, "nfqueue": False}
    text = ""
    for path in _config_files():
        try:
            candidate = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Only a file that defines the key replaces it. A file that never
        # mentions af-packet leaves the block above it standing.
        if any(line.startswith("af-packet:") for line in candidate.splitlines()):
            text = candidate

    in_block = False
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[:1].isspace():          # a new top level section
            in_block = raw.startswith("af-packet:")
            continue
        if not in_block:
            continue
        stripped = raw.strip()
        if stripped.startswith("- interface:"):
            iface = stripped.split(":", 1)[1].strip()
            # "default" is a settings template for other interfaces, not an interface
            if iface and iface != "default" and iface not in info["interfaces"]:
                info["interfaces"].append(iface)
        elif stripped.startswith("copy-mode:") and "ips" in stripped:
            info["copy_mode_ips"] = True

    cmdline = _suricata_cmdline()
    info["nfqueue"] = " -q " in f" {cmdline} " or "--nfqueue" in cmdline
    info["cmdline"] = cmdline
    return info


IPS_MODE_BIN = "/usr/local/sbin/rapi-ips-mode"


def drop_rules() -> int:
    """Signatures in the merged file loaded with `drop` rather than `alert`.

    The number the mode switch is meaningless without. Blocking turned on with
    nothing set to drop reports itself as blocking and stops exactly nothing,
    and that reads as a working control rather than as a half-finished one.
    Counted from the file the engine actually loaded, not from drop.conf, so a
    rebuild that quietly did not happen shows up as a zero here.
    """
    try:
        with _rules_file().open("rb") as handle:
            return sum(1 for line in handle if line.startswith(b"drop "))
    except OSError:
        return 0


def _reason(blocking: bool, inline: bool, forwarding: bool,
            dropping: int, pending: int, mirror: bool = False,
            refusal: str = "", switchable: bool = True) -> str:
    """What this mode means here, which the mechanism decides.

    Two mechanisms and therefore two sentences, and the difference is not a
    detail: netfilter with `bypass` lets traffic past when the engine stops,
    while an engine that is doing the forwarding takes the link with it. Saying
    the first on a device doing the second is telling the operator the opposite
    of the risk they accepted.
    """
    if not blocking:
        # The sentence under the switch is the only place a disabled button can
        # explain itself on a phone, where there is no hover.
        if refusal:
            return refusal
        if inline:
            return ("The kernel forwards the frames and the engine reads a copy, "
                    "so a matching rule can only report. Blocking here hands the "
                    "forwarding to the engine instead: the same two cables, and a "
                    "link that then stops while the engine does.")
        if not switchable:
            # No helper, so no buttons: the sentence must not offer what the
            # screen has no way to do.
            return ("The engine reads a copy of the traffic, so a matching rule "
                    "can only report. This installation has no switch for "
                    f"blocking: {IPS_MODE_BIN} is not installed.")
        # Not "cannot block here": that was written when only the inline
        # layout could, and stayed under a switch that works. On a mirror the
        # refusal above is what is said instead.
        return ("The engine reads a copy of the traffic, so a matching rule can "
                "only report. Blocking puts the engine in this device's own path "
                "through a netfilter queue: it then stops matching traffic to and "
                "from this Pi, and nothing beyond it.")

    if mirror and not forwarding:
        # A device switched before the switch was refused here. The engine is
        # on the queue, which holds this Pi's own packets, and the mirror port
        # is not being read at all: the network it was put there to watch is
        # not inspected, and the screen said blocking.
        return ("The engine is reading a netfilter queue, which on a mirror "
                "layout holds only this Pi's own traffic. The mirror port is not "
                "being read, so the network behind it is not inspected at all. "
                "Switch back to Detection.")

    # A label before the number and a thousands separator: "45491 rules are
    # loaded..." at the start of a sentence read as the id of one rule.
    rules = f"Signatures set to drop: {dropping:,}."
    # Blocking on with the policy not in the rule set is the state this exists
    # for: the mode is right, the file is not, and every other thing on the
    # screen says "blocking". A panel upgraded from before the policy starts
    # here, with one vendor drop rule and forty thousand alerts.
    also = (f" {pending:,} {'signature does' if pending == 1 else 'signatures do'} "
            "not follow the enabled categories yet, and will not until the rule "
            "set is rebuilt."
            if pending else "")
    also += (" The engine also drops flows on its own: a stream picked up "
             "midway, or a packet the exception policy cannot process.")

    if inline and not forwarding:
        # The combination nothing else catches: cabled inline, and still
        # carrying the queue's drop-in. The rules are on the IP forward hook,
        # bridged frames never reach it, and every other thing on this screen
        # says blocking. The failure that looks most like success.
        return ("The engine is set to take packets from a netfilter queue, and "
                "on this layout the frames cross a kernel bridge and never reach "
                "it. Nothing is being inspected and nothing is being blocked. "
                "Switch to detection and back to put the engine in the path "
                "properly.")

    if forwarding:
        return ("The engine carries this link: it reads from one port and writes "
                f"to the other, so a packet it drops is never forwarded. {rules}"
                + also
                + " If the engine stops, restarts or reloads, nothing crosses "
                  "this link at all.")
    return ("Netfilter holds each packet until the engine gives a verdict, so a "
            f"matching signature can drop it. {rules}" + also
            + " If the engine stops, netfilter lets the traffic past uninspected "
              "rather than holding it.")


def _inline_layout() -> list[str]:
    """The two interfaces of an inline layout, or nothing. Imported late: the
    network module reads settings and topology, and this one is loaded by the
    reader thread."""
    from ..network import capture as network_capture
    return network_capture.inline_members()


class ModeRefused(Exception):
    """The layout cannot carry blocking. The operator's request refused, with
    the reason, rather than a fault: the endpoint answers 409, not 500."""


MIRROR_CANNOT_BLOCK = (
    "A mirror port hands this Pi a copy of the traffic, and the original is "
    "already on its way, so there is nothing a drop rule could stop. Switching "
    "would also stop the engine reading the mirror port. Blocking needs the "
    "inline layout, where the traffic crosses this Pi.")

LAYOUT_NOT_APPLIED = (
    "The layout chosen in the network setup has not been applied yet, so the "
    "engine is still running the previous one and blocking cannot tell what it "
    "would act on. Apply the layout first.")


def _layout() -> dict[str, Any]:
    from ... import settings
    from ..network import topology
    return settings.get(topology.SETTINGS_KEY) or {}


def _mirror_layout() -> bool:
    """Whether a mirror port is chosen, applied or not.

    The one layout where blocking cannot mean anything: the Pi is handed a copy
    and the original is already on its way. Worse than useless, too: the queue
    mechanism starts the engine with -q instead of --af-packet, so it stops
    reading the mirror port at all and inspects only this device's own traffic,
    while every screen says blocking.
    """
    return _layout().get("profile") == "mirror"


def _queue_refusal() -> str:
    """Why the netfilter queue must not be switched on here, or "" if it may.

    Decided by the layout that is running, not merely the one saved: the wizard
    stores a choice the moment its step is saved, with "applied" false, while
    the engine carries on with the previous layout. Reading the saved choice let
    a saved-but-unapplied "self" offer the queue on a device still reading a
    mirror port, which is the blinding this exists to prevent. A device where
    the wizard never ran (no profile) captures on its own interface, which the
    queue covers.
    """
    stored = _layout()
    if _mirror_layout():
        return MIRROR_CANNOT_BLOCK
    if stored.get("profile") and not stored.get("applied"):
        return LAYOUT_NOT_APPLIED
    return ""


def _catch_up_rules() -> tuple[bool, str]:
    """Rebuild the rule set before blocking starts, if it lags the policy.

    Otherwise the operator had to find a second button: the switch reported
    blocking while the categories it named were still loaded as alerts. Done
    before the switch, while the link is still carried the old way, so the
    rebuild adds to the wait and not to the outage. A rebuild that fails stops
    the switch: blocking that would stop one vendor rule is not worth the link
    depending on the engine.
    """
    if scan_rules().blocking_pending == 0:
        return True, ""
    ok, output = rebuild_from_state()
    if ok:
        return True, ""
    return False, ("The rule set could not be rebuilt, so blocking was not switched "
                   "on and nothing on the link changed.\n\n" + output[-4000:])


def set_mode(block: bool) -> tuple[bool, str]:
    """Put the engine in the forwarding path, or take it back out.

    Two mechanisms, because the layout decides which one can work at all.

    On an inline layout the traffic crosses a kernel bridge, and NFQUEUE rules
    hang on the IP forward hook, which bridged frames never reach without
    br_netfilter. Blocking there means handing the forwarding to the engine
    instead: af-packet copy-mode ips, the two cables unchanged. That is the one
    layout where a `drop` rule stops somebody else's packet.

    Everywhere else the Pi is a host, not a link, so NFQUEUE on its own input
    and output is what there is. Worth saying plainly: that protects this
    device, not the network it watches.

    Turning blocking on first brings the rule set up to the policy if it has
    fallen behind. Both mechanisms restart the engine, so the rebuilt file is
    what it starts with, and no reload of its own is needed.
    """
    if block and not _inline_layout() and (refusal := _queue_refusal()):
        # Refused before the rule set is touched. Switching back to detection
        # stays open: a device switched before this rule has to be able to
        # leave the state this refuses to enter.
        raise ModeRefused(refusal)
    if block:
        ok, output = _catch_up_rules()
        if not ok:
            return False, output

    if _inline_layout():
        from ..network import capture as network_capture
        # Nothing about the queue here. The swap helper takes the queue's
        # drop-in out itself, without a restart, inside the one sequence where
        # it stops and starts the engine. Doing it from here first cost a
        # restart of its own, which on the way back landed while the engine was
        # still forwarding, and a `status` that failed was read as "nothing to
        # clear" and swapped on top of a drop-in that makes the engine ignore
        # the configuration it had just been given.
        return network_capture.set_inline_blocking(block)

    return _run_ips_mode("ips" if block else "ids")


def _run_ips_mode(word: str) -> tuple[bool, str]:
    """The NFQUEUE helper, which owns the drop-in and the nftables table."""
    try:
        proc = subprocess.run(["sudo", "-n", IPS_MODE_BIN, word],
                              capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        return False, "the engine did not finish restarting within 180s"
    except FileNotFoundError:
        return False, f"{IPS_MODE_BIN} is not installed"
    output = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        if "sudo" in output and "password" in output.lower():
            output += ("\n\nThe panel is not allowed to run this command. Install the "
                       "sudoers entry: scripts/install-service.sh.")
        return False, output
    return True, output


def mode_info() -> dict[str, Any]:
    """Engine mode: detection only, or detection with blocking."""
    capture = _yaml_capture()
    blocking = capture["nfqueue"] or capture["copy_mode_ips"]
    inline = bool(_inline_layout())
    mirror = _mirror_layout()
    refusal = "" if inline else _queue_refusal()
    dropping = drop_rules()
    pending = scan_rules().blocking_pending
    can_switch = Path(IPS_MODE_BIN).exists() or inline
    return {
        # Whether this panel can change it at all. The helper owns the queue,
        # and on an inline layout the swap does not go through it, so an image
        # missing it can still turn blocking on where blocking is real.
        "can_switch": can_switch,
        # Rules that would actually stop something. Blocking with this at zero
        # is a switch that reports itself on and does nothing.
        "drop_rules": dropping,
        # Rules the policy says should drop and the running set has as alerts.
        # Above zero, the rule set needs a rebuild before blocking is what the
        # categories say it is.
        "drop_pending": pending,
        "id": "ips" if blocking else "ids",
        "label": "Detection and blocking" if blocking else "Detection",
        # Which mechanism this switch would use, which the layout decides. On a
        # layout the traffic crosses, blocking hands the forwarding to the
        # engine and the link then lives and dies with it; everywhere else the
        # queue protects this device and nothing beyond it. The screen has to
        # ask a different question in the two cases, so it is told which.
        "inline": inline,
        "can_block": blocking,
        # This used to say blocking needs "an inline bridge or NFQUEUE", which
        # sent anyone who read it at the inline layout in the wizard - a layout
        # that does not block. A kernel bridge forwards the frame and hands the
        # engine a copy; being in the path is necessary and not sufficient. What
        # actually drops is the engine doing the forwarding itself.
        # False where the switch would blind the engine rather than protect
        # anything: the screen keeps the option visible and says why it is off.
        "blocking_possible": not refusal,
        "blocking_unavailable": refusal,
        "reason": _reason(blocking, inline, capture["copy_mode_ips"], dropping, pending,
                          mirror, refusal, can_switch),
        "interfaces": capture["interfaces"],
        "capture": "nfqueue" if capture["nfqueue"] else "af-packet",
    }


def _link_state(name: str) -> dict[str, Any]:
    """Administrative and physical state of one interface, straight from sysfs.

    Read here rather than through the network module: this runs on every status
    poll, and two small files are cheaper than enumerating every interface on
    the machine to answer a question about one of them.
    """
    base = SYS_NET / name
    if not base.is_dir():
        return {"name": name, "present": False, "up": False, "carrier": False,
                "operstate": None, "promisc": False}
    try:
        operstate = (base / "operstate").read_text(encoding="utf-8").strip()
    except OSError:
        operstate = "unknown"
    try:
        carrier = (base / "carrier").read_text(encoding="utf-8").strip() == "1"
    except OSError:
        # The kernel refuses to answer this one while the interface is
        # administratively down, and that refusal is itself the answer.
        carrier = False
    return {"name": name, "present": True, "up": operstate == "up",
            "operstate": operstate, "carrier": carrier, "promisc": _promisc(base)}


def _promisc(base: Path) -> bool:
    """IFF_PROMISC, straight out of the kernel's flag word.

    Worth its own read because it is the difference between a capture interface
    and a capture interface that works. A mirror port delivers frames addressed
    to other machines; without this flag the kernel drops every one of them
    before Suricata is offered anything, and the result looks exactly like a
    quiet segment. The engine asks for promiscuous mode itself when it opens the
    socket, so this being off means something outside took it away.
    """
    try:
        return bool(int((base / "flags").read_text(encoding="utf-8").strip(), 16) & IFF_PROMISC)
    except (OSError, ValueError):
        return False


def capture_link() -> dict[str, Any]:
    """Whether the interfaces the engine captures on can carry anything.

    This exists because "the engine is running" and "the engine is being given
    traffic" are different statements, and the panel used to make only the first
    one. af-packet opens its socket on an interface that is down, waits, and the
    counters stop moving: a sensor deaf since the last reboot renders exactly
    like a quiet night. Taking the interface out of NetworkManager's hands is
    what makes this likely rather than exotic, because after that nothing brings
    it back up on its own.

    Read from the kernel, never inferred from the packet count. A segment where
    genuinely nothing happens has to stay distinguishable from a dead cable, and
    only the link state can tell them apart.
    """
    info = _yaml_capture()
    links = [_link_state(name) for name in info["interfaces"]]

    # Blocking through NFQUEUE takes packets from netfilter rather than from an
    # interface, so there is no link here to have an opinion about.
    if info["nfqueue"] or not links:
        return {"interfaces": links, "state": "ok", "problem": None}

    missing = [l["name"] for l in links if not l["present"]]
    down = [l["name"] for l in links if l["present"] and not l["up"]]
    dark = [l["name"] for l in links if l["up"] and not l["carrier"]]

    if missing:
        return {
            "interfaces": links, "state": "bad",
            "problem": f"The engine is configured to capture on {_names(missing)}, "
                       "which the kernel does not have. Nothing is being inspected. "
                       "Check the layout in the wizard: an adapter that was renamed "
                       "or unplugged looks like this.",
        }
    if down:
        return {
            "interfaces": links, "state": "bad",
            "problem": f"{_names(down)} is down, so nothing reaches the engine. "
                       "The service still reports itself as running and the alert "
                       "count stays where it was, which is why this says so here.",
        }
    if dark:
        return {
            "interfaces": links, "state": "warn",
            "problem": f"{_names(dark)} is up but has no carrier: nothing is plugged "
                       "into it, or the port on the other end is disabled. No frames "
                       "can arrive until that changes.",
        }
    return {"interfaces": links, "state": "ok", "problem": None}


def _names(values: list[str]) -> str:
    """Interface names in a sentence, without a comma before the last one."""
    if len(values) < 2:
        return values[0] if values else ""
    return ", ".join(values[:-1]) + " and " + values[-1]


def snapshot() -> dict[str, Any]:
    """Everything the intrusion prevention screen needs."""
    scan = scan_rules()
    state = load_state()
    categories = []
    for cat in CATEGORIES:
        counts = scan.per_category.get(cat.id, {"total": 0, "enabled": 0, "informational": 0})
        # Nothing enabled means nothing to be honest about. The residual
        # bucket exists so the per-category counts add up to the total and so
        # that rules belonging to no category are visibly still running; with
        # none of them running it is a row that only invites the question of
        # how it differs from the rating switch below.
        if cat.locked and counts["enabled"] == 0:
            continue
        categories.append({
            "id": cat.id,
            "name": cat.name,
            "description": cat.description,
            "enabled": True if cat.locked else state["categories"].get(cat.id, True),
            "locked": cat.locked,
            "signatures": counts["total"],
            "active_signatures": counts["enabled"],
            # How many of this category the informational switch takes away.
            # Measured here: 6 061 of the 6 720 in "botnet" are ET DYN_DNS, so
            # that switch drops the category to 517 and the screen used to say
            # nothing about it at all.
            "informational": counts.get("informational", 0),
            # Loaded, alerting, and never dropped in the mode that blocks.
            "alert_only": cat.id in ALERT_ONLY_CATEGORIES,
        })
    dates = source_dates()
    return {
        "signatures": {"total": scan.total, "active": scan.enabled},
        # When the panel last rebuilt the merged file. Kept because it is the
        # honest answer to "are my switches in the running set", but it is no
        # longer what the screen calls the age of the detection.
        "updated_at": scan.updated_at,
        "built_at": dates["built"],
        "fetched_at": dates["fetched"],
        "source": "Emerging Threats Open",
        "applied": state["applied"],
        "applied_at": state["applied_at"],
        "mode": mode_info(),
        "categories": categories,
        "informational": {
            "enabled": bool(state.get("informational", True)),
            "signatures": scan.informational["total"],
            "active_signatures": scan.informational["enabled"],
        },
        "muted": muted_signatures(),
        "allowed": allowed_signatures(),
    }
