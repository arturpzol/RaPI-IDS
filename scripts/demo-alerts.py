#!/usr/bin/env python3
"""Write made-up alert events for screenshots, from the rules that are installed.

    python3 demo-alerts.py --rules /var/lib/suricata/rules/suricata.rules \
        --home 10.0.2.0/24 >> /var/log/suricata/eve.json

A fresh machine has three alerts, all of them the same test request, and a
screenshot of that shows nothing of what the panel is for. This prints EVE
alert lines the panel reads like any other: a spread of ratings over the last
two days, some of them blocked, with the names of well-known malware families.

Nothing here is traffic and nothing is downloaded. The signature names, ids,
categories and ratings are taken from the rule file on the machine, so every
alert on the screen is a rule that really exists; only the event is invented.
The addresses outside the home network are from the ranges reserved for
documentation (RFC 5737), so no real host is shown next to a malware name.

Used by scripts/test-image-vm.sh --gui --demo, inside the virtual machine. Not
for a device that watches a real network: the events land in its alert history.
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import random
import re
import sys

# Families a reader recognises, tried in this order within each rating.
KNOWN = ("Cobalt Strike", "Emotet", "Qakbot", "TrickBot", "AgentTesla", "Lumma",
         "RedLine", "Mirai", "LockBit", "IcedID", "Formbook", "Remcos", "njRAT",
         "AsyncRAT", "Dridex", "Raccoon", "Vidar", "Gh0st", "XMRig", "CoinMiner",
         "Log4j", "EternalBlue", "Metasploit", "Meterpreter", "Tor ", "BitTorrent")
# How many alerts of each rating today and yesterday, by the calendar: the
# dashboard's rating tiles compare the day so far with the day before.
# Uneven on purpose: a real network has a long quiet tail and a few bad ones.
TODAY = {"Critical": 7, "Major": 26, "Minor": 43, "Informational": 121}
YESTERDAY = {"Critical": 3, "Major": 31, "Minor": 38, "Informational": 97}
DISTINCT = {"Critical": 5, "Major": 12, "Minor": 12, "Informational": 14}
BLOCKED = {"Critical": 0.7, "Major": 0.3, "Minor": 0.0, "Informational": 0.0}
OUTSIDE = ("192.0.2.", "198.51.100.", "203.0.113.")   # RFC 5737

RULE = re.compile(rb'^(?:alert|drop) (\w+) .*?\(msg:"([^"]+)";.*?classtype:([\w-]+);'
                  rb'.*?sid:(\d+);.*?rev:(\d+);.*?metadata:([^;]*);')
SEVERITY = re.compile(r"signature_severity (\w+)")
CLASS = re.compile(r"^config classification:\s*([\w-]+),([^,]+),(\d+)")


def classes(path: str) -> dict[str, tuple[str, int]]:
    found = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                match = CLASS.match(line)
                if match:
                    found[match.group(1)] = (match.group(2).strip(), int(match.group(3)))
    except OSError:
        pass
    return found


def rules(path: str) -> dict[str, list[dict]]:
    by_rating: dict[str, list[dict]] = {name: [] for name in TODAY}
    with open(path, "rb") as handle:
        for line in handle:
            match = RULE.match(line)
            if not match:
                continue
            proto, msg, classtype, sid, rev, metadata = (part.decode("utf-8", "replace")
                                                         for part in match.groups())
            rating = SEVERITY.search(metadata)
            if not rating or rating.group(1) not in by_rating or not msg.startswith("ET "):
                continue
            by_rating[rating.group(1)].append({
                "proto": proto, "msg": msg, "classtype": classtype,
                "sid": int(sid), "rev": int(rev), "rating": rating.group(1)})
    return by_rating


def pick(pool: list[dict], count: int, rng: random.Random) -> list[dict]:
    """The recognisable names first, one rule per family, then anything else."""
    chosen, used = [], set()
    for name in KNOWN:
        match = next((r for r in pool if name.lower() in r["msg"].lower()
                      and r["sid"] not in used), None)
        if match and len(chosen) < count:
            chosen.append(match)
            used.add(match["sid"])
    rest = [r for r in pool if r["sid"] not in used]
    rng.shuffle(rest)
    return chosen + rest[:max(0, count - len(chosen))]


def event(rule: dict, when: datetime.datetime, inside: list[str], known: dict,
          rng: random.Random) -> dict:
    category, priority = known.get(rule["classtype"], ("Misc activity", 3))
    host = rng.choice(inside)
    remote = rng.choice(OUTSIDE) + str(rng.randint(2, 250))
    proto = {"dns": "UDP", "udp": "UDP", "icmp": "ICMP"}.get(rule["proto"], "TCP")
    app = rule["proto"] if rule["proto"] in ("dns", "http", "tls", "smb", "ssh") else ""
    port = {"dns": 53, "http": 80, "tls": 443, "smb": 445, "ssh": 22}.get(app, rng.choice((80, 443, 8080, 4444)))
    record = {
        "timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        "flow_id": rng.getrandbits(50), "in_iface": "eth0", "event_type": "alert",
        "src_ip": host, "src_port": rng.randint(32768, 60999),
        "dest_ip": remote, "dest_port": port, "proto": proto,
        "alert": {
            "action": "blocked" if rng.random() < BLOCKED[rule["rating"]] else "allowed",
            "gid": 1, "signature_id": rule["sid"], "rev": rule["rev"],
            "signature": rule["msg"], "category": category, "severity": priority,
            "metadata": {"signature_severity": [rule["rating"]]},
        },
    }
    if app:
        record["app_proto"] = app
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--rules", default="/var/lib/suricata/rules/suricata.rules")
    parser.add_argument("--classification", default="/etc/suricata/classification.config")
    parser.add_argument("--home", default="10.0.2.0/24", help="the network the inside hosts are in")
    parser.add_argument("--seed", type=int, default=5)
    args = parser.parse_args()
    rng = random.Random(args.seed)
    net = ipaddress.ip_network(args.home, strict=False)
    inside = [str(net.network_address + n) for n in (21, 34, 57, 102, 118) if n < net.num_addresses - 1]
    known = classes(args.classification)
    pools = rules(args.rules)
    now = datetime.datetime.now().astimezone()
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    # Today runs from midnight to two minutes ago, yesterday is the whole day
    # before. Run just after midnight, today is short and crowded; that is
    # still a truthful picture of a day that has only just begun.
    spans = ((midnight, max((now - midnight).total_seconds() - 120, 60), TODAY),
             (midnight - datetime.timedelta(days=1), 86400, YESTERDAY))
    records = []
    chosen = {rating: pick(pools[rating], DISTINCT[rating], rng) for rating in TODAY}
    for rating, rules_ in chosen.items():
        if not rules_:
            print(f"no {rating} rules in {args.rules}", file=sys.stderr)
    for start, length, counts in spans:
        for rating, count in counts.items():
            if not chosen[rating]:
                continue
            for _ in range(count):
                # The first few rules take most of the alerts, as they do in life.
                rule = chosen[rating][min(int(rng.expovariate(0.45)), len(chosen[rating]) - 1)]
                # Two humps, morning and evening, so the hourly chart has a
                # shape instead of a flat line.
                at = rng.betavariate(2, 5) if rng.random() < 0.45 else rng.betavariate(5, 2)
                records.append(event(rule, start + datetime.timedelta(seconds=at * length),
                                     inside, known, rng))
    # The top of the alert list is what a screenshot shows: the last two
    # minutes hold one of everything, in an order that mixes the ratings.
    recent = ("Informational", "Major", "Minor", "Critical", "Informational", "Minor",
              "Major", "Informational", "Critical", "Minor", "Major", "Informational",
              "Minor", "Major", "Informational", "Critical")
    for index, rating in enumerate(recent):
        if chosen[rating]:
            rule = chosen[rating][index % len(chosen[rating])]
            when = now - datetime.timedelta(seconds=5 + index * 7 + rng.random() * 3)
            records.append(event(rule, when, inside, known, rng))
    records.sort(key=lambda r: r["timestamp"])
    for record in records:
        print(json.dumps(record))
    return 0


if __name__ == "__main__":
    sys.exit(main())
