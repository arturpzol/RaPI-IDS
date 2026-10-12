#!/usr/bin/env python3
"""How many flows had an endpoint inside HOME_NET, and how many there were.

    eve-homenet.py <eve.json> <home-net> [since-iso8601]

`home-net` is the string the panel stores, e.g. "[10.0.0.0/8,192.168.0.0/16]".

Most of the rule set is written as $HOME_NET -> $EXTERNAL_NET or the reverse. A
sensor watching a segment that is not in HOME_NET still loads every rule and
still reports itself healthy; the rules simply never match. The engine says
nothing about it, so this counts.
"""
from __future__ import annotations

import ipaddress
import json
import sys
from collections import deque

TAIL_LINES = 40000


def networks(spec: str) -> list:
    out = []
    for part in spec.strip().strip("[]").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return out


def inside(address: str, nets: list) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in net for net in nets)


def main() -> None:
    path, spec = sys.argv[1], sys.argv[2]
    since = sys.argv[3] if len(sys.argv) > 3 else ""
    nets = networks(spec)
    seen = home = 0
    with open(path, errors="ignore") as handle:
        for line in deque(handle, maxlen=TAIL_LINES):
            if '"event_type":"flow"' not in line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if since and event.get("timestamp", "") < since:
                continue
            seen += 1
            if inside(event.get("src_ip", ""), nets) or inside(event.get("dest_ip", ""), nets):
                home += 1
    print(seen, home)


if __name__ == "__main__":
    main()
