#!/usr/bin/env python3
"""How many TCP flows the engine saw in both directions, and how many at all.

    eve-flows.py <eve.json> [since-iso8601]

Its own file rather than a heredoc inside verify.sh, because the shell there
already nests one and a second would have to agree with it about delimiters.

The tail only. Reading a week of logs to answer a question about now would take
longer than the check is worth, and a sensor writes this file continuously.
"""
from __future__ import annotations

import json
import sys
from collections import deque

TAIL_LINES = 40000


def main() -> None:
    path = sys.argv[1]
    since = sys.argv[2] if len(sys.argv) > 2 else ""
    total = both = 0
    with open(path, errors="ignore") as handle:
        for line in deque(handle, maxlen=TAIL_LINES):
            if '"event_type":"flow"' not in line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get("proto") != "TCP":
                continue
            # Flow records outlive a restart, and answering with traffic from
            # before the last configuration change would report a fault that has
            # already been fixed - or hide one that has just been made.
            if since and event.get("timestamp", "") < since:
                continue
            flow = event.get("flow", {})
            total += 1
            if flow.get("pkts_toserver") and flow.get("pkts_toclient"):
                both += 1
    print(total, both)


if __name__ == "__main__":
    main()
