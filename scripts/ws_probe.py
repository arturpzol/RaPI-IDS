#!/usr/bin/env python3
"""Tap into the panel WebSocket stream - for debugging without a frontend.

Uzycie:  ./.venv/bin/python scripts/ws_probe.py [sekundy] [ws://host:port/ws]
"""
from __future__ import annotations

import asyncio
import json
import sys

import websockets


async def main() -> None:
    seconds = float(sys.argv[1]) if len(sys.argv) > 1 else 15.0
    url = sys.argv[2] if len(sys.argv) > 2 else "ws://127.0.0.1:8000/ws"

    async with websockets.connect(url) as ws:
        print(f"podlaczony do {url}, nasluchuje {seconds}s...", flush=True)
        counts: dict[str, int] = {}
        try:
            async with asyncio.timeout(seconds):
                async for raw in ws:
                    msg = json.loads(raw)
                    topic = msg.get("topic", "?")
                    counts[topic] = counts.get(topic, 0) + 1
                    data = msg.get("data", {})
                    if topic == "suricata.alert":
                        print(f"[ALERT] sev={data.get('severity')} "
                              f"{data.get('src_ip')} -> {data.get('dest_ip')} "
                              f":: {data.get('signature')}", flush=True)
                    elif topic == "suricata.event":
                        print(f"[{data.get('event_type','?'):5}] "
                              f"{data.get('src_ip')} -> {data.get('dest_ip')} "
                              f"{data.get('detail') or ''}", flush=True)
                    elif topic == "suricata.stats":
                        eng = data.get("engine", {})
                        print(f"[STATS] pkt={eng.get('packets')} "
                              f"drop={eng.get('kernel_drops')} "
                              f"alerts={eng.get('alerts_detected')}", flush=True)
        except TimeoutError:
            pass
        print(f"\npodsumowanie: {counts}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
