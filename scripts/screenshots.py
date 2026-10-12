#!/usr/bin/env python3
"""Render the panel in a headless browser and save what it looks like.

    backend/.venv/bin/python scripts/screenshots.py [--url URL] [--out DIR]
                                                    [--width N] [--only NAME]

Why this exists: everything in this project is checked by asking the code what
it did, and nothing ever looked at the result. A tile changed from a link to a
button rendered a hundred pixels narrower than its neighbours and went past 322
green tests, because not one of them measured a box. This is the missing step:
a person, or a model, gets to look before saying the work is done.

It also reports two things it can check on its own, on every screen it visits:

  * anything wider than the window, which is how a phone layout breaks,
  * tiles in one row that do not share a width, which is the fault above.

The password is read from RAPI_PASS or asked for on the terminal, never passed
on the command line and never written anywhere: it goes to the panel's own login
endpoint through the browser, which keeps the session cookie the panel sets.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import websockets

# Every screen worth a picture, and the parameters that put it in a known state.
SCREENS: dict[str, str] = {
    "login": "/login",
    "dashboard": "/dashboard",
    "alerts": "/ids?tab=alerts",
    "protection": "/ids?tab=protection",
    "engine": "/ids?tab=rules",
    "logs": "/ids?tab=logs",
    "notifications": "/ids?tab=notify",
    "live": "/ids?tab=live",
    "setup": "/setup",
    "system": "/system",
}

# Desktop and a phone. The narrow one is not decoration: the sidebar collapses,
# the tab bar scrolls sideways and the tables get their own scroll container,
# and each of those has been wrong at least once.
WIDTHS = (1280, 420)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Browser:
    """The smallest part of the DevTools Protocol this needs."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.ws: websockets.ClientConnection | None = None
        self.next_id = 0

    async def open(self) -> None:
        url = await asyncio.to_thread(self._page_socket)
        self.ws = await websockets.connect(url, max_size=64 * 1024 * 1024)

    def _page_socket(self) -> str:
        import urllib.request
        for _ in range(100):
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{self.port}/json/list", timeout=1) as r:
                    for target in json.load(r):
                        if target.get("type") == "page":
                            return target["webSocketDebuggerUrl"]
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("the browser never offered a page to drive")

    async def send(self, method: str, **params):
        assert self.ws is not None
        self.next_id += 1
        wanted = self.next_id
        await self.ws.send(json.dumps({"id": wanted, "method": method,
                                       "params": params}))
        while True:
            message = json.loads(await self.ws.recv())
            if message.get("id") != wanted:
                continue          # an event, not our answer
            if "error" in message:
                raise RuntimeError(f"{method}: {message['error'].get('message')}")
            return message.get("result", {})

    async def evaluate(self, expression: str):
        result = await self.send("Runtime.evaluate", expression=expression,
                                 awaitPromise=True, returnByValue=True)
        return result.get("result", {}).get("value")

    async def goto(self, url: str) -> None:
        await self.send("Page.navigate", url=url)
        # The app renders after its first requests come back, and there is no
        # single event for "the screen is ready". Settling on a quiet document
        # is close enough for a picture and costs nothing when it is quick.
        for _ in range(60):
            await asyncio.sleep(0.25)
            state = await self.evaluate("document.readyState")
            if state == "complete":
                break
        await asyncio.sleep(1.2)


# Kept as a constant so a test can run it against a page built to fail it. A
# check nobody has watched fail is a check nobody knows works.
LAYOUT_CHECK_JS = """(() => {
  const faults = [];
  const room = document.documentElement.clientWidth;
  // Wide content is allowed, as long as it scrolls inside its own container:
  // that is the rule this project writes tables and diagrams to. Reporting the
  // table inside a scroller as a broken layout is how a check stops being read.
  const scrolls = (el) => {
    for (let p = el.parentElement; p; p = p.parentElement) {
      const o = getComputedStyle(p).overflowX;
      if (o === 'auto' || o === 'scroll') return true;
    }
    return false;
  };
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.width > 0 && r.right > room + 1 && getComputedStyle(el).position !== 'fixed'
        && !scrolls(el)) {
      const own = el.className && typeof el.className === 'string'
        ? '.' + el.className.trim().split(/\\s+/).join('.') : el.tagName;
      faults.push(`wider than the window: ${own} reaches ${Math.round(r.right)} of ${room}`);
      break;
    }
  }
  for (const row of document.querySelectorAll('.tiles')) {
    const tiles = [...row.querySelectorAll('.tile')];
    const boxes = tiles.map(t => t.getBoundingClientRect());
    const first = boxes.length ? Math.round(boxes[0].top) : 0;
    const sameRow = boxes.filter(b => Math.round(b.top) === first)
                         .map(b => Math.round(b.width));
    if (new Set(sameRow).size > 1) {
      faults.push(`tiles in one row differ in width: ${sameRow.join(', ')}`);
    }
  }
  return faults;
})()"""


async def check_layout(page: Browser, width: int) -> list[str]:
    """Two faults a picture shows and no unit test in this project would."""
    return await page.evaluate(LAYOUT_CHECK_JS)


async def sign_in(page: Browser, base: str, user: str, password: str) -> bool:
    """Log in through the panel's own endpoint, from inside the page.

    Same origin, so the browser keeps the HttpOnly session cookie the panel
    sets. Nothing here stores the password: it lives in this call and in the
    request it makes.
    """
    await page.goto(base + "/login")
    payload = json.dumps({"username": user, "password": password})
    ok = await page.evaluate(f"""
      fetch('/api/auth/login', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        credentials: 'include',
        body: {json.dumps(payload)},
      }}).then(r => r.ok).catch(() => false)
    """)
    return bool(ok)


async def run(args: argparse.Namespace) -> int:
    chromium = shutil.which("chromium") or shutil.which("chromium-browser")
    if not chromium:
        print("chromium is not installed (apt install chromium)", file=sys.stderr)
        return 2

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    port = free_port()
    profile = out / ".profile"
    proc = subprocess.Popen(
        [chromium, "--headless=new", f"--remote-debugging-port={port}",
         f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check",
         # The panel issues its own certificate on the device it runs on, so
         # there is no authority a browser would know. Refusing it here would
         # only mean never looking at the panel.
         "--ignore-certificate-errors", "--disable-gpu", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    page = Browser(port)
    faults: list[str] = []
    try:
        await page.open()
        await page.send("Page.enable")
        await page.send("Runtime.enable")

        signed_in = False
        if not args.no_login:
            password = os.environ.get("RAPI_PASS") or getpass.getpass(
                f"Panel password for {args.user}: ")
            signed_in = await sign_in(page, args.url, args.user, password)
            del password
            if not signed_in:
                print("Could not sign in. Only the login page will be captured.",
                      file=sys.stderr)

        wanted = {args.only: SCREENS[args.only]} if args.only else SCREENS
        themes = ("light", "dark") if args.theme == "both" else (args.theme,)
        for theme in themes:
            # The panel's theme setting starts at "system", which follows the
            # browser, so telling the browser is enough and nothing is stored.
            await page.send("Emulation.setEmulatedMedia", features=[
                {"name": "prefers-color-scheme", "value": theme}])
            suffix = "" if theme == "light" else "-dark"
            for width in ([args.width] if args.width else WIDTHS):
                await page.send("Emulation.setDeviceMetricsOverride", width=width,
                                height=1000, deviceScaleFactor=1, mobile=width < 700)
                for name, path in wanted.items():
                    if name != "login" and not signed_in:
                        continue
                    await page.goto(args.url + path)
                    for fault in await check_layout(page, width) or []:
                        faults.append(f"{name} at {width}px ({theme}): {fault}")
                    shot = await page.send("Page.captureScreenshot",
                                           captureBeyondViewport=True)
                    target = out / f"{name}-{width}{suffix}.png"
                    target.write_bytes(base64.b64decode(shot["data"]))
                    print(f"  {target}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(profile, ignore_errors=True)

    if faults:
        print("\nLayout faults:", file=sys.stderr)
        for fault in faults:
            print(f"  {fault}", file=sys.stderr)
        return 1
    print("\nNo layout faults found. Look at the pictures anyway.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=os.environ.get("RAPI_URL", "https://127.0.0.1"))
    parser.add_argument("--out", default="build/screenshots")
    parser.add_argument("--user", default=os.environ.get("RAPI_USER", "admin"))
    parser.add_argument("--width", type=int, help="one width instead of both")
    parser.add_argument("--only", choices=sorted(SCREENS), help="one screen")
    parser.add_argument("--theme", choices=("light", "dark", "both"), default="light",
                        help="dark pictures are named NAME-WIDTH-dark.png")
    parser.add_argument("--no-login", action="store_true",
                        help="capture the login page only")
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
