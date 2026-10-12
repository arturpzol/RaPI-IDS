"""The check that looks at the panel instead of asking it what it did.

scripts/screenshots.py renders every screen in a headless browser, saves a
picture and reports two faults it can find on its own. This covers the finding
half: a check nobody has watched fail is a check nobody knows works.

The fault it was written for: a tile changed from a link to a button rendered
189px wide next to neighbours at 291, because a button carries the browser's own
stylesheet and shrinks to its content. It went past 322 green tests, none of
which measured a box.
"""
from __future__ import annotations

import asyncio
import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from .helpers import PROJECT_ROOT, BackendTestCase

CHROMIUM = shutil.which("chromium") or shutil.which("chromium-browser")

CLEAN = """<!doctype html><meta charset="utf-8"><style>
 body{margin:0;font:14px system-ui}
 .tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:.8rem;padding:1rem}
 .tile{display:flex;flex-direction:column;padding:1rem;border:1px solid #ccc}
 button.tile{width:100%;margin:0;font:inherit;text-align:inherit}
</style><div class="tiles">
 <div class="tile">one</div><div class="tile">two</div>
 <span style="display:block"><button type="button" class="tile">three</button></span>
</div>"""

# The same page with the normalisation taken out, which is exactly the state the
# panel was in when the row had a hole in it.
NARROW_TILE = CLEAN.replace(
    "button.tile{width:100%;margin:0;font:inherit;text-align:inherit}", "")

# Something wider than the window, which is how a phone layout breaks.
OVERFLOW = """<!doctype html><meta charset="utf-8"><style>body{margin:0}</style>
<div class="wide" style="width:3000px;height:40px;background:#eee"></div>"""


# The same width, inside a container that scrolls. This is what the project
# asks wide tables and diagrams to do, so reporting it would be crying wolf on
# every screen that has a table.
SCROLLER = """<!doctype html><meta charset="utf-8"><style>body{margin:0}
 .table-wrap{overflow-x:auto}</style>
<div class="table-wrap">
  <div class="wide" style="width:3000px;height:40px;background:#eee"></div>
</div>"""


def _load():
    spec = importlib.util.spec_from_file_location(
        "screenshots", PROJECT_ROOT / "scripts" / "screenshots.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(CHROMIUM, "chromium is not installed")
class LayoutCheckTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.shots = _load()

    def _faults(self, html: str) -> list[str]:
        page_file = self.tmp / "page.html"
        page_file.write_text(html, encoding="utf-8")

        async def run():
            port = self.shots.free_port()
            profile = tempfile.mkdtemp()
            proc = subprocess.Popen(
                [CHROMIUM, "--headless=new", f"--remote-debugging-port={port}",
                 f"--user-data-dir={profile}", "--no-first-run", "--disable-gpu",
                 "about:blank"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            page = self.shots.Browser(port)
            try:
                await page.open()
                await page.send("Page.enable")
                await page.send("Runtime.enable")
                await page.send("Emulation.setDeviceMetricsOverride", width=900,
                                height=600, deviceScaleFactor=1, mobile=False)
                await page.goto(f"file://{page_file}")
                return await page.evaluate(self.shots.LAYOUT_CHECK_JS)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                shutil.rmtree(profile, ignore_errors=True)

        return asyncio.run(run()) or []

    def test_it_sees_a_tile_that_does_not_match_its_row(self):
        faults = self._faults(NARROW_TILE)
        self.assertTrue(any("differ in width" in f for f in faults), faults)

    def test_it_sees_something_wider_than_the_window(self):
        faults = self._faults(OVERFLOW)
        self.assertTrue(any("wider than the window" in f for f in faults), faults)

    def test_it_leaves_wide_content_that_scrolls_alone(self):
        # The live alert table is 632px wide inside a 420px phone window and is
        # correct: it has its own scroll container. Reported as a fault, it was
        # the only line the check printed on a real screen, every time.
        self.assertEqual(self._faults(SCROLLER), [])

    def test_it_stays_quiet_on_a_page_with_neither(self):
        # Half of a check is not crying wolf: one that reports on every page is
        # one nobody reads by the second day.
        self.assertEqual(self._faults(CLEAN), [])


class ScreenshotScriptTest(BackendTestCase):
    """No browser needed: what the script promises about itself."""

    SOURCE = (PROJECT_ROOT / "scripts" / "screenshots.py").read_text(encoding="utf-8")

    def test_every_screen_the_panel_has_is_on_the_list(self):
        module = _load()
        for screen in ("dashboard", "alerts", "protection", "engine", "logs",
                       "notifications", "live", "setup", "system", "login"):
            with self.subTest(screen=screen):
                self.assertIn(screen, module.SCREENS)

    def test_it_shoots_a_phone_width_as_well(self):
        # The sidebar collapses, the tab bar scrolls sideways and the tables get
        # their own scroll container. Each of those has been wrong once.
        self.assertTrue(any(w < 700 for w in _load().WIDTHS), _load().WIDTHS)

    def test_the_password_is_never_an_argument(self):
        """It would land in the process list and in every shell history.

        Read from RAPI_PASS or asked for on the terminal, and passed to the
        panel's own endpoint from inside the page, so the browser keeps the
        session cookie and nothing here has to store anything.
        """
        self.assertIn("getpass", self.SOURCE)
        self.assertNotIn("--password", self.SOURCE)
        self.assertNotIn("add_argument(\"--pass", self.SOURCE)
