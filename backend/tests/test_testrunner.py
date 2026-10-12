"""scripts/test.sh: does it say a suite passed when it did not.

For a while it did. `run_backend || FAILED=1` suppresses errexit inside the
function, the function ended with `cd "$ROOT"`, and a function's exit status is
its last command - so a backend that failed to import came back as 0 and the
script printed "Both suites passed". This is the release gate for the whole
project, so a green light it cannot back up is the worst single fault in it.

Run against a fake tree rather than the real one: a stub interpreter that exits
with whatever this test wants, and no browser on PATH so the frontend half
takes its documented skip.
"""
from __future__ import annotations

import os
import shutil
import subprocess

from .helpers import PROJECT_ROOT, BackendTestCase


class TestRunnerTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        # scripts/test.sh works out the project root from its own location, so
        # a copy inside the temporary directory roots it there.
        (self.tmp / "scripts").mkdir()
        shutil.copy(PROJECT_ROOT / "scripts" / "test.sh", self.tmp / "scripts" / "test.sh")
        (self.tmp / "frontend" / "node_modules").mkdir(parents=True)

        # Just enough on PATH for the script to run, and deliberately no
        # chromium: the frontend half then skips and cannot colour the result.
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        for tool in ("bash", "dirname", "basename", "cat", "env"):
            found = shutil.which(tool)
            if found:
                (self.bin / tool).symlink_to(found)

    def _stub_python(self, exit_code: int) -> None:
        path = self.tmp / "backend" / ".venv" / "bin" / "python"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"#!/bin/sh\necho 'stub backend'\nexit {exit_code}\n")
        path.chmod(0o755)

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["PATH"] = str(self.bin)
        env["CHROME_BIN"] = ""
        return subprocess.run(
            [shutil.which("bash") or "/bin/bash",
             str(self.tmp / "scripts" / "test.sh"), *args],
            capture_output=True, text=True, timeout=60, env=env,
        )

    def test_a_failing_backend_fails_the_run(self):
        # The fault itself. This exited 0 and said both suites passed.
        self._stub_python(1)
        result = self._run("all")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Both suites passed", result.stdout)

    def test_a_failing_backend_says_so(self):
        self._stub_python(1)
        self.assertIn("FAILED", self._run("all").stdout)

    def test_a_passing_backend_still_passes(self):
        # Without this, "return 1 always" would pass the test above and turn the
        # gate red for everybody, for ever.
        self._stub_python(0)
        result = self._run("all")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Both suites passed", result.stdout)

    def test_the_backend_only_run_fails_too(self):
        self._stub_python(1)
        self.assertNotEqual(self._run("backend").returncode, 0)

    def test_a_missing_venv_is_a_failure_not_a_pass(self):
        # No stub interpreter at all: the script has its own message for this,
        # and it must not end in a green line either.
        result = self._run("all")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("setup.sh", result.stderr)

    def test_the_frontend_half_really_did_skip(self):
        # If chromium were found, the checks above would be measuring the
        # frontend suite against a fake tree instead of the thing they claim.
        self._stub_python(0)
        self.assertIn("skipping the frontend tests", self._run("all").stderr)


class NoRootFromTheSuiteTest(BackendTestCase):
    """A call the test forgot to replace must fail, not run as root."""

    def test_sudo_is_refused_inside_the_suite(self):
        proc = subprocess.run(["sudo", "-n", "true"], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refused inside the test suite", proc.stderr)

    def test_the_panel_s_own_rebuild_cannot_reach_the_engine_s_rules(self):
        from unittest.mock import patch
        from app.modules.suricata import protection
        with patch.object(protection, "record_silent_drops", return_value=False):
            ok, output = protection.rebuild(offline=True)
        self.assertFalse(ok)
        self.assertIn("refused inside the test suite", output)
