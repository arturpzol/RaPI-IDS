"""The files that run as root: sudoers, the systemd unit, the helper scripts.

Every silent failure this panel has had came from one of these three, and all
three looked fine from a shell. They are checked here as text and, where the
script allows it, by running it against a fixture.
"""
from __future__ import annotations

import io
import os
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import types
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from app import privileges, settings
from app.modules.network import capture, topology
from app.modules.suricata import protection

from .helpers import PROJECT_ROOT, BackendTestCase, run_helper

DEPLOY = PROJECT_ROOT / "deploy"
# Read before any test runs: BackendTestCase points the constant at a path
# that is not there, so that a test never forks sudo.
RULES_DATE_HELPER = protection.RULES_DATE_HELPER
SUDOERS = (DEPLOY / "sudoers-rapi-panel").read_text()
UNIT = (DEPLOY / "rapi-panel.service.in").read_text()


class ShellSyntaxTest(BackendTestCase):
    def test_every_script_parses(self):
        scripts = sorted(PROJECT_ROOT.glob("scripts/*.sh"))
        scripts += [p for p in DEPLOY.iterdir()
                    if p.is_file() and p.read_bytes().startswith(b"#!/usr/bin/env bash")]
        self.assertTrue(scripts)
        for script in scripts:
            with self.subTest(script=script.name):
                result = subprocess.run(["bash", "-n", str(script)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_script_stops_on_an_error(self):
        # Half a configuration change is worse than none.
        for script in sorted(DEPLOY.iterdir()):
            if not script.is_file() or not script.read_bytes().startswith(b"#!/usr/bin/env bash"):
                continue
            with self.subTest(script=script.name):
                self.assertIn("set -euo pipefail", script.read_text())

    def test_the_helpers_are_executable(self):
        for name in ("rapi-capture-apply", "rapi-capture-iface", "rapi-capture-probe",
                     "rapi-log-dir", "rapi-include", "rapi-outputs", "rapi-tuning",
                     "rapi-rules-update", "rapi-rules-date"):
            with self.subTest(helper=name):
                mode = (DEPLOY / name).stat().st_mode
                self.assertTrue(mode & stat.S_IXUSR, name)


class SudoersTest(BackendTestCase):
    def test_the_rebuild_command_matches_what_the_panel_runs(self):
        # Spelled out character by character, no wildcards: if the two drift
        # apart the rebuild starts asking for a password nobody can type.
        def templated(offline: bool) -> str:
            command = protection.rebuild_command(offline)[2:]   # drop "sudo -n"
            line = " ".join(["/usr/bin/" + command[0], *command[1:]])
            return (line
                    .replace(str(protection.DISABLE_CONF), "@DISABLE_CONF@")
                    .replace(str(protection.DROP_CONF), "@DROP_CONF@"))

        self.assertIn(templated(True), SUDOERS)
        self.assertIn(templated(False), SUDOERS)

    def test_every_helper_the_panel_calls_is_allowed(self):
        for helper in (capture.APPLY, capture.IFACE):
            with self.subTest(helper=helper):
                self.assertIn(helper, SUDOERS)

    def test_the_engine_control_the_panel_uses_is_allowed(self):
        # restart is not on a button any more, but the panel still needs it:
        # moving the log directory and changing the capture interface both do one.
        self.assertIn("/usr/bin/systemctl restart suricata", SUDOERS)
        self.assertIn("/usr/bin/suricatasc -c reload-rules", SUDOERS)

    def test_a_blanket_grant_is_recognised_however_it_is_written(self):
        """The narrow sudoers file is only worth something if it is the only one.

        On this very device cloud-init had left `rapi ALL=(ALL) NOPASSWD:ALL`
        in a separate file, which made every line of the narrow entry advice
        rather than a limit: `systemctl stop suricata` still worked after the
        privilege had been taken away.
        """
        listing = """User rapi may run the following commands on rapi-ids:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
    (root) ALL
    (root) NOPASSWD: /usr/bin/systemctl reload suricata
    (root) NOPASSWD: /usr/local/sbin/rapi-capture-apply *
"""
        self.assertEqual(
            privileges.blanket_grants(listing),
            ["(ALL : ALL) ALL", "(ALL) NOPASSWD: ALL", "(root) ALL"],
        )

    def test_the_narrow_entry_alone_is_not_a_finding(self):
        listing = """    (root) NOPASSWD: /usr/bin/systemctl restart suricata
    (root) NOPASSWD: /usr/bin/suricatasc -c reload-rules
    (root) NOPASSWD: /usr/local/sbin/rapi-bridge *
"""
        self.assertEqual(privileges.blanket_grants(listing), [])

    def test_the_image_does_not_hand_out_a_blanket_grant(self):
        # It builds the account with useradd, not cloud-init, so the file that
        # bit this device is not one the image writes. Pinned so it stays that way.
        customize = (PROJECT_ROOT / "image" / "customize.sh").read_text(encoding="utf-8")
        self.assertNotIn("NOPASSWD:ALL", customize.replace(" ", ""))

    def test_the_panel_cannot_switch_detection_off(self):
        """No start, no stop - not on a button and not in sudoers either.

        Leaving the privilege behind after taking the buttons away would make
        the change cosmetic: anything reaching the panel's user could still
        stop the one process this device exists to run.
        """
        for command in ("systemctl start suricata", "systemctl stop suricata"):
            with self.subTest(command=command):
                self.assertNotIn(command, SUDOERS)

    def test_no_blanket_privilege(self):
        # Every extra command widens what someone reaching the panel over HTTP
        # can do.
        grants = [l for l in SUDOERS.splitlines() if " ALL=(" in l]
        self.assertTrue(grants, SUDOERS)
        for line in grants:
            self.assertNotIn("NOPASSWD: ALL", line)

    def test_the_grant_names_the_account_the_panel_runs_as(self):
        """Not the literal rapi: a checkout installs the unit as whoever ran it.

        The sudoers file said `rapi ALL=(root)` whatever the unit said, so on a
        checkout by anybody else every privileged feature of the panel was
        refused by sudo and did nothing, quietly.
        """
        self.assertIn("@PANEL_USER@ ALL=(root)", SUDOERS)
        self.assertNotRegex(SUDOERS, r"(?m)^rapi ALL=")
        checkout = (PROJECT_ROOT / "scripts" / "install-service.sh").read_text()
        image = (PROJECT_ROOT / "image" / "customize.sh").read_text()
        # Both substitute it, and with the same name they give the unit.
        self.assertIn('-e "s|@PANEL_USER@|$(id -un)|g"', checkout)
        self.assertIn('s|@PANEL_USER@|$(id -un)|g', checkout.split("rapi-panel.service.in")[0])
        self.assertIn('-e "s|@PANEL_USER@|$PANEL_USER|g"', image)

    def test_wildcards_are_only_on_root_owned_helpers(self):
        for match in re.finditer(r"(\S+) \*", SUDOERS):
            with self.subTest(command=match.group(1)):
                self.assertTrue(match.group(1).startswith("/usr/local/sbin/rapi-"),
                                match.group(1))


    def test_the_date_helper_the_panel_calls_is_allowed(self):
        # Read only and argument free, so it is spelled out with no wildcard.
        self.assertIn(RULES_DATE_HELPER + "\n", SUDOERS)

    def test_every_helper_sudoers_grants_is_installed(self):
        """A privilege for a file that is not there is a feature that is not there.

        rapi-bridge was granted in sudoers and installed by the checkout path
        only. On a flashed image the inline layout in the topology wizard died
        with "command not found", which is the one place nobody looks, because
        sudoers said it was allowed.
        """
        installers = {
            "image/customize.sh": (PROJECT_ROOT / "image" / "customize.sh").read_text(),
            "scripts/install-service.sh":
                (PROJECT_ROOT / "scripts" / "install-service.sh").read_text()
                + (PROJECT_ROOT / "scripts" / "setup-suricata-override.sh").read_text(),
        }
        granted = sorted(set(re.findall(r"/usr/local/sbin/(rapi-[a-z-]+)", SUDOERS)))
        self.assertIn("rapi-bridge", granted)
        self.assertIn("rapi-rules-date", granted)
        for helper in granted:
            for where, text in installers.items():
                with self.subTest(helper=helper, installer=where):
                    self.assertIn(helper, text, f"{where} never installs {helper}")


class PrivilegedCallTest(BackendTestCase):
    """Every `sudo -n` in this repo has to be a command sudoers actually grants.

    On the image the panel account is not in group sudo (image/customize.sh),
    so the NOPASSWD lines in /etc/sudoers.d/rapi-panel are the whole of what it
    can run, whatever its password.

    A development box seeded by cloud-init carries `(ALL) NOPASSWD: ALL`, and
    every one of these calls works there whether sudoers grants it or not.
    That is what hid verify.sh asking for `suricatasc -c dump-counters` while
    sudoers granted only `reload-rules`: on the artifact the script exists to
    gate, the counters came back empty and two checks reported "?" while the
    script still exited 0.
    """

    CALL = re.compile(r"sudo\s+-n\s+([^\n|&;)]+)")

    def _calls(self) -> list[tuple[str, list[str]]]:
        found = []
        for path in sorted(PROJECT_ROOT.glob("scripts/*.sh")):
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.lstrip().startswith("#"):
                    continue
                for match in self.CALL.finditer(line):
                    words = match.group(1).split()
                    if words:
                        found.append((path.name, words))
        return found

    def test_the_scan_reads_the_scripts_it_claims_to(self):
        # A scan that finds nothing agrees with every assertion below.
        calls = self._calls()
        self.assertGreaterEqual(len(calls), 2)
        self.assertTrue(any(c[0] == "verify.sh" for c in calls))

    def test_every_privileged_call_is_one_sudoers_grants(self):
        for script, words in self._calls():
            with self.subTest(script=script, call=" ".join(words[:3])):
                command = words[0]
                self.assertIn(command.rsplit("/", 1)[-1], SUDOERS,
                              f"{script} runs {command} under sudo -n")
                # Fixed arguments count too: sudoers matches the whole command
                # line, so a different subcommand is a different permission.
                for word in words[1:3]:
                    if word.startswith(("$", '"', "'", "-")) or "$" in word:
                        continue
                    self.assertIn(word, SUDOERS,
                                  f"{script} runs {command} {word}, "
                                  "which sudoers does not list")


class SystemdUnitTest(BackendTestCase):
    """The sandbox has switched working features off three times.

    Each time the panel reported success and did nothing, so each capability is
    pinned here with the feature it belongs to.
    """

    def _value(self, key: str) -> str:
        """The value of a unit setting, with continuation lines folded in."""
        joined = UNIT.replace("\\\n", " ")
        values = [l.split("=", 1)[1] for l in joined.splitlines()
                  if l.strip().startswith(key + "=")]
        self.assertTrue(values, f"{key} missing from the unit")
        return " ".join(values)

    def test_sudo_can_still_work(self):
        # CapabilityBoundingSet with only CAP_NET_BIND_SERVICE stops setuid sudo
        # dead: "unable to change to root gid".
        caps = self._value("CapabilityBoundingSet")
        for capability in ("CAP_SETUID", "CAP_SETGID", "CAP_AUDIT_WRITE"):
            self.assertIn(capability, caps)

    def test_the_packet_probe_can_open_a_raw_socket(self):
        caps = self._value("CapabilityBoundingSet")
        self.assertIn("CAP_NET_RAW", caps)
        self.assertIn("CAP_NET_ADMIN", caps)

    def test_root_can_reach_the_data_directory(self):
        # /home/rapi is 0700, and without this suricata-update reports "file
        # does not exist" about a file that does, so muted signatures come back.
        self.assertIn("CAP_DAC_READ_SEARCH", self._value("CapabilityBoundingSet"))

    def test_dac_override_is_not_granted(self):
        self.assertNotIn("CAP_DAC_OVERRIDE", self._value("CapabilityBoundingSet"))

    def test_the_directories_the_helpers_write_to_are_writable(self):
        # ProtectSystem=full makes /etc read only for root children too - they
        # share the mount namespace of the unit.
        paths = self._value("ReadWritePaths")
        self.assertIn("/etc/suricata", paths)
        self.assertIn("/etc/NetworkManager", paths)

    def test_the_panel_comes_back_after_a_clean_exit(self):
        # With Restart=on-failure a SIGTERM from anywhere at all left the box
        # running with no panel until the next reboot. On an appliance that is
        # the difference between a hiccup and a site visit.
        self.assertEqual(self._value("Restart").strip(), "always")

    def test_the_hardening_that_should_stay(self):
        for setting in ("ProtectSystem=", "ProtectHome=", "NoNewPrivileges="):
            self.assertIn(setting, UNIT)


class InlineHelperTest(BackendTestCase):
    """The one helper that swaps who forwards an inline link, run for real.

    Every command it runs is a stub that records itself, so what is checked is
    the thing that matters here and that four reviews of the previous version
    kept finding wrong: the order. The engine configuration verified before
    anything moves. The engine stopped before either forwarding path changes,
    so there is never a moment with two forwarders. A failure after that point
    converging on the kernel bridge, which forwards without the engine.
    """

    STUBS = ("rapi-capture-apply", "rapi-capture-iface", "rapi-bridge",
             "rapi-ips-mode", "systemctl", "ethtool")

    def setUp(self):
        super().setUp()
        self.sys_net = self.tmp / "class-net"
        for name, mac in (("eth0", "de:ad:be:ef:00:00"), ("eth1", "de:ad:be:ef:00:01"),
                          ("wlan0", "de:ad:be:ef:00:02")):
            (self.sys_net / name).mkdir(parents=True)
            (self.sys_net / name / "address").write_text(mac + "\n")
        self.conf = self.tmp / "inline-nm-conf.d"
        self.conf.mkdir()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.log = self.tmp / "commands.log"
        self.log.write_text("")
        self.fails = self.tmp / "fails"
        for name in self.STUBS:
            self._stub(name)
        self._route("wlan0")

    def _stub(self, name: str) -> None:
        """Records `name args`, then fails if a line in `fails` is a prefix of it.

        A line starting with `once:` fails the first match and is then removed,
        which is how a restart that fails once and works on the retry is shown.
        """
        extra = ""
        if name == "rapi-bridge":
            # What the real helper leaves behind, so the check after the engine
            # starts has a bridge to look at.
            extra = (
                f'skip=""; [ -f "{self.tmp}/skip-member" ] && skip="$(cat "{self.tmp}/skip-member")"\n'
                'if [ "$2" = "up" ]; then\n'
                '  for m in "$3" "$4"; do [ "$m" = "$skip" ] || mkdir -p "$SYS_NET/$1/brif/$m"; done\n'
                'fi\n'
                'if [ "$2" = "down" ]; then rm -rf "$SYS_NET/$1"; fi\n'
            )
        stub = self.bin / name
        stub.write_text(
            "#!/bin/sh\n"
            f'SYS_NET="{self.sys_net}"\n'
            f'line="{name} $*"\n'
            f'echo "$line" >> "{self.log}"\n'
            f'if [ -f "{self.fails}" ]; then\n'
            f'  while IFS= read -r pat; do\n'
            f'    once=0; case "$pat" in once:*) once=1; pat="${{pat#once:}}";; esac\n'
            f'    case "$line" in "$pat"*)\n'
            f'      if [ $once -eq 1 ]; then grep -vxF "once:$pat" "{self.fails}" > "{self.fails}.n"; mv "{self.fails}.n" "{self.fails}"; fi\n'
            f'      exit 1;; esac\n'
            f'  done < "{self.fails}"\n'
            f'fi\n'
            + extra +
            "exit 0\n")
        stub.chmod(0o755)

    def _route(self, *ifaces: str) -> None:
        """What `ip -4 route show default` says, one line per interface.

        Several, because a device with a way out over Wi-Fi and a lease on a
        port it is about to bridge has two, and which of them exist is the whole
        question the guard asks.
        """
        routes = "".join(
            f'  echo "default via 10.0.0.1 dev {iface} proto dhcp metric {100 + i}"\n'
            for i, iface in enumerate(ifaces))
        stub = self.bin / "ip"
        stub.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "-4" ]; then\n' + routes + "  exit 0\nfi\n"
            f'echo "ip $*" >> "{self.log}"\n'
            "exit 0\n")
        stub.chmod(0o755)

    def _fail(self, *patterns: str) -> None:
        self.fails.write_text("".join(p + "\n" for p in patterns))

    def _run(self, mode="pair", a="eth0", b="eth1", home_net="[10.10.0.0/16]"):
        return run_helper(
            "rapi-inline", mode, a, b, home_net,
            env={
                "RAPI_SYS_NET": str(self.sys_net),
                "RAPI_NM_CONF_DIR": str(self.conf),
                "RAPI_CAPTURE_APPLY_BIN": str(self.bin / "rapi-capture-apply"),
                "RAPI_CAPTURE_IFACE_BIN": str(self.bin / "rapi-capture-iface"),
                "RAPI_BRIDGE_BIN": str(self.bin / "rapi-bridge"),
                "RAPI_IPS_MODE_BIN": str(self.bin / "rapi-ips-mode"),
            },
            path_prefix=self.bin)

    def lines(self) -> list[str]:
        return [line for line in self.log.read_text().splitlines()
                if not line.startswith(("ip link", "ethtool"))]

    def index(self, prefix: str) -> int:
        for i, line in enumerate(self.lines()):
            if line.startswith(prefix):
                return i
        self.fail(f"{prefix!r} never ran: {self.lines()}")

    def _bridge_exists(self):
        (self.sys_net / "br-rapi" / "brif" / "eth0").mkdir(parents=True)
        (self.sys_net / "br-rapi" / "brif" / "eth1").mkdir(parents=True)

    # --- the two targets --------------------------------------------------------

    def test_the_pair_is_built_in_the_one_safe_order(self):
        self._bridge_exists()
        proc = self._run("pair")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.lines(), [
            "rapi-capture-apply eth0 [10.10.0.0/16] eth1",
            "rapi-ips-mode clear",
            "systemctl stop suricata",
            "rapi-bridge br-rapi down",
            "rapi-capture-iface eth0 capture",
            "rapi-capture-iface eth1 capture",
            "systemctl start suricata",
            "systemctl is-active --quiet suricata",
        ])

    def test_the_bridge_is_built_in_the_one_safe_order(self):
        proc = self._run("bridge")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.lines(), [
            "rapi-capture-apply br-rapi [10.10.0.0/16]",
            "rapi-ips-mode clear",
            "systemctl stop suricata",
            "rapi-bridge br-rapi up eth0 eth1",
            "systemctl start suricata",
            "systemctl is-active --quiet suricata",
        ])

    def test_there_is_never_a_moment_with_two_forwarders(self):
        """The engine stops before either forwarding path is touched.

        Coming back from the pair, a bridge built while the engine still
        forwarded between the same two ports sent every frame across twice,
        and if the configuration was then refused the duplication stayed.
        """
        for mode in ("pair", "bridge"):
            with self.subTest(mode=mode):
                self.log.write_text("")
                self._run(mode)
                stop = self.index("systemctl stop")
                for line in self.lines()[:stop]:
                    self.assertFalse(line.startswith(("rapi-bridge", "rapi-capture-iface")),
                                     f"{line!r} ran while the engine could still be forwarding")

    # --- nothing changes when the configuration is refused ----------------------

    def test_a_refused_configuration_changes_nothing_at_all(self):
        # Written and verified first, so there is no rollback to get wrong:
        # the engine, the bridge and both ports are exactly as they were.
        self._fail("rapi-capture-apply")
        proc = self._run("pair")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("nothing was changed", proc.stderr)
        self.assertEqual(self.lines(), ["rapi-capture-apply eth0 [10.10.0.0/16] eth1"])

    def test_a_queue_that_will_not_clear_stops_before_the_engine(self):
        self._fail("rapi-ips-mode clear")
        proc = self._run("pair")
        self.assertEqual(proc.returncode, 1)
        self.assertNotIn("systemctl stop suricata", self.lines())

    # --- a failure after the stop converges on the bridge -----------------------

    def test_a_pair_that_cannot_be_built_leaves_the_bridge_carrying_the_link(self):
        self._fail("rapi-capture-iface eth1 capture")
        proc = self._run("pair")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("fallback bridge", proc.stdout)
        after = self.lines()[self.index("rapi-capture-iface eth1 capture"):]
        self.assertIn("rapi-capture-apply br-rapi [10.10.0.0/16]", after)
        self.assertIn("rapi-bridge br-rapi up eth0 eth1", after)
        self.assertEqual(after[-2:], ["systemctl start suricata",
                                      "systemctl is-active --quiet suricata"])

    def test_an_engine_that_will_not_start_is_retried_on_the_bridge(self):
        self._fail("once:systemctl start")
        proc = self._run("pair")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertEqual(self.lines().count("systemctl start suricata"), 2)

    def test_it_says_the_link_is_down_when_even_the_bridge_will_not_come_back(self):
        self._fail("rapi-capture-iface eth1 capture", "rapi-bridge br-rapi up")
        proc = self._run("pair")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("the link is down", proc.stderr)

    def test_a_bridge_that_says_yes_without_both_ports_is_not_believed(self):
        """The helper's word is checked against the machine.

        A bridge helper that exits 0 with one port still outside the bridge is a
        link that carries nothing in one direction, reported as a success. The
        membership is read back after the engine starts, and a port missing
        from it counts as the failure it is.
        """
        (self.tmp / "skip-member").write_text("eth1")
        proc = self._run("bridge")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("eth1 is not in the bridge", proc.stdout + proc.stderr)

    def test_the_bridge_configuration_is_accepted_before_the_bridge_exists(self):
        """rapi-inline and the real rapi-capture-apply, together.

        Every other test here replaces rapi-capture-apply with a stub, and so
        did every test of rapi-capture-apply replace rapi-inline. Booting the
        image found what that hid: the swap writes the configuration before it
        builds the bridge, by design, and rapi-capture-apply refused a bridge
        that did not exist yet, so going back to detection failed every time.
        """
        yaml = self.tmp / "suricata.yaml"
        yaml.write_text(
            "%YAML 1.1\n---\nvars:\n  address-groups:\n"
            "    HOME_NET: \"[192.168.0.0/16]\"\n"
            "af-packet:\n  - interface: eth0\n")
        engine = self.bin / "suricata"
        engine.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            "  --dump-config) cat <<'DUMP'\n"
            "vars.address-groups.HOME_NET = [192.168.0.0/16]\n"
            "vars.address-groups.EXTERNAL_NET = !$HOME_NET\n"
            "vars.port-groups.HTTP_PORTS = 80\n"
            "DUMP\n"
            "  exit 0 ;;\n"
            "esac\n"
            "exit 0\n")
        engine.chmod(0o755)
        capture_yaml = self.tmp / "rapi-capture.yaml"
        proc = run_helper(
            "rapi-inline", "bridge", "eth0", "eth1", "[10.10.0.0/16]",
            env={
                "RAPI_SYS_NET": str(self.sys_net),
                "RAPI_NM_CONF_DIR": str(self.conf),
                "RAPI_CAPTURE_APPLY_BIN": str(DEPLOY / "rapi-capture-apply"),
                "RAPI_CAPTURE_IFACE_BIN": str(self.bin / "rapi-capture-iface"),
                "RAPI_BRIDGE_BIN": str(self.bin / "rapi-bridge"),
                "RAPI_IPS_MODE_BIN": str(self.bin / "rapi-ips-mode"),
                "RAPI_SURICATA_YAML": str(yaml),
                "RAPI_SURICATA_CAPTURE": str(capture_yaml),
                "RAPI_SURICATA_VARS": str(self.tmp / "rapi-home-net.yaml"),
                "RAPI_HOME_NET_STATE": str(self.tmp / "rapi-home-net"),
                "RAPI_SURICATA_CONF_DIR": str(self.tmp),
                "RAPI_INCLUDE_BIN": str(DEPLOY / "rapi-include"),
            },
            path_prefix=self.bin)
        self.assertNotIn("no such interface: br-rapi", proc.stderr)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("- interface: br-rapi", capture_yaml.read_text())

    def test_the_panel_recognises_the_fallback_this_helper_prints(self):
        """rapi-inline's real output, read by the panel the way _run hands it over.

        The panel's own test fed it a fallback line and nothing after it. The
        helper prints the cause after that line, and _run appends stderr, so
        every real fallback reached the operator without being told the link
        still carries traffic.
        """
        self._fail("rapi-capture-iface eth1 capture")
        proc = self._run("pair")
        self.assertEqual(proc.returncode, 2, proc.stderr)
        settings.set(topology.SETTINGS_KEY, {
            "profile": "bridge", "applied": True, "home_net": "[10.10.0.0/16]",
            "roles": {"bridge_a": "eth0", "bridge_b": "eth1", "management": "wlan0"},
        })
        with patch.object(
                capture, "_run", return_value=(False, (proc.stdout + proc.stderr).strip())):
            ok, output = capture.set_inline_blocking(True)
        self.assertFalse(ok)
        self.assertIn("traffic flows and nothing is blocked", output)

    def test_the_reason_a_helper_gave_reaches_the_operator(self):
        """"The bridge could not be built" and nothing else.

        That was all the one run that mattered had to say, booting the image,
        because every helper's output went to /dev/null. The words of the
        helper that failed travel with the failure now.
        """
        bridge = self.bin / "rapi-bridge"
        bridge.write_text(
            "#!/bin/sh\n"
            f'echo "rapi-bridge $*" >> "{self.log}"\n'
            'echo "Error: Connection activation failed: device eth1 not available" >&2\n'
            "exit 1\n")
        bridge.chmod(0o755)
        proc = self._run("bridge")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("device eth1 not available", proc.stderr)

    def test_a_helper_that_fails_without_a_word_is_still_reported(self):
        # An empty failure gave the error filter nothing to keep, and under
        # pipefail that ended this script in the middle of a swap, silently.
        bridge = self.bin / "rapi-bridge"
        bridge.write_text(f'#!/bin/sh\necho "rapi-bridge $*" >> "{self.log}"\nexit 1\n')
        bridge.chmod(0o755)
        proc = self._run("bridge")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("failed without saying why", proc.stderr)
        self.assertIn("the link is down", proc.stderr)

    def test_every_way_out_starts_the_engine_again(self):
        # The condition stopping it was allowed on. Even when the fallback
        # itself fails, the last thing tried is starting the engine.
        self._fail("rapi-capture-iface eth1 capture", "rapi-bridge br-rapi up")
        self._run("pair")
        stop = self.index("systemctl stop")
        self.assertIn("systemctl start suricata", self.lines()[stop:])

    # --- the ports ------------------------------------------------------------------

    def test_a_port_held_under_its_old_name_is_found_by_its_card(self):
        """A USB adapter's name moves between boots; its MAC does not.

        The file was written as eth9. The card it matches is eth1 today. Asking
        for eth9 back fails with "no such interface" and leaves eth1 unmanaged,
        and no bridge can be built on a device NetworkManager does not manage.
        """
        (self.conf / "99-rapi-capture-eth9.conf").write_text(
            "[device-rapi-capture-eth9]\nmatch-device=mac:de:ad:be:ef:00:01\nmanaged=0\n")
        proc = self._run("bridge")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("rapi-capture-iface eth1 restore", self.lines())
        self.assertNotIn("rapi-capture-iface eth9 restore", self.lines())

    def test_a_port_that_is_not_held_is_left_alone(self):
        # A live bridge member handed through restore gets its offloads turned
        # back on for nothing.
        proc = self._run("bridge")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse([l for l in self.lines() if l.endswith("restore")])

    def test_the_ports_are_prepared_even_when_the_bridge_was_already_up(self):
        # rapi-bridge exits early on a bridge that exists and never reaches its
        # own offload loop, which left GRO on both ports after a way back.
        self._bridge_exists()
        self._run("bridge")
        raw = self.log.read_text()
        for port in ("eth0", "eth1"):
            with self.subTest(port=port):
                self.assertIn(f"ethtool -K {port} gro off", raw)
                self.assertIn(f"ip link set {port} promisc on", raw)

    # --- refused before anything --------------------------------------------------

    def test_the_port_carrying_the_only_default_route_is_refused_first(self):
        self._route("eth1")
        proc = self._run("pair")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("default route", proc.stderr)
        self.assertEqual(self.lines(), [])

    def test_a_lease_on_a_member_does_not_block_the_swap(self):
        """What happened on this device on 2026-09-18.

        Switching blocking off hands both ports back to NetworkManager for a
        moment, one of them picks up a lease with a default route, and the old
        check then refused to build the bridge. The ports were already
        released, so the link carried nothing, the engine could not start on a
        bridge that did not exist, and the panel could not put any of it back:
        a check meant to keep the device reachable had taken the network down.

        The device is still reachable over wlan0 here, which is the whole
        point: the question is not whether a member carries a default route but
        whether anything else does.
        """
        for mode in ("bridge", "pair"):
            with self.subTest(mode=mode):
                self.log.write_text("")
                self._route("eth0", "wlan0")
                proc = self._run(mode)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("systemctl start suricata", self.lines())

    def test_both_members_carrying_the_only_routes_is_still_refused(self):
        self._route("eth0", "eth1")
        proc = self._run("bridge")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("Reach the panel another way", proc.stderr)
        self.assertEqual(self.lines(), [])

    def test_a_device_with_no_default_route_at_all_is_not_refused(self):
        # A fresh appliance on a network with no DHCP server. Nothing to lose.
        self._route()
        proc = self._run("bridge")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_arguments_are_checked_before_anything_runs(self):
        cases = (
            (("sideways", "eth0", "eth1", "[10.0.0.0/8]"), "not a mode"),
            (("pair", "eth0", "eth0", "[10.0.0.0/8]"), "have to differ"),
            (("pair", "eth0", "eth7", "[10.0.0.0/8]"), "no such interface"),
            (("pair", "eth0;id", "eth1", "[10.0.0.0/8]"), "not an interface name"),
            (("pair", "eth0", "eth1", "[10.0.0.0/8]\nx"), "not a network list"),
        )
        for args, message in cases:
            with self.subTest(args=args):
                self.log.write_text("")
                proc = self._run(*args)
                self.assertEqual(proc.returncode, 1)
                self.assertIn(message, proc.stderr)
                self.assertEqual(self.lines(), [])


class BridgeHelperTest(BackendTestCase):
    """The helper that can take a working network down.

    Everything it decides is decided before anything is created, so all of that
    can be exercised here: the machine it reads (interfaces, the default route)
    comes from a fixture tree, and the commands it would run are stubs that
    record their arguments.
    """

    def setUp(self):
        super().setUp()
        self.sys_net = self.tmp / "class-net"
        for name in ("eth0", "eth1", "wlan0"):
            (self.sys_net / name).mkdir(parents=True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.log = self.tmp / "commands.log"
        for command in ("nmcli", "ip", "ethtool"):
            stub = self.bin / command
            stub.write_text(
                f'#!/bin/sh\necho "{command} $*" >> "{self.log}"\nexit 0\n')
            stub.chmod(0o755)
        self._route("wlan0")

    def _route(self, *ifaces: str) -> None:
        """`ip -4 route show default`, one line per interface that carries one."""
        routes = "".join(
            f'  echo "default via 10.0.0.1 dev {iface} proto dhcp metric {100 + i}"\n'
            for i, iface in enumerate(ifaces))
        stub = self.bin / "ip"
        stub.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "-4" ]; then\n' + routes + "  exit 0\nfi\n"
            f'echo "ip $*" >> "{self.log}"\n'
        )
        stub.chmod(0o755)

    def _run(self, *args):
        return run_helper("rapi-bridge", *args,
                          env={"RAPI_SYS_NET": str(self.sys_net)},
                          path_prefix=self.bin)

    def commands(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def test_a_bridge_is_built_from_two_interfaces(self):
        proc = self._run("br-rapi", "up", "eth0", "eth1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        log = self.commands()
        self.assertIn("nmcli connection add type bridge ifname br-rapi", log)
        self.assertIn("con-name br-rapi-eth0 master br-rapi", log)
        self.assertIn("con-name br-rapi-eth1 master br-rapi", log)

    def test_the_bridge_carries_no_address_of_its_own(self):
        # An inline bridge is meant to be invisible. An address on it is one
        # more thing on the segment being inspected.
        self._run("br-rapi", "up", "eth0", "eth1")
        self.assertIn("ipv4.method disabled", self.commands())
        self.assertIn("ipv6.method disabled", self.commands())

    def test_spanning_tree_stays_off(self):
        self._run("br-rapi", "up", "eth0", "eth1")
        self.assertIn("stp no", self.commands())

    def test_the_offloads_that_rewrite_frames_are_turned_off(self):
        # Same reason as the capture interface: rules measuring sizes or offsets
        # would match against frames the network never carried.
        self._run("br-rapi", "up", "eth0", "eth1")
        for feature in ("gro", "lro", "tso", "gso"):
            self.assertIn(f"ethtool -K eth0 {feature} off", self.commands())

    def test_the_interface_carrying_the_only_default_route_is_refused(self):
        # The last line of defence before the network changes, checked against
        # the machine as it is rather than against what the panel detected.
        self._route("eth0")
        proc = self._run("br-rapi", "up", "eth0", "eth1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("default route", proc.stderr)
        self.assertNotIn("nmcli", self.commands())

    def test_a_member_with_a_lease_is_bridged_when_another_way_out_exists(self):
        # A port handed back to NetworkManager for a moment picks up a lease,
        # and refusing then leaves the link with nothing carrying it.
        self._route("eth0", "wlan0")
        proc = self._run("br-rapi", "up", "eth0", "eth1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("nmcli connection add type bridge ifname br-rapi",
                      self.commands())

    def test_one_interface_cannot_be_both_sides(self):
        proc = self._run("br-rapi", "up", "eth0", "eth0")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("two different interfaces", proc.stderr)

    def test_an_interface_that_is_not_there_is_refused(self):
        proc = self._run("br-rapi", "up", "eth0", "eth9")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("no such interface", proc.stderr)

    def test_a_name_that_is_not_a_name_is_refused(self):
        proc = self._run("br-rapi", "up", "eth0; reboot", "eth1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("not an interface name", proc.stderr)

    def test_building_the_same_bridge_twice_changes_nothing(self):
        # The wizard can be walked through again, and rebuilding a working
        # bridge would be an outage for no reason.
        (self.sys_net / "br-rapi" / "brif" / "eth0").mkdir(parents=True)
        (self.sys_net / "br-rapi" / "brif" / "eth1").mkdir(parents=True)
        proc = self._run("br-rapi", "up", "eth0", "eth1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("already up", proc.stdout)
        self.assertNotIn("nmcli connection add", self.commands())

    def test_a_bridge_with_other_members_is_not_silently_reused(self):
        (self.sys_net / "br-rapi" / "brif" / "eth0").mkdir(parents=True)
        (self.sys_net / "br-rapi" / "brif" / "wlan0").mkdir(parents=True)
        proc = self._run("br-rapi", "up", "eth0", "eth1")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("different members", proc.stderr)

    def test_taking_it_down_hands_the_interfaces_back(self):
        (self.sys_net / "br-rapi" / "brif" / "eth0").mkdir(parents=True)
        (self.sys_net / "br-rapi" / "brif" / "eth1").mkdir(parents=True)
        proc = self._run("br-rapi", "down")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        log = self.commands()
        self.assertIn("nmcli connection delete br-rapi-eth0", log)
        self.assertIn("nmcli connection delete br-rapi-eth1", log)
        self.assertIn("ethtool -K eth0 gro on", log)


class SandboxHolesTest(BackendTestCase):
    """Every /etc path a helper writes to must be a hole in the unit sandbox.

    `ProtectSystem=full` makes /etc read-only for the whole unit, and the
    root-owned helpers sudo starts run inside that same mount namespace - being
    root buys them nothing there. A helper that writes somewhere the unit does
    not open fails with "Read-only file system" at the moment somebody presses
    the button.

    This is derived from the scripts rather than written out by hand, because
    the way it breaks is always the same: a helper learns to write somewhere
    new, the unit is not touched, and nothing goes wrong until it runs through
    the service. Running the helper from a shell works - a shell is not in the
    namespace - which is exactly what makes it easy to ship broken. It shipped
    twice: once for /etc/systemd/system, once for /etc/logrotate.d.
    """

    def _raw_read_write_paths(self):
        """Exactly as written, dashes and substitution markers included."""
        line = next(l for l in UNIT.splitlines() if l.startswith("ReadWritePaths="))
        return line.split("=", 1)[1].split()

    def _read_write_paths(self):
        # The leading dash is systemd's "tolerate this being absent", not part
        # of the path, so it is stripped here: a helper writing under an
        # optional path is still writing under a path the sandbox opens.
        return [p.lstrip("-") for p in self._raw_read_write_paths()
                if p.lstrip("-").startswith("/")]

    # Paths a helper only ever reads. ProtectSystem=full leaves /etc readable,
    # so these need no hole - but they have to be named here rather than
    # silently skipped, because "named in a script" is how the check finds a
    # write it was never told about. Anything new still fails until somebody
    # decides which of the two it is.
    READ_ONLY_ETC = {
        # rapi-log-dir asks findmnt whether the parent of the log directory is
        # a mount point that failed to mount. It never writes it.
        "/etc/fstab",
    }

    def _helper_paths(self):
        """Every /etc path named in a helper, comments stripped."""
        found: dict[str, str] = {}
        for script in sorted(DEPLOY.glob("rapi-*")):
            if script.name.startswith("rapi-panel"):
                continue
            # Only the helpers the panel itself runs over sudo, because the
            # sandbox this is about is the panel's. rapi-issue writes /etc/issue
            # and the panel never calls it: systemd does at boot, and
            # NetworkManager does when an address changes. Naming it here would
            # mean opening /etc/issue to the panel for no reason at all.
            if script.name not in SUDOERS:
                continue
            for raw in script.read_text(encoding="utf-8").splitlines():
                for hit in re.findall(r"/etc/[A-Za-z0-9._/-]+", raw.split("#", 1)[0]):
                    found.setdefault(hit, script.name)
        return found

    def test_every_etc_path_a_helper_touches_is_open_in_the_unit(self):
        allowed = self._read_write_paths()
        paths = self._helper_paths()
        self.assertTrue(paths, "no /etc paths found - the extraction broke")
        for path, script in sorted(paths.items()):
            if path in self.READ_ONLY_ETC:
                continue
            with self.subTest(path=path, script=script):
                self.assertTrue(
                    any(path == a or path.startswith(a.rstrip("/") + "/") for a in allowed),
                    f"{script} writes {path}, which ReadWritePaths does not open",
                )

    def test_no_read_only_exemption_outlives_its_script(self):
        """The list above is a human judgement, and the way it rots is an entry
        left behind after the script stopped using the path. A stale exemption
        is a hole nobody meant to leave open, so each one has to still be named
        by a helper."""
        named = set(self._helper_paths())
        for path in sorted(self.READ_ONLY_ETC):
            with self.subTest(path=path):
                self.assertIn(path, named,
                              f"{path} is exempted but no helper mentions it any more")

    # Paths in ReadWritePaths that no package creates. systemd refuses to start
    # a service whose ReadWritePaths names a directory that is not there, and it
    # says "Failed at step NAMESPACE", which reads as a broken interpreter.
    # Each entry here is a package that ships the directory, and the package has
    # to be in the image for the claim to hold.
    PATH_OWNERS = {
        "/etc/suricata": "suricata",
        "/etc/NetworkManager": "network-manager",
        "/etc/systemd/system": "systemd",
        "/etc/logrotate.d": "logrotate",
    }

    def test_a_path_that_might_not_exist_is_marked_optional(self):
        # The regression this exists for: /etc/nftables.d was added without the
        # leading dash, the nftables package does not create it, and the panel
        # could not start at all - 52 restarts in one boot, with the only clue
        # being "Failed at step NAMESPACE spawning /usr/bin/python3".
        image_packages = (PROJECT_ROOT / "image" / "packages.list").read_text()
        for entry in self._raw_read_write_paths():
            if entry.startswith("-") or entry.startswith("@"):
                continue
            with self.subTest(path=entry):
                owner = self.PATH_OWNERS.get(entry)
                # A directory the build creates is not enough. The panel also
                # runs from a checkout, and an image upgraded in place keeps the
                # /etc it already had, so the only thing that makes a path
                # certain is a package that ships it.
                self.assertIsNotNone(
                    owner,
                    f"{entry} is required to exist and no package here ships it - "
                    f"write it as -{entry}, or add it to PATH_OWNERS",
                )
                self.assertIn(owner, image_packages,
                              f"{entry} is claimed to come from {owner}, which the image "
                              f"does not install")

    def test_no_owner_claim_outlives_its_path(self):
        """PATH_OWNERS is a human judgement and rots the same way READ_ONLY_ETC
        does: an entry left behind after the path stopped being needed."""
        entries = set(self._raw_read_write_paths())
        for path in sorted(self.PATH_OWNERS):
            with self.subTest(path=path):
                self.assertIn(path, entries)

    def test_the_sandbox_is_still_on(self):
        # The lazy fix for the above is to drop ProtectSystem. This says no.
        self.assertIn("ProtectSystem=full", UNIT)
        self.assertIn("ProtectHome=read-only", UNIT)

    def test_no_hole_is_wider_than_a_directory_the_panel_uses(self):
        # /etc on its own would make the sandbox decorative.
        for path in self._read_write_paths():
            with self.subTest(path=path):
                self.assertNotIn(path.rstrip("/"), ("/etc", "/usr", "/", "/boot"))


class OverrideOwnerTest(BackendTestCase):
    """Who gets /etc/suricata/rapi-overrides.yaml.

    The panel writes the log directory into it, so it has to belong to the
    account the panel runs as. The script took that from ${SUDO_USER:-$USER},
    which is right when a person runs it with sudo and wrong in the one place
    every device runs it: the first boot, as root, from a unit, where systemd
    sets USER to nothing. `chown :` then succeeds and changes nothing, the file
    stays root's, and the first thing a freshly flashed card said on the System
    screen was "the panel cannot write to /etc/suricata/rapi-overrides.yaml".
    """

    SCRIPT = PROJECT_ROOT / "scripts" / "setup-suricata-override.sh"

    def _run(self, **env: str) -> tuple[subprocess.CompletedProcess, str]:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "suricata.yaml").write_text("%YAML 1.1\n---\nvars: {}\n")
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        log = tmp / "sudo.log"
        # sudo that writes the files the script names (all under tmp) and only
        # records the rest. suricata -T fails, which is where the script stops:
        # after the owner is settled and before anything touches the system.
        (bin_dir / "sudo").write_text(
            "#!/bin/sh\n"
            f'echo "$*" >> "{log}"\n'
            'case "$1" in\n'
            '  tee|cp) exec "$@" ;;\n'
            '  suricata) exit 1 ;;\n'
            'esac\n'
            'exit 0\n')
        (bin_dir / "sudo").chmod(0o755)
        environment = {k: v for k, v in os.environ.items()
                       if k not in ("SUDO_USER", "RAPI_PANEL_USER")}
        environment.update({
            "PATH": f"{bin_dir}:{environment['PATH']}",
            "RAPI_SURICATA_YAML": str(tmp / "suricata.yaml"),
            "RAPI_SURICATA_OVERRIDE": str(tmp / "rapi-overrides.yaml"),
        })
        environment.update(env)
        proc = subprocess.run(["bash", str(self.SCRIPT)], capture_output=True,
                              text=True, timeout=60, env=environment)
        return proc, log.read_text() if log.exists() else ""

    def chowns(self, log: str) -> list[str]:
        return [l for l in log.splitlines() if l.startswith("chown ")]

    def test_the_first_boot_names_the_owner(self):
        # What the unit gives it: no SUDO_USER, an empty USER.
        _, log = self._run(USER="", RAPI_PANEL_USER="rapi")
        self.assertEqual(len(self.chowns(log)), 1, log)
        self.assertTrue(self.chowns(log)[0].startswith("chown rapi:rapi "), log)

    def test_the_first_boot_passes_the_owner(self):
        script = (PROJECT_ROOT / "image" / "first-boot" / "rapi-first-boot.sh").read_text()
        wire = re.search(r"wire_engine\(\) \{(.*?)\n\}", script, re.S).group(1)
        self.assertIn("RAPI_PANEL_USER=rapi", wire)

    def test_nobody_to_give_it_to_is_refused_not_ignored(self):
        proc, log = self._run(USER="")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("RAPI_PANEL_USER", proc.stderr)
        self.assertEqual(self.chowns(log), [], log)

    def test_root_is_not_an_answer(self):
        # The panel never runs as root, so a file of root's is the bug itself.
        proc, log = self._run(USER="root")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.chowns(log), [], log)

    def test_a_person_with_sudo_still_gets_it(self):
        _, log = self._run(USER="root", SUDO_USER="someone")
        self.assertTrue(self.chowns(log)[0].startswith("chown someone:someone "), log)


class OverrideWithoutANetworkTest(BackendTestCase):
    """setup-suricata-override.sh on a device with no IPv4 link route yet.

    The first boot runs it before anybody has plugged a cable in. Its HOME_NET
    detection returned 1 there, and under set -e the assignment ended the whole
    script before its own "leave HOME_NET alone" branch, skipping the output
    and tuning helpers after it. Silent on the old first boot, which stamped
    itself done anyway; a boot that never finishes on the new one.
    """

    SCRIPT = PROJECT_ROOT / "scripts" / "setup-suricata-override.sh"

    def test_it_leaves_home_net_alone_and_carries_on(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        yaml = tmp / "suricata.yaml"
        yaml.write_text("%YAML 1.1\n---\nvars:\n  address-groups:\n"
                        "    HOME_NET: \"[192.168.0.0/16]\"\n")
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        log = tmp / "sudo.log"
        (bin_dir / "sudo").write_text(
            "#!/bin/sh\n"
            f'echo "$*" >> "{log}"\n'
            'case "$1" in tee|cp|awk) exec "$@" ;; esac\n'
            "exit 0\n")
        (bin_dir / "ip").write_text("#!/bin/sh\nexit 0\n")          # no routes at all
        (bin_dir / "suricata").write_text("#!/bin/sh\nexit 0\n")
        for f in bin_dir.iterdir():
            f.chmod(0o755)
        environment = {k: v for k, v in os.environ.items() if k != "RAPI_HOME_NET"}
        environment.update({
            "PATH": f"{bin_dir}:{environment['PATH']}",
            "RAPI_SURICATA_YAML": str(yaml),
            "RAPI_SURICATA_OVERRIDE": str(tmp / "rapi-overrides.yaml"),
            "RAPI_HOME_NET_STATE": str(tmp / "rapi-home-net"),
            "RAPI_PANEL_USER": "rapi",
        })
        proc = subprocess.run(["bash", str(self.SCRIPT)], capture_output=True,
                              text=True, timeout=60, env=environment)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("Could not work out HOME_NET", proc.stderr)
        self.assertIn('HOME_NET: "[192.168.0.0/16]"', yaml.read_text())
        # The helpers after it still ran.
        ran = log.read_text()
        self.assertIn("/usr/local/sbin/rapi-outputs", ran)
        self.assertIn("/usr/local/sbin/rapi-tuning", ran)


class ExportPublicTest(BackendTestCase):
    """scripts/export-public.sh: the public branch, without the private parts.

    The working repository keeps the Polish journal in docs/, the Polish README
    and the whole history. The public one gets one parentless commit of the
    code, rebuilt on every run, and nothing Polish.
    """

    def setUp(self):
        super().setUp()
        self.repo = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.repo, True)
        (self.repo / "scripts").mkdir()
        shutil.copy(PROJECT_ROOT / "scripts" / "export-public.sh", self.repo / "scripts")
        (self.repo / "backend" / "app").mkdir(parents=True)
        (self.repo / "backend" / "app" / "main.py").write_text('VERSION = "0.5.0"\n')
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "obraz-ids.md").write_text("Obraz jest gotowy, wiec dziala.\n")
        (self.repo / "README.md").write_text("Panel dziala tylko przez HTTPS.\n")
        (self.repo / "NOTES.md").write_text("The panel serves HTTPS only.\n")
        (self.repo / "README.en.md").write_text("# Panel\n\nThe panel serves HTTPS only.\n")
        self.git("init", "-q", "-b", "panel")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "prywatna historia")

    def git(self, *args: str) -> str:
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        env.pop("GIT_INDEX_FILE", None)
        return subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True,
                              text=True, check=True, env=env).stdout

    def export(self, *args: str) -> subprocess.CompletedProcess:
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        env.pop("GIT_INDEX_FILE", None)
        return subprocess.run(["bash", str(self.repo / "scripts" / "export-public.sh"), *args],
                              cwd=self.repo, capture_output=True, text=True, env=env)

    def test_the_private_paths_are_left_out(self):
        proc = self.export()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        files = self.git("ls-tree", "-r", "--name-only", "public").split()
        # README.md is the English one now, never the private Polish file.
        self.assertNotIn("dziala", self.git("show", "public:README.md"))
        self.assertFalse([f for f in files if f.startswith("docs/")])
        self.assertIn("NOTES.md", files)
        self.assertIn("backend/app/main.py", files)

    def _readme(self, text: str) -> None:
        (self.repo / "README.en.md").write_text(text)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "readme")

    def test_no_public_readme_stops_the_export(self):
        # Otherwise the repository would go out with no README at all.
        self.git("rm", "-q", "README.en.md")
        self.git("commit", "-q", "-m", "bez readme")
        proc = self.export()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("README.en.md", proc.stderr)

    def test_a_placeholder_account_stops_the_export(self):
        # The install steps would point Imager at a 404.
        self._readme("Paste https://github.com/OWNER/rapi-ids/releases/latest\n")
        proc = self.export()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("OWNER", proc.stderr)

    def test_a_missing_screenshot_stops_the_export(self):
        self._readme("![Dashboard](assets/screenshots/dashboard.png)\n")
        proc = self.export()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("assets/screenshots/dashboard.png", proc.stderr)

    def test_a_screenshot_that_is_there_passes(self):
        (self.repo / "assets" / "screenshots").mkdir(parents=True)
        (self.repo / "assets" / "screenshots" / "dashboard.png").write_bytes(b"\x89PNG")
        self._readme("![Dashboard](assets/screenshots/dashboard.png)\n"
                     "![Badge](https://example.com/badge.svg)\n")
        proc = self.export()
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_the_english_readme_is_published_as_the_readme(self):
        (self.repo / "README.en.md").write_text("The panel serves HTTPS only.\n")
        self.git("add", "README.en.md")
        self.git("commit", "-q", "-m", "angielski")
        proc = self.export()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        files = self.git("ls-tree", "-r", "--name-only", "public").split()
        self.assertIn("README.md", files)
        self.assertNotIn("README.en.md", files)
        self.assertEqual(self.git("show", "public:README.md"), "The panel serves HTTPS only.\n")

    def test_it_is_one_commit_every_time(self):
        self.export()
        (self.repo / "NOTES.md").write_text("The panel serves HTTPS only, on 443.\n")
        self.git("commit", "-q", "-am", "druga zmiana")
        self.export()
        self.assertEqual(self.git("rev-list", "--count", "public").strip(), "1")
        self.assertEqual(self.git("log", "-1", "--format=%P", "public").strip(), "")
        self.assertIn("on 443", self.git("show", "public:NOTES.md"))
        self.assertEqual(self.git("log", "-1", "--format=%s", "public").strip(),
                         "RaPi IDS Panel 0.5.0")

    def test_the_working_copy_and_the_branch_are_untouched(self):
        before = (self.git("status", "--porcelain"), self.git("rev-parse", "HEAD"),
                  self.git("symbolic-ref", "HEAD"))
        self.export()
        after = (self.git("status", "--porcelain"), self.git("rev-parse", "HEAD"),
                 self.git("symbolic-ref", "HEAD"))
        self.assertEqual(before, after)
        self.assertTrue((self.repo / "docs" / "obraz-ids.md").exists())

    def test_a_large_file_is_read_to_the_end_of_its_first_match(self):
        # grep -q stopped at the first match, git show died of SIGPIPE, and
        # under pipefail that read as "no match": every file past the pipe
        # buffer with a Polish word near its top was published.
        big = "To jest polski tekst.\n" + ("a" * 79 + "\n") * 3000   # 240 kB
        (self.repo / "GUIDE.md").write_text(big)
        self.git("add", "GUIDE.md")
        self.git("commit", "-q", "-m", "duzy plik")
        proc = self.export()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("GUIDE.md", proc.stderr)

    def test_the_version_is_the_one_in_the_published_tree(self):
        # An uncommitted bump in the working copy is not in the commit.
        (self.repo / "backend" / "app" / "main.py").write_text('VERSION = "9.9.9"\n')
        self.export()
        self.assertEqual(self.git("log", "-1", "--format=%s", "public").strip(),
                         "RaPi IDS Panel 0.5.0")

    def test_polish_under_another_name_stops_the_export(self):
        (self.repo / "INSTALL.md").write_text("Obraz trzeba zapisac, zeby dzialal.\n")
        self.git("add", "INSTALL.md")
        self.git("commit", "-q", "-m", "wpadka")
        proc = self.export()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("INSTALL.md", proc.stderr)
        self.assertNotIn("public", self.git("branch", "--list", "public"))


class LoginPasswordHelperTest(BackendTestCase):
    """deploy/rapi-login-password: the SSH password follows the panel's, or not.

    The rule the operator asked for: a password that came with the card stays;
    without one, the panel's becomes the SSH password. The case that matters
    most is the third one nobody asked about: on a checkout the account is
    somebody's own login, and the panel must never change it.

    passwd and systemd-run are stubs, so nothing here touches a real account.
    """

    PASSWORD = "correct horse battery"

    def _run(self, *args, marker=None, state="L", stdin=None, unit_user="rapi",
             load_state="loaded"):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        bin_dir = tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "passwd").write_text(f'#!/bin/sh\necho "$2 {state} 2026-09-21"\n')
        (bin_dir / "systemctl").write_text(
            "#!/bin/sh\ncase \"$*\" in\n"
            f'  *"-p User"*) echo "{unit_user}" ;;\n'
            f'  *"-p LoadState"*) echo "{load_state}" ;;\n'
            "esac\n")
        (bin_dir / "systemd-run").write_text(
            "#!/bin/sh\n"
            f'echo "$*" > "{tmp}/argv"\n'
            f'cat > "{tmp}/stdin"\n')
        for f in bin_dir.iterdir():
            f.chmod(0o755)
        state_file = tmp / "rapi-ssh-login"
        if marker is not None:
            state_file.write_text(marker)
        environment = dict(os.environ)
        environment.update({
            "PATH": f"{bin_dir}:{environment['PATH']}",
            "RAPI_LOGIN_STATE": str(state_file),
        })
        environment.pop("RAPI_LOGIN_ACCOUNT", None)
        proc = subprocess.run(
            [str(PROJECT_ROOT / "deploy" / "rapi-login-password"), *args],
            input=stdin, capture_output=True, text=True, timeout=30, env=environment)
        self.tmp = tmp
        return proc

    def changed(self) -> bool:
        return (self.tmp / "stdin").exists()

    def test_the_image_s_locked_account_takes_the_panel_password(self):
        proc = self._run("set", marker="image rapi\n", stdin=self.PASSWORD + "\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((self.tmp / "stdin").read_text(), f"rapi:{self.PASSWORD}\n")
        self.assertEqual((self.tmp / "rapi-ssh-login").read_text(), "panel rapi\n")

    def test_the_password_is_never_an_argument(self):
        self._run("set", marker="image rapi\n", stdin=self.PASSWORD + "\n")
        argv = (self.tmp / "argv").read_text()
        self.assertNotIn(self.PASSWORD, argv)
        self.assertIn("chpasswd", argv)

    def test_the_write_is_handed_out_of_the_panel_sandbox(self):
        # chpasswd run directly inside the panel's unit hits a read-only file
        # system; through systemd-run PID 1 runs it outside. --wait, or the
        # helper reports success before anything was written.
        self._run("set", marker="image rapi\n", stdin=self.PASSWORD + "\n")
        argv = (self.tmp / "argv").read_text().split()
        self.assertIn("--wait", argv)
        self.assertIn("--pipe", argv)

    def test_a_password_that_came_with_the_card_stays(self):
        proc = self._run("set", marker="card pi\n", state="P", stdin=self.PASSWORD + "\n")
        self.assertEqual(proc.returncode, 3)
        self.assertFalse(self.changed())

    def test_a_card_prepared_for_keys_gets_no_password(self):
        proc = self._run("set", marker="key rapi\n", state="L", stdin=self.PASSWORD + "\n")
        self.assertEqual(proc.returncode, 3)
        self.assertFalse(self.changed())
        self.assertEqual((self.tmp / "rapi-ssh-login").read_text(), "key rapi\n")

    def test_somebody_s_own_login_is_never_changed(self):
        # A checkout on a personal Pi: the account has a password and nothing
        # says the panel set it.
        proc = self._run("set", state="P", stdin=self.PASSWORD + "\n")
        self.assertEqual(proc.returncode, 4)
        self.assertFalse(self.changed())
        self.assertFalse((self.tmp / "rapi-ssh-login").exists())

    def test_a_login_locked_for_keys_only_is_never_opened(self):
        # passwd -S says L both for the image's account and for one its owner
        # locked on purpose (cloud-init does it by default), so the account
        # state cannot be what decides. Setting a password here would switch
        # password logins on for somebody who chose keys.
        proc = self._run("set", state="L", stdin=self.PASSWORD + "\n")
        self.assertEqual(proc.returncode, 4)
        self.assertFalse(self.changed())
        self.assertFalse((self.tmp / "rapi-ssh-login").exists())

    def test_a_password_the_panel_set_follows_the_next_change(self):
        proc = self._run("set", marker="panel rapi\n", state="P", stdin=self.PASSWORD + "\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(self.changed())

    def test_a_short_password_is_refused(self):
        proc = self._run("set", marker="image rapi\n", stdin="short\n")
        self.assertEqual(proc.returncode, 2)
        self.assertFalse(self.changed())

    def test_status_names_whose_password_it_is(self):
        for marker, state, source, login in (
            ("card pi\n", "P", "card", "pi"),
            ("key rapi\n", "L", "key", "rapi"),
            ("panel rapi\n", "P", "panel", "rapi"),
            ("image rapi\n", "L", "none", "rapi"),
            (None, "P", "other", "rapi"),
            (None, "L", "other", "rapi"),
        ):
            with self.subTest(source=source):
                proc = self._run("status", marker=marker, state=state)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn(f"source={source}\n", proc.stdout)
                self.assertIn(f"login={login}\n", proc.stdout)

    def test_the_account_is_the_one_the_panel_runs_as(self):
        # A checkout installs the unit with User=$(id -un), so naming rapi here
        # would print a login that does not exist on that machine.
        proc = self._run("status", unit_user="someone")
        self.assertIn("login=someone\n", proc.stdout)

    def test_the_password_goes_to_the_account_the_record_names(self):
        # A device from the image, and later a checkout installed on it as
        # somebody else: the unit now says admin, the record still says rapi.
        # The unit's answer changed admin's own login; with no User= it would
        # have been root's.
        for unit_user, load_state in (("admin", "loaded"), ("", "loaded")):
            with self.subTest(unit=unit_user or "no User="):
                proc = self._run("set", marker="image rapi\n", unit_user=unit_user,
                                 load_state=load_state, stdin=self.PASSWORD + "\n")
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual((self.tmp / "stdin").read_text(), f"rapi:{self.PASSWORD}\n")
                self.assertEqual((self.tmp / "rapi-ssh-login").read_text(), "panel rapi\n")
                self.assertIn("login=rapi\n", proc.stdout)

    def test_a_unit_with_no_user_of_its_own_runs_as_root_and_says_so(self):
        # `sudo scripts/install-service.sh` builds the unit with User=root, and
        # answering "rapi" there names an account that may not exist.
        proc = self._run("status", unit_user="", load_state="loaded")
        self.assertIn("login=root\n", proc.stdout)

    def test_no_unit_at_all_falls_back_to_the_image_account(self):
        # Nothing installed yet, so the image's account is the only answer.
        proc = self._run("status", unit_user="", load_state="not-found")
        self.assertIn("login=rapi\n", proc.stdout)

    def test_the_image_marks_its_own_account(self):
        customize = (PROJECT_ROOT / "image" / "customize.sh").read_text()
        lock = customize.index('passwd --lock "$PANEL_USER"')
        mark = customize.index("printf 'image %s\\n' \"$PANEL_USER\" > \"$ROOTFS/var/lib/rapi-ssh-login\"")
        self.assertGreater(mark, lock)
        # And only the image: a checkout install must not claim the account.
        self.assertNotIn("rapi-ssh-login", (PROJECT_ROOT / "scripts" / "install-service.sh").read_text())

    def test_sudoers_grants_exactly_what_the_panel_calls(self):
        sudoers = (PROJECT_ROOT / "deploy" / "sudoers-rapi-panel").read_text()
        code = (PROJECT_ROOT / "backend" / "app" / "modules" / "system" / "ssh.py").read_text()
        for mode in ("status", "set"):
            with self.subTest(mode=mode):
                self.assertIn(f'"sudo", "-n", HELPER, "{mode}"', code)
                self.assertIn(f"/usr/local/sbin/rapi-login-password {mode}", sudoers)
        self.assertNotIn("rapi-login-password *", sudoers)


class LogDirHelperTest(BackendTestCase):
    """The helper that creates the log directory and sets up its rotation.

    It does both because the panel can do neither: logrotate ignores files not
    owned by root, and a disk mounted at /mnt/ssd belongs to root, so the
    panel's own mkdir fails inside it. Validation runs before anything is
    written, which is why these cases run unprivileged.
    """

    def test_a_path_with_shell_characters_is_refused(self):
        for target in ("/mnt/a b", "/mnt/$(id)", "/mnt/a\nb", "/mnt/a;rm"):
            with self.subTest(target=target):
                result = run_helper("rapi-log-dir", target)
                self.assertEqual(result.returncode, 3, result.stderr)

    def test_dot_dot_is_refused_even_though_the_characters_are_legal(self):
        result = run_helper("rapi-log-dir", "/mnt/ssd/../../etc")
        self.assertEqual(result.returncode, 3)

    def test_the_forbidden_directories_match_the_panel(self):
        for target in ("/etc/logrotate.d", "/home/rapi/logs", "/usr/share"):
            with self.subTest(target=target):
                self.assertEqual(run_helper("rapi-log-dir", target).returncode, 4)

    def test_no_argument_is_a_usage_error(self):
        self.assertEqual(run_helper("rapi-log-dir").returncode, 2)

    def test_a_missing_parent_is_refused_rather_than_conjured(self):
        # Creating a deep tree under nothing would silently put the logs on the
        # boot card at a path that looks like a disk.
        result = run_helper("rapi-log-dir", "/mnt/nothing-here-at-all/deeper/still")
        self.assertEqual(result.returncode, 5, result.stderr)
        self.assertIn("no such directory", result.stderr)

    def test_a_directory_it_cannot_create_says_so_in_a_sentence(self):
        # Unprivileged here, so /mnt is not writable. Without its own exit code
        # this fell through to `set -e` as a bare 1, which the panel cannot turn
        # into anything a person can read.
        result = run_helper("rapi-log-dir", "/mnt/nothing-here-at-all")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("cannot create", result.stderr)


class RulesDateHelperTest(BackendTestCase):
    """The helper that answers "how old is the detection".

    The panel used to answer it from the mtime of the merged rule file, which
    every category switch rewrites. The vendor's own build stamp survives only
    as the mtimes inside the archive suricata-update caches, and that directory
    is root only - hence a helper rather than a read.
    """

    def setUp(self):
        super().setUp()
        self.cache = self.tmp / "cache"
        self.cache.mkdir()

    def _archive(self, name: str, built: datetime, fetched: datetime | None = None,
                 dir_built: datetime | None = None, files: bool = True,
                 stale: datetime | None = None) -> Path:
        """One archive shaped like the vendor's: a directory, then rule files."""
        path = self.cache / name
        with tarfile.open(path, "w:gz") as tar:
            entry = tarfile.TarInfo("rules/")
            entry.type = tarfile.DIRTYPE
            entry.mtime = int((dir_built or built).timestamp())
            tar.addfile(entry)
            if files:
                stamps = [stale] if stale else []
                stamps.append(built)
                for index, stamp in enumerate(stamps):
                    member = tarfile.TarInfo(f"rules/emerging-{index}.rules")
                    member.size = 3
                    member.mtime = int(stamp.timestamp())
                    tar.addfile(member, io.BytesIO(b"x\n\n"))
        if fetched is not None:
            stamp = fetched.timestamp()
            os.utime(path, (stamp, stamp))
        return path

    def _run(self):
        return run_helper("rapi-rules-date", env={"RAPI_RULES_CACHE": str(self.cache)})

    def _dates(self, result) -> dict[str, float]:
        self.assertEqual(result.returncode, 0, result.stderr)
        return {line.split()[0]: float(line.split()[1])
                for line in result.stdout.splitlines()}

    def test_it_reads_the_vendor_stamp_out_of_the_archive(self):
        built = datetime(2026, 9, 2, 22, 45)
        self._archive("a-emerging.rules.tar.gz", built)
        self.assertEqual(self._dates(self._run())["built"], built.timestamp())

    def test_the_download_time_is_reported_separately(self):
        """The two answer different questions and used to be the same number.

        Built says how old the detection is; downloaded says whether this device
        is keeping up. A set built yesterday and last fetched in June is a
        working timer that has silently stopped.
        """
        built = datetime(2026, 9, 2, 22, 45)
        fetched = datetime(2026, 9, 3, 3, 31)
        self._archive("a-emerging.rules.tar.gz", built, fetched=fetched)
        dates = self._dates(self._run())
        self.assertEqual(dates["built"], built.timestamp())
        self.assertEqual(dates["fetched"], fetched.timestamp())

    def test_the_directory_entry_is_not_the_vendor_stamp(self):
        # The leading entry carries whatever the packer's own filesystem had.
        # Newer than the rules here, so counting it in is a date from the future
        # rather than a near miss that a reader would never notice.
        built = datetime(2026, 9, 2, 22, 45)
        self._archive("a-emerging.rules.tar.gz", built,
                      dir_built=datetime(2027, 1, 1, 0, 0))
        self.assertEqual(self._dates(self._run())["built"], built.timestamp())

    def test_a_file_left_over_from_an_older_build_does_not_win(self):
        # Every entry in the vendor's archive carries the same stamp today. If
        # one ever does not, the age of the set is the newest of them, not
        # whichever happens to be packed first.
        built = datetime(2026, 9, 2, 22, 45)
        self._archive("a-emerging.rules.tar.gz", built,
                      stale=datetime(2024, 3, 3, 9, 0))
        self.assertEqual(self._dates(self._run())["built"], built.timestamp())

    def test_the_newest_archive_wins(self):
        """suricata-update keys the file name by a hash of the source URL.

        The URL carries the engine version, so an engine upgrade leaves the
        previous engine's archive sitting in the cache next to the current one.
        Sorted by name, the stale one wins about half the time.
        """
        old = datetime(2026, 6, 1, 10, 0)
        new = datetime(2026, 9, 2, 22, 45)
        self._archive("zzz-emerging.rules.tar.gz", old,
                      fetched=datetime(2026, 6, 1, 11, 0))
        self._archive("aaa-emerging.rules.tar.gz", new,
                      fetched=datetime(2026, 9, 3, 3, 31))
        self.assertEqual(self._dates(self._run())["built"], new.timestamp())

    def test_a_cache_that_is_not_there_is_a_sentence_not_a_traceback(self):
        result = run_helper("rapi-rules-date",
                            env={"RAPI_RULES_CACHE": str(self.tmp / "nothing")})
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("no signature cache", result.stderr)

    def test_a_cache_with_no_archive_says_so(self):
        # A device that has never downloaded rules. The screen has to say
        # "unknown" rather than show the rebuild date as if it were the age.
        result = self._run()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn("no signature archive", result.stderr)

    def test_an_archive_with_no_dated_file_says_so(self):
        self._archive("a-emerging.rules.tar.gz", datetime(2026, 9, 2, 22, 45),
                      files=False)
        result = self._run()
        self.assertEqual(result.returncode, 5, result.stderr)
        self.assertIn("no dated entry", result.stderr)

    def test_an_archive_of_many_files_does_not_break_the_pipe(self):
        """Stopping at the first match closes the pipe under tar, and pipefail
        then reports the vendor's own archive as our failure. It needs a listing
        longer than a pipe buffer to show, so it would not have shown here."""
        path = self.cache / "big-emerging.rules.tar.gz"
        built = datetime(2026, 9, 2, 22, 45)
        with tarfile.open(path, "w:gz") as tar:
            for index in range(4000):
                member = tarfile.TarInfo(f"rules/emerging-{index:04d}.rules")
                member.size = 3
                member.mtime = int(built.timestamp())
                tar.addfile(member, io.BytesIO(b"x\n\n"))
        self.assertEqual(self._dates(self._run())["built"], built.timestamp())


class CaptureIfaceHelperTest(BackendTestCase):
    """The helper that turns an ordinary port into a capture interface.

    Everything it does at runtime - the link up, promiscuous mode, the offloads
    off - lives in the kernel and is gone after a reboot, and the file it writes
    to stop NetworkManager touching the interface is also what stops anything
    bringing it back up. So the half that has to survive, the unit, is what most
    of this exercises: the machine comes from a fixture tree and the commands
    the script would run are stubs that record their arguments.
    """

    def setUp(self):
        super().setUp()
        self.sys_net = self.tmp / "class-net"
        (self.sys_net / "eth0").mkdir(parents=True)
        self.nm = self.tmp / "nm-conf"
        self.units = self.tmp / "systemd"
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.log = self.tmp / "commands.log"
        for command in ("ip", "ethtool", "nmcli", "systemctl"):
            stub = self.bin / command
            stub.write_text(f'#!/bin/sh\necho "{command} $*" >> "{self.log}"\nexit 0\n')
            stub.chmod(0o755)

    def _run(self, *args):
        return run_helper(
            "rapi-capture-iface", *args,
            env={
                "RAPI_SYS_NET": str(self.sys_net),
                "RAPI_NM_CONF_DIR": str(self.nm),
                "RAPI_SYSTEMD_DIR": str(self.units),
            },
            path_prefix=self.bin,
        )

    def commands(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def unit(self) -> str:
        return (self.units / "rapi-capture-link@.service").read_text()

    def test_an_interface_name_that_is_not_one_is_refused(self):
        for name in ("eth0;id", "../../etc/passwd", "a" * 20, ""):
            with self.subTest(name=name):
                self.assertEqual(run_helper("rapi-capture-iface", name, "capture").returncode, 1)

    def test_an_interface_that_does_not_exist_is_refused(self):
        result = run_helper("rapi-capture-iface", "eth42", "capture")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no such interface", result.stderr)

    def test_the_mode_is_one_of_the_three_words(self):
        result = self._run("eth0", "delete-everything")
        self.assertEqual(result.returncode, 1)
        self.assertIn("unknown mode", result.stderr)

    def test_networkmanager_is_told_to_leave_the_interface_alone(self):
        self.assertEqual(self._run("eth0", "capture").returncode, 0)
        conf = (self.nm / "99-rapi-capture-eth0.conf").read_text()
        self.assertIn("interface-name:eth0", conf)
        self.assertIn("managed=0", conf)

    def test_capture_installs_the_unit_that_puts_it_back_after_a_reboot(self):
        # The bug this exists for: the interface came up once, when somebody
        # clicked through the wizard, and never again. A day of that is a day
        # with no detection and a service reporting itself as running.
        self.assertEqual(self._run("eth0", "capture").returncode, 0)
        self.assertIn("ExecStart=/usr/local/sbin/rapi-capture-iface %i boot", self.unit())
        self.assertIn("systemctl enable rapi-capture-link@eth0.service", self.commands())

    def test_the_unit_is_ordered_before_the_engine(self):
        # Suricata reads its capture interface when it opens the socket. Coming
        # up after it works, but only because af-packet recovers on its own.
        self._run("eth0", "capture")
        self.assertIn("Before=suricata.service", self.unit())

    def test_the_unit_follows_the_device_rather_than_the_clock(self):
        # A USB adapter appears seconds or hours after boot. Bound to the device
        # unit, it gets the same preparation either way.
        self._run("eth0", "capture")
        unit = self.unit()
        self.assertIn("BindsTo=sys-subsystem-net-devices-%i.device", unit)
        self.assertIn("WantedBy=sys-subsystem-net-devices-%i.device", unit)

    # --- which card, not which name ----------------------------------------
    #
    # Everything below exists because interface names on this device are not
    # stable and are not unique over time. Raspberry Pi OS points both files in
    # /etc/systemd/network at /dev/null, so there is no naming policy at all and
    # a USB adapter is eth1 or eth2 depending on probe order. The onboard
    # controller never moves; the adapter is the one people unplug, and it is
    # also the one worth using as the mirror port.

    def _card(self, name: str, mac: str) -> None:
        """An interface in the fixture tree that has a hardware address."""
        (self.sys_net / name).mkdir(parents=True, exist_ok=True)
        (self.sys_net / name / "address").write_text(f"{mac}\n")

    def test_the_rule_names_the_card_when_the_kernel_offers_one(self):
        self._card("eth1", "00:00:5e:00:53:04")
        self.assertEqual(self._run("eth1", "capture").returncode, 0)
        conf = (self.nm / "99-rapi-capture-eth1.conf").read_text()
        self.assertIn("match-device=mac:00:00:5e:00:53:04", conf)
        # Both together would be an OR, and the wrong half could win: after a
        # rename the name matches a different card, and unmanaging a management
        # link on a headless sensor is worse than anything it would prevent.
        self.assertNotIn("interface-name", conf)

    def test_a_card_with_no_address_still_gets_a_rule(self):
        # Nothing in the fixture tree has one, which is how the older test above
        # passes unchanged. A rule on the name is weaker than a rule on the card
        # but far better than no rule, which is DHCP on the mirror port.
        self.assertEqual(self._run("eth0", "capture").returncode, 0)
        conf = (self.nm / "99-rapi-capture-eth0.conf").read_text()
        self.assertIn("match-device=interface-name:eth0", conf)

    def test_boot_leaves_alone_an_interface_that_was_never_set_up(self):
        # `prepare_link` flushes addresses, so the question boot has to answer
        # first is whether this interface is a capture interface at all.
        result = self._run("eth0", "boot")
        self.assertEqual(result.returncode, 1)
        self.assertIn("not a capture interface", result.stderr)
        self.assertNotIn("addr flush", self.commands())

    def test_boot_refuses_a_different_card_wearing_the_same_name(self):
        # The one that would hurt: eth1 was the adapter, it was unplugged, and
        # another card took the name. The enabled rapi-capture-link@eth1 still
        # fires, and without this check it strips the address off a working link
        # and puts it in promiscuous mode.
        self._card("eth1", "00:00:5e:00:53:04")
        self._run("eth1", "capture")
        self.log.unlink()
        self._card("eth1", "aa:bb:cc:dd:ee:ff")
        result = self._run("eth1", "boot")
        self.assertEqual(result.returncode, 1)
        self.assertIn("not the card", result.stderr)
        self.assertNotIn("addr flush", self.commands())

    def test_boot_prepares_the_card_it_was_set_up_for(self):
        # The negative tests above pass on a script that refuses everything.
        self._card("eth1", "00:00:5e:00:53:04")
        self._run("eth1", "capture")
        self.log.unlink()
        self.assertEqual(self._run("eth1", "boot").returncode, 0)
        commands = self.commands()
        self.assertIn("ip addr flush dev eth1", commands)
        self.assertIn("ip link set eth1 promisc on", commands)

    def test_restore_lets_go_of_a_rule_written_under_an_older_name(self):
        # Handing the port back has to undo the rule that is actually holding
        # it, not the one named after today. Left behind, it keeps the card
        # unmanaged for good: no address, and nothing that would bring it up.
        self._card("eth1", "00:00:5e:00:53:04")
        self._run("eth1", "capture")
        (self.sys_net / "eth1").rename(self.sys_net / "eth2")
        self.assertEqual(self._run("eth2", "restore").returncode, 0)
        self.assertEqual(sorted(q.name for q in self.nm.glob("*.conf")), [])

    def test_boot_mode_does_the_part_the_kernel_forgets(self):
        # Through `capture` first, because that is the only way an interface
        # ever reaches `boot`: the unit is enabled by the same call that writes
        # the rule, and boot refuses an interface with no rule.
        self._run("eth0", "capture")
        self.log.unlink()
        self.assertEqual(self._run("eth0", "boot").returncode, 0)
        log = self.commands()
        self.assertIn("ip link set eth0 up", log)
        self.assertIn("ip link set eth0 promisc on", log)
        # An offload that merges segments makes the engine measure sizes the
        # network never carried, and `ethtool -K` is not written down anywhere.
        self.assertIn("ethtool -K eth0 gro off", log)

    def test_boot_mode_touches_neither_systemd_nor_networkmanager(self):
        # It runs from inside a unit systemd is in the middle of starting.
        # Reloading NetworkManager or enabling units from there can hang a boot,
        # and neither would change anything that is not already on disk.
        self._run("eth0", "boot")
        log = self.commands()
        self.assertNotIn("systemctl", log)
        self.assertNotIn("nmcli", log)
        self.assertFalse(self.units.exists())

    def test_restore_finishes_for_an_ordinary_card(self):
        """A card with a MAC, captured once, handed back once.

        The ordinary case, and the one no test covered. The others restored a
        card with no MAC, which skips the search by address, or a card with a
        stale second file, which gives the search something to find. With the
        card's own file already removed, the search found nothing, pipefail
        turned that into a failure, and set -e ended the script before
        NetworkManager was reloaded or the port handed back. Silently: no
        output, no error, a port left half way. Booting the image found it.
        """
        self._card("eth1", "00:00:5e:00:53:04")
        self._run("eth1", "capture")
        self.log.unlink()
        proc = self._run("eth1", "restore")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        commands = self.commands()
        self.assertIn("nmcli device set eth1 managed yes", commands)
        self.assertIn("systemctl reload NetworkManager", commands)
        self.assertIn("ip link set eth1 promisc off", commands)
        self.assertIn("handed back", proc.stdout)

    def test_restore_stops_the_unit_coming_back(self):
        self._run("eth0", "capture")
        self.log.unlink()
        self.assertEqual(self._run("eth0", "restore").returncode, 0)
        self.assertIn("systemctl disable rapi-capture-link@eth0.service", self.commands())
        self.assertFalse((self.nm / "99-rapi-capture-eth0.conf").exists())

    def test_restore_leaves_the_template_for_the_other_interface(self):
        # One template, any number of instances: the inline bridge prepares two
        # interfaces, and taking one back must not disarm the other.
        self._run("eth0", "capture")
        self._run("eth0", "restore")
        self.assertTrue((self.units / "rapi-capture-link@.service").exists())


class CaptureApplyHelperTest(BackendTestCase):
    """The script that writes the capture configuration, run for real.

    Every path it touches comes from an environment variable and the only
    command it calls is the engine's own configuration test, so a stub engine on
    PATH is enough to run the whole thing as an ordinary user.
    """

    # What `suricata --dump-config` prints for the variables. The helper reads
    # them back out of the engine rather than parsing YAML, so this is the
    # surface the test has to imitate.
    DUMPED = [
        "vars = (null)",
        "vars.address-groups = (null)",
        'vars.address-groups.HOME_NET = [192.168.0.0/16]',
        "vars.address-groups.EXTERNAL_NET = !$HOME_NET",
        "vars.address-groups.HTTP_SERVERS = $HOME_NET",
        "vars.port-groups = (null)",
        "vars.port-groups.HTTP_PORTS = 80",
        "vars.port-groups.SHELLCODE_PORTS = !80",
    ]

    def setUp(self):
        super().setUp()
        self.yaml = self.tmp / "suricata.yaml"
        self.capture_yaml = self.tmp / "rapi-capture.yaml"
        self.vars_yaml = self.tmp / "rapi-home-net.yaml"
        self.home_net_state = self.tmp / "rapi-home-net"
        self.yaml.write_text(
            "%YAML 1.1\n---\nvars:\n  address-groups:\n"
            "    HOME_NET: \"[192.168.0.0/16]\"\n"
            "    EXTERNAL_NET: \"!$HOME_NET\"\n"
            "af-packet:\n  - interface: eth0\n"
        )
        self.stub_bin = self.tmp / "bin"
        self.stub_bin.mkdir()
        self._stub_engine(0)
        self.iface = _an_interface()

    def _stub_engine(self, exit_code: int, dumped: list[str] | None = None) -> None:
        lines = self.DUMPED if dumped is None else dumped
        engine = self.stub_bin / "suricata"
        engine.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            "  --dump-config) cat <<'DUMP'\n"
            + "\n".join(lines) + "\n"
            "DUMP\n"
            "  exit 0 ;;\n"
            "esac\n"
            f"echo 'configuration test'\nexit {exit_code}\n"
        )
        engine.chmod(0o755)

    def _apply(self, iface=None, home_net="[192.168.1.0/24]", peer=None):
        args = [iface or self.iface, home_net] + ([peer] if peer else [])
        return run_helper(
            "rapi-capture-apply", *args,
            env={
                "RAPI_SURICATA_YAML": str(self.yaml),
                "RAPI_SURICATA_CAPTURE": str(self.capture_yaml),
                "RAPI_SURICATA_VARS": str(self.vars_yaml),
                "RAPI_HOME_NET_STATE": str(self.home_net_state),
                "RAPI_SURICATA_CONF_DIR": str(self.tmp),
                "RAPI_INCLUDE_BIN": str(DEPLOY / "rapi-include"),
            },
            path_prefix=self.stub_bin,
        )

    def test_only_the_panel_s_own_bridge_may_be_missing(self):
        # The exemption is for the bridge rapi-inline builds after this check.
        # Any other missing name is still a mistake to refuse.
        for name in ("br-other", "eth99"):
            with self.subTest(name=name):
                proc = self._apply(iface=name)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("no such interface", proc.stderr)

    def test_a_pair_is_written_as_the_engine_forwarding_between_them(self):
        """The inline blocking mode, which is the only thing here that drops.

        Not a kernel bridge: the engine reads from each interface and writes to
        the other, so a packet a rule drops is simply never written. Suricata's
        own name for it is copy-mode ips with a paired copy-iface.
        """
        names = sorted(os.listdir("/sys/class/net"))
        if len(names) < 2:
            self.skipTest("needs two interfaces on this machine")
        first, second = names[0], names[1]
        proc = self._apply(iface=first, peer=second)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        written = self.capture_yaml.read_text()

        self.assertIn(f"- interface: {first}", written)
        self.assertIn(f"- interface: {second}", written)
        self.assertEqual(written.count("copy-mode: ips"), 2)
        self.assertIn(f"copy-iface: {second}", written)
        self.assertIn(f"copy-iface: {first}", written)

    def test_the_pair_does_not_defragment(self):
        # A datagram reassembled here cannot be forwarded as the fragments that
        # arrived. The engine's own documentation says to turn it off inline.
        names = sorted(os.listdir("/sys/class/net"))
        if len(names) < 2:
            self.skipTest("needs two interfaces on this machine")
        self._apply(iface=names[0], peer=names[1])
        written = self.capture_yaml.read_text()
        inline = written.split("- interface: default")[0]
        self.assertEqual(inline.count("defrag: no"), 2)
        self.assertNotIn("defrag: yes", inline)

    def test_the_two_sides_do_not_share_a_cluster(self):
        # One id across both interfaces puts the two directions of the same link
        # into a single load balancing group.
        names = sorted(os.listdir("/sys/class/net"))
        if len(names) < 2:
            self.skipTest("needs two interfaces on this machine")
        self._apply(iface=names[0], peer=names[1])
        ids = re.findall(r"cluster-id: (\d+)", self.capture_yaml.read_text())
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2)

    def test_a_pair_of_the_same_interface_is_refused(self):
        # The engine would forward every packet straight back out of the port it
        # came from.
        proc = self._apply(iface=self.iface, peer=self.iface)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("have to differ", proc.stderr)

    def test_a_peer_that_is_not_there_is_refused(self):
        proc = self._apply(peer="eth99")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("no such interface", proc.stderr)

    def test_without_a_peer_nothing_about_the_pair_is_written(self):
        # The passive layout is the common one and must not gain an inline
        # setting by accident.
        self._apply()
        written = self.capture_yaml.read_text()
        self.assertNotIn("copy-mode", written)
        self.assertNotIn("copy-iface", written)

    def test_the_generated_block_carries_the_packaged_settings_and_nothing_else(self):
        # use-mmap and tpacket-v3 are not in the packaged configuration. Added
        # here once, they broke the engine's automatic checksum detection and it
        # logged an invalid checksum alert for nearly every packet the Pi sent:
        # 2814 of them in four minutes.
        self.assertEqual(self._apply().returncode, 0)
        written = self.capture_yaml.read_text()
        self.assertNotIn("use-mmap", written)
        self.assertNotIn("tpacket-v3", written)
        self.assertIn("promisc: yes", written)
        self.assertIn(f"- interface: {self.iface}", written)

    def test_the_ring_is_deep_enough_for_a_burst(self):
        # The default ring is max-pending-packets over the thread count, about
        # 256 packets on a four core board: three milliseconds of gigabit. A
        # mirror hands over bursts at line rate whatever the average rate is,
        # and this device was losing 13 % of packets while averaging 40 per
        # second. Dropped packets are never inspected, so the alerts in them
        # never happen.
        self._apply()
        self.assertIn("ring-size: 8192", self.capture_yaml.read_text())

    def test_the_vlan_id_stays_out_of_the_flow_key(self):
        # The engine hashes the VLAN id into the flow key by default. A mirror
        # port that carries a trunk on one side and an access port on the other
        # hands over one direction tagged and the other untagged, so with this
        # on, every conversation arrives as two unidirectional halves.
        #
        # Nothing reports that. What it costs is the whole TCP side of
        # detection: no handshake completes in the engine's view, so no stream
        # is tracked and no app-layer parser ever starts. Measured on this
        # device over twelve hours: 12179 TCP flows, one of them bidirectional,
        # zero tls and zero http transactions, and every rule matching on what
        # a server sends back was dead. The only visible symptom was a trickle
        # of STREAM "invalid ack" alerts, which reads as a network fault.
        self._apply()
        written = self.capture_yaml.read_text()
        self.assertIn("vlan:", written)
        self.assertRegex(written, r"vlan:\s*\n\s*use-for-tracking:\s*(no|false)\b")

    def test_the_default_entry_survives(self):
        # An include replaces the whole key, so the entry the engine falls back
        # on for interfaces it was given no settings for has to be written too.
        self._apply()
        self.assertIn("- interface: default", self.capture_yaml.read_text())

    def test_the_include_is_added_once(self):
        self._apply()
        self._apply()
        text = self.yaml.read_text()
        self.assertEqual(text.count(f"  - {self.capture_yaml}"), 1)

    def test_home_net_goes_in_a_file_of_our_own(self):
        self._apply(home_net="[10.10.0.0/16]")
        written = self.vars_yaml.read_text()
        self.assertIn('HOME_NET: "[10.10.0.0/16]"', written)
        self.assertEqual(self.home_net_state.read_text().strip(), "[10.10.0.0/16]")

    def test_the_packaged_file_is_no_longer_edited_in_place(self):
        # The only line this adds to suricata.yaml is an include. Everything
        # with our name on it lives in files we own outright, so a rollback is
        # deleting a file rather than restoring somebody else's.
        before = self.yaml.read_text()
        self._apply(home_net="[10.10.0.0/16]")
        after = self.yaml.read_text()
        self.assertIn('HOME_NET: "[192.168.0.0/16]"', after)   # untouched
        added = after[len(before):]
        for line in added.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            self.assertTrue(line == "include:" or line.startswith("  - "), line)

    def test_the_whole_vars_key_is_written_not_just_home_net(self):
        # An include replaces a whole top-level key. Writing only HOME_NET took
        # EXTERNAL_NET, HTTP_SERVERS and every port group down with it, which is
        # measurable rather than theoretical:
        #   vars.address-groups.HOME_NET = [10.9.9.0/24]   <- and nothing else
        self._apply()
        written = self.vars_yaml.read_text()
        self.assertIn('EXTERNAL_NET: "!$HOME_NET"', written)
        self.assertIn('HTTP_SERVERS: "$HOME_NET"', written)
        self.assertIn("  port-groups:", written)
        self.assertIn('HTTP_PORTS: "80"', written)
        self.assertIn('SHELLCODE_PORTS: "!80"', written)

    def test_the_variables_survive_being_read_back_out_of_our_own_file(self):
        """Three changes of HOME_NET, and the references still refer.

        The worry, raised in review, is that this bakes values in: read the
        variables out of the running configuration, write them back, and any
        "$HOME_NET" becomes whatever it pointed at, so the second change leaves
        EXTERNAL_NET stuck on the previous network while HOME_NET moves on.

        It does not happen, and the reason is that `suricata --dump-config`
        prints the configuration tree rather than resolved address groups: it
        answers "EXTERNAL_NET = !$HOME_NET", not a resolved address list. Checked
        against the running engine as well as here. The test matters anyway,
        because the fixed stub above never reads back what a previous run wrote,
        which is exactly the path the worry is about.
        """
        for net in ("[10.0.0.0/8]", "[172.16.0.0/12]", "[10.9.9.0/24]"):
            with self.subTest(home_net=net):
                self.assertEqual(self._apply(home_net=net).returncode, 0)
                written = self.vars_yaml.read_text()
                self.assertIn(f'HOME_NET: "{net}"', written)
                self.assertIn('EXTERNAL_NET: "!$HOME_NET"', written)
                self.assertIn('HTTP_SERVERS: "$HOME_NET"', written)
                # The engine on the next run reads the file we just wrote, so
                # that is what the stub has to report back.
                self._stub_engine(0, self._dump_of(written))

    @staticmethod
    def _dump_of(vars_yaml: str) -> list[str]:
        """The generated file, flattened the way --dump-config prints it."""
        lines, group = [], None
        for raw in vars_yaml.splitlines():
            stripped = raw.strip()
            if stripped in ("address-groups:", "port-groups:"):
                group = stripped.rstrip(":")
                lines.append(f"vars.{group} = (null)")
            elif group and ": " in stripped and not stripped.startswith("#"):
                name, value = stripped.split(": ", 1)
                lines.append(f"vars.{group}.{name} = {value.strip(chr(34))}")
        return lines

    def test_the_group_headers_without_a_variable_are_not_variables(self):
        # `suricata --dump-config` prints "vars.address-groups = (null)" for the
        # group itself. Written out as a variable it would be a key with an
        # empty name, and the engine would refuse the whole file.
        self._apply()
        for line in self.vars_yaml.read_text().splitlines():
            self.assertNotIn(': ""', line)
            self.assertFalse(line.strip().startswith(': '), line)

    def test_applying_twice_gives_the_same_variables(self):
        # The second run reads back what the first one wrote, through the same
        # --dump-config. If that did not round-trip, every reapply would lose
        # variables until only HOME_NET was left.
        self._apply(home_net="[10.10.0.0/16]")
        first = self.vars_yaml.read_text()
        self._apply(home_net="[10.10.0.0/16]")
        self.assertEqual(
            [ln for ln in first.splitlines() if not ln.startswith("#")],
            [ln for ln in self.vars_yaml.read_text().splitlines() if not ln.startswith("#")],
        )

    def test_the_include_is_added_once_per_file(self):
        self._apply()
        self._apply()
        text = self.yaml.read_text()
        self.assertEqual(text.count(f"  - {self.vars_yaml}"), 1)

    def test_a_configuration_the_engine_refuses_is_rolled_back(self):
        before = self.yaml.read_text()
        self._stub_engine(1)
        result = self._apply()
        self.assertEqual(result.returncode, 1)
        self.assertIn("rolled back", result.stderr)
        self.assertEqual(self.yaml.read_text(), before)
        self.assertFalse(self.capture_yaml.exists())
        self.assertFalse(self.vars_yaml.exists())

    def test_an_engine_that_reports_no_variables_changes_nothing(self):
        # Reading them back is the whole mechanism. If that fails, writing the
        # key anyway would replace every variable with one.
        before = self.yaml.read_text()
        self._stub_engine(0, dumped=["vars = (null)"])
        result = self._apply()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.yaml.read_text(), before)
        self.assertFalse(self.vars_yaml.exists())

    def test_a_variable_with_a_quote_in_it_is_refused(self):
        # It is written into a quoted scalar, so a quote would end it early and
        # whatever followed would be read as configuration.
        before = self.yaml.read_text()
        self._stub_engine(0, dumped=[
            'vars.address-groups.HOME_NET = [10.0.0.0/8]',
            'vars.address-groups.EVIL = "\nrun-as: {user: root}',
        ])
        result = self._apply()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.yaml.read_text(), before)

    def test_an_interface_name_that_is_not_one_is_refused(self):
        for name in ("eth0 -o", "../../etc", "eth0;id", "a" * 20):
            with self.subTest(name=name):
                result = self._apply(iface=name)
                self.assertEqual(result.returncode, 1)
                self.assertFalse(self.capture_yaml.exists())

    def test_a_home_net_that_could_end_the_quoted_value_is_refused(self):
        # This string is written into suricata.yaml, so nothing that could close
        # the scalar or start a new key may pass.
        for value in ('[192.168.1.0/24]"\nrun-as: {user: root}', "[192.168.1.0/24] #x",
                      "192.168.1.0/24", "[$(id)]"):
            with self.subTest(value=value):
                self.assertEqual(self._apply(home_net=value).returncode, 1)

    def test_the_number_of_arguments_is_fixed(self):
        result = run_helper("rapi-capture-apply", self.iface)
        self.assertEqual(result.returncode, 1)
        self.assertIn("usage", result.stderr)

    def test_a_rejected_configuration_leaves_the_working_one_in_place(self):
        """Rolling back means going back, not going empty.

        The rollback used to restore suricata.yaml and delete the two generated
        files. That is right exactly once - the first time this ever runs. On
        every later run those files hold a working configuration, the restored
        suricata.yaml still includes them by name, and deleting them leaves an
        engine that cannot start at all. A capture change the engine merely
        declined would take detection down with it, at the moment somebody was
        reconfiguring the sensor and least likely to notice.
        """
        self.assertEqual(self._apply(home_net="[10.0.0.0/8]").returncode, 0)
        good_capture = self.capture_yaml.read_text()
        good_vars = self.vars_yaml.read_text()
        good_yaml = self.yaml.read_text()

        self._stub_engine(1)
        result = self._apply(home_net="[172.16.0.0/12]")

        self.assertEqual(result.returncode, 1)
        self.assertTrue(self.capture_yaml.exists(), "the working capture file was deleted")
        self.assertTrue(self.vars_yaml.exists(), "the working variables file was deleted")
        self.assertEqual(self.capture_yaml.read_text(), good_capture)
        self.assertEqual(self.vars_yaml.read_text(), good_vars)
        self.assertEqual(self.yaml.read_text(), good_yaml)
        self.assertIn("10.0.0.0/8", self.vars_yaml.read_text())

    def test_a_rejected_first_run_leaves_nothing_behind(self):
        # The other half of the same rule: there was nothing there before, so
        # putting back "nothing" is the correct restore.
        self._stub_engine(1)
        self.assertEqual(self._apply().returncode, 1)
        self.assertFalse(self.capture_yaml.exists())
        self.assertFalse(self.vars_yaml.exists())

    def test_no_backup_or_half_written_file_survives_a_good_run(self):
        self.assertEqual(self._apply().returncode, 0)
        leftovers = [f.name for f in self.tmp.iterdir()
                     if f.name.endswith((".rapi-bak", ".new"))]
        self.assertEqual(leftovers, [])


class IncludeHelperTest(BackendTestCase):
    """One array of includes instead of several lines saying the same thing.

    The engine has an opinion about the old way and states it on every start:

        Multipline "include" fields at the same level are deprecated and will
        not work in Suricata 8, please move to an array of include files

    Said by Suricata 8, about Suricata 8, while doing it anyway. It is a
    warning today and a promise about tomorrow, and there are four generated
    files here now.
    """

    PACKAGED = "%YAML 1.1\n---\nvars:\n  address-groups:\n    HOME_NET: \"any\"\n"

    def setUp(self):
        super().setUp()
        self.yaml = self.tmp / "suricata.yaml"
        self.yaml.write_text(self.PACKAGED)
        self.conf = self.tmp / "conf"
        self.conf.mkdir()
        for name in ("rapi-capture.yaml", "rapi-overrides.yaml"):
            (self.conf / name).write_text("%YAML 1.1\n---\n")

    def _run(self):
        return run_helper("rapi-include", env={
            "RAPI_SURICATA_YAML": str(self.yaml),
            "RAPI_SURICATA_CONF_DIR": str(self.conf),
        })

    def test_every_generated_file_ends_up_in_one_array(self):
        self.assertEqual(self._run().returncode, 0)
        text = self.yaml.read_text()
        self.assertEqual(text.count("include:"), 1)
        self.assertIn(f"  - {self.conf / 'rapi-capture.yaml'}", text)
        self.assertIn(f"  - {self.conf / 'rapi-overrides.yaml'}", text)

    def test_the_old_single_lines_are_replaced_not_added_to(self):
        # Devices set up before this helper existed carry the old form. Leaving
        # it would mean both spellings in one file, which is the deprecated
        # thing plus an array.
        self.yaml.write_text(
            self.PACKAGED
            + "\n# --- RaPi IDS Panel: overrides from the panel (must stay last) ---\n"
            + f"include: {self.conf / 'rapi-overrides.yaml'}\n"
            + "\n# --- RaPi IDS Panel: capture interface (must stay last) ---\n"
            + f"include: {self.conf / 'rapi-capture.yaml'}\n"
        )
        self._run()
        text = self.yaml.read_text()
        self.assertEqual(text.count("include:"), 1)
        self.assertNotIn(f"include: {self.conf / 'rapi-capture.yaml'}", text)
        self.assertIn(f"  - {self.conf / 'rapi-capture.yaml'}", text)

    def test_the_packaged_configuration_is_left_alone(self):
        self._run()
        self.assertIn('HOME_NET: "any"', self.yaml.read_text())

    def test_an_include_of_somebody_elses_file_is_not_touched(self):
        # Only files matching our own name pattern in our own directory are
        # ours to move. Anything else in that file belongs to the package or to
        # whoever set this machine up.
        other = self.tmp / "site.yaml"
        self.yaml.write_text(self.PACKAGED + f"\ninclude: {other}\n")
        self._run()
        self.assertIn(f"include: {other}", self.yaml.read_text())

    def test_running_it_again_changes_nothing(self):
        self._run()
        first = self.yaml.read_text()
        self._run()
        self.assertEqual(self.yaml.read_text(), first)

    def test_a_file_that_is_gone_stops_being_included(self):
        # What a rollback leaves behind. The list is rebuilt from what exists,
        # so nobody has to remember to edit it - and an include of a missing
        # file stops the engine dead.
        self._run()
        (self.conf / "rapi-capture.yaml").unlink()
        self._run()
        text = self.yaml.read_text()
        self.assertNotIn("rapi-capture.yaml", text)
        self.assertIn("rapi-overrides.yaml", text)

    def test_the_block_stays_at_the_end(self):
        # A later include wins over the packaged value it replaces, so this is
        # not tidiness: in front of the packaged keys it would do nothing.
        self._run()
        lines = [ln for ln in self.yaml.read_text().splitlines() if ln.strip()]
        self.assertTrue(lines[-1].strip().startswith("- "), lines[-3:])

    def test_nothing_to_include_is_refused_rather_than_written_empty(self):
        for name in ("rapi-capture.yaml", "rapi-overrides.yaml"):
            (self.conf / name).unlink()
        before = self.yaml.read_text()
        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.yaml.read_text(), before)


class OutputsHelperTest(BackendTestCase):
    """What the engine writes to disk.

    Measured on this device: eve.json 107 MB and stats.log 50 MB in the same
    fourteen hours, plus fast.log carrying every alert a second time in a format
    nothing here reads. A third of everything written was counters nobody has
    ever opened, on a machine whose whole point is to sit on an SD card for
    years.
    """

    PACKAGED = """%YAML 1.1
---
outputs:
  - fast:
      enabled: yes
      filename: fast.log
  - eve-log:
      enabled: yes
      filename: eve.json
      types:
        - alert:
            payload: no
        - flow
        - stats:
            totals: yes
  - tls-store:
      enabled: no
  - stats:
      enabled: yes
      filename: stats.log

logging:
  default-log-level: notice
"""

    def setUp(self):
        super().setUp()
        self.yaml = self.tmp / "suricata.yaml"
        self.yaml.write_text(self.PACKAGED)
        self.outputs = self.tmp / "rapi-outputs.yaml"
        self.stub_bin = self.tmp / "bin"
        self.stub_bin.mkdir()
        self._stub_engine(0)

    def _stub_engine(self, exit_code: int) -> None:
        engine = self.stub_bin / "suricata"
        engine.write_text(f"#!/bin/sh\necho 'configuration test'\nexit {exit_code}\n")
        engine.chmod(0o755)

    def _run(self):
        return run_helper(
            "rapi-outputs",
            env={
                "RAPI_SURICATA_YAML": str(self.yaml),
                "RAPI_SURICATA_OUTPUTS": str(self.outputs),
                "RAPI_SURICATA_CONF_DIR": str(self.tmp),
                "RAPI_INCLUDE_BIN": str(DEPLOY / "rapi-include"),
            },
            path_prefix=self.stub_bin,
        )

    def test_the_two_files_nobody_reads_are_gone(self):
        # There is no way to switch off one entry of a list from an include, so
        # they go by being left out of a key we write in full.
        self.assertEqual(self._run().returncode, 0)
        # By entry, not by word: the header of the generated file names both of
        # them while explaining why they are not in it.
        entries = [ln for ln in self.outputs.read_text().splitlines()
                   if ln.startswith("  - ")]
        self.assertEqual(entries, ["  - eve-log:"])

    def test_the_eve_block_is_copied_whole(self):
        # Transcribing 35 event types by hand would drift from the package on
        # the first update. Copying keeps it faithful by construction.
        self._run()
        written = self.outputs.read_text()
        self.assertIn("- eve-log:", written)
        self.assertIn("filename: eve.json", written)
        self.assertIn("- alert:", written)
        self.assertIn("payload: no", written)
        self.assertIn("- flow", written)

    def test_the_stats_records_inside_eve_stay(self):
        # The panel's live counters come from these. Losing them would leave a
        # dashboard that has to be told the engine is alive by something else.
        self._run()
        self.assertIn("- stats:", self.outputs.read_text())

    def test_it_stops_at_the_end_of_the_eve_entry(self):
        # Every top-level output sits at two spaces and the event types at
        # eight, so the copy has to end at the next two-space line - not run on
        # into tls-store, stats and whatever the package adds after them.
        self._run()
        written = self.outputs.read_text()
        self.assertNotIn("tls-store", written)
        self.assertNotIn("logging:", written)

    def test_the_include_is_added_once(self):
        self._run()
        self._run()
        self.assertEqual(self.yaml.read_text().count(f"  - {self.outputs}"), 1)

    def test_a_file_with_no_eve_block_is_refused(self):
        self.yaml.write_text("%YAML 1.1\n---\noutputs:\n  - fast:\n      enabled: yes\n")
        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.outputs.exists())

    def test_an_eve_block_without_alerts_is_refused(self):
        # A sensor logging everything except what it is for. The check is cheap
        # and the failure it prevents is silent.
        self.yaml.write_text(
            "%YAML 1.1\n---\noutputs:\n  - eve-log:\n      enabled: yes\n"
            "      types:\n        - flow\n"
        )
        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertIn("alert", result.stderr)
        self.assertFalse(self.outputs.exists())

    def test_a_configuration_the_engine_refuses_takes_the_file_with_it(self):
        self._stub_engine(1)
        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.outputs.exists())


class TuningHelperTest(BackendTestCase):
    """Settings that are not about the capture interface.

    Both came from a UniFi gateway running the same engine, and both are here
    only because they survived being measured. What did not: detect.profile
    (1081 MB against 1085 MB), the memory caps (theirs are 4 to 30 times leaner
    and ours use 11 MB of a 128 MB flow cap), and mpm-algo: hs, which is what
    that gateway actually gains from and which the Debian arm64 build does not
    have - "Hyperscan support: no".
    """

    DUMPED = [
        "stream = (null)",
        "stream.memcap = 64 MiB",
        "stream.checksum-validation = yes",
        "stream.reassembly = (null)",
        "stream.reassembly.urgent = (null)",
        "stream.reassembly.urgent.policy = oob",
        "stream.reassembly.memcap = 256 MiB",
        "stream.reassembly.depth = 1 MiB",
        "mpm-algo = auto",
    ]

    def setUp(self):
        super().setUp()
        self.yaml = self.tmp / "suricata.yaml"
        self.yaml.write_text("%YAML 1.1\n---\nstream:\n  memcap: 64mb\n")
        self.tuning = self.tmp / "rapi-tuning.yaml"
        self.conf = self.tmp / "conf"
        self.conf.mkdir()
        (self.conf / "rapi-capture.yaml").write_text("%YAML 1.1\n---\n")
        self.stub_bin = self.tmp / "bin"
        self.stub_bin.mkdir()
        self._stub_engine(0)

    def _stub_engine(self, exit_code: int, dumped=None, test_output="loaded") -> None:
        lines = self.DUMPED if dumped is None else dumped
        engine = self.stub_bin / "suricata"
        engine.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            "  --dump-config) cat <<'DUMP'\n" + "\n".join(lines) + "\nDUMP\n"
            "  exit 0 ;;\n"
            "esac\n"
            f"echo '{test_output}'\nexit {exit_code}\n"
        )
        engine.chmod(0o755)

    def _run(self):
        # The tuning file has to land in the directory rapi-include scans, or
        # the include list is rebuilt without it.
        self.tuning = self.conf / "rapi-tuning.yaml"
        return run_helper("rapi-tuning", env={
            "RAPI_SURICATA_YAML": str(self.yaml),
            "RAPI_SURICATA_TUNING": str(self.tuning),
            "RAPI_SURICATA_CONF_DIR": str(self.conf),
            "RAPI_INCLUDE_BIN": str(DEPLOY / "rapi-include"),
        }, path_prefix=self.stub_bin)

    def test_the_whole_stream_key_is_written(self):
        # An include replaces a whole key, so a file holding only `bypass`
        # takes reassembly.depth with it, and the engine says what happens:
        #   i: stream-tcp: stream.reassembly.depth set to unlimited by default
        self.assertEqual(self._run().returncode, 0, self.tuning)
        written = self.tuning.read_text()
        self.assertIn('memcap: "64 MiB"', written)
        self.assertIn('depth: "1 MiB"', written)
        self.assertIn('checksum-validation: "yes"', written)

    def test_nesting_survives_the_round_trip(self):
        # --dump-config prints flat paths; three levels have to come back as
        # three levels or the engine reads a key that is not there.
        self._run()
        written = self.tuning.read_text()
        self.assertIn("stream:\n", written)
        self.assertIn("  reassembly:\n", written)
        self.assertIn("    urgent:\n", written)
        self.assertIn('      policy: "oob"', written)

    def test_the_container_lines_are_not_written_as_settings(self):
        # "stream.reassembly = (null)" is the container, not a value.
        self._run()
        self.assertNotIn("(null)", self.tuning.read_text())

    def test_bypass_is_added_because_there_is_nothing_to_replace(self):
        # It is absent from the packaged file, so it is absent from
        # --dump-config. Substituting it silently did nothing at all.
        self._run()
        self.assertIn('bypass: "yes"', self.tuning.read_text())

    def test_the_matcher_is_named_rather_than_left_to_auto(self):
        # `auto` resolves to `ac` on this build; ac-ks is 53 MB smaller on this
        # rule set. Naming it means a different build cannot change it quietly.
        self._run()
        self.assertIn("mpm-algo: ac-ks", self.tuning.read_text())

    def test_an_engine_that_reports_no_stream_settings_writes_nothing(self):
        self._stub_engine(0, dumped=["mpm-algo = auto"])
        self.assertEqual(self._run().returncode, 1)
        self.assertFalse(self.tuning.exists())

    def test_a_configuration_the_engine_refuses_takes_the_file_with_it(self):
        self._stub_engine(1)
        self.assertEqual(self._run().returncode, 1)
        self.assertFalse(self.tuning.exists())

    def test_losing_the_reassembly_depth_is_caught_not_shipped(self):
        # The engine only mentions this in passing, on a line that is not an
        # error, so it has to be looked for on purpose.
        self._stub_engine(0, test_output="stream-tcp: depth set to unlimited by default")
        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.tuning.exists())


class IpsModeHelperTest(BackendTestCase):
    """The switch between watching and blocking.

    Being inline is not the same as blocking, and this helper is the difference.
    A kernel bridge forwards the frame and hands the engine a copy, so the alert
    is raised after the packet has gone. NFQUEUE parks the packet until the
    engine has a verdict.
    """

    SCRIPT = (DEPLOY / "rapi-ips-mode").read_text()

    def test_the_mode_is_one_of_the_three_words(self):
        result = run_helper("rapi-ips-mode", "block-everything")
        self.assertEqual(result.returncode, 1)
        self.assertIn("usage", result.stderr)

    def test_it_says_which_mode_it_is_in_without_being_root(self):
        result = run_helper("rapi-ips-mode", "status",
                            env={"RAPI_SYSTEMD_DIR": "/nonexistent"})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "ids")

    def _written_ruleset(self):
        """The file the real helper writes, with the two commands it runs stubbed."""
        nft_dir = self.tmp / "nftables.d"
        units = self.tmp / "systemd"
        bin_dir = self.tmp / "stub-bin"
        bin_dir.mkdir(exist_ok=True)
        for name in ("nft", "systemctl"):
            stub = bin_dir / name
            stub.write_text("#!/bin/sh\nexit 0\n")
            stub.chmod(0o755)
        proc = run_helper("rapi-ips-mode", "ips",
                          env={"RAPI_NFT_DIR": str(nft_dir), "RAPI_SYSTEMD_DIR": str(units)},
                          path_prefix=bin_dir)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return nft_dir / "rapi-ips.nft"

    def test_loading_the_rules_again_replaces_them(self):
        """Reported by an outside audit as critical; half of it held up.

        True: "nft -f" merges into a table that already exists and appends
        every rule again, so each call grew each chain by another copy of its
        queue rule. Not true: that each copy queued the packet again. A queue
        statement ends the chain, and a counter on each copy, measured in a
        network namespace, showed the second and third never reached. Fixed
        anyway, because a ruleset that grows with every use of the switch is not
        one anybody can read.

        Run for real: the file the helper writes, loaded by nft in a network
        namespace of its own, once and then three times.
        """
        probe = subprocess.run(["unshare", "-rn", "nft", "list", "ruleset"],
                               capture_output=True)
        if probe.returncode != 0:
            self.skipTest("no unprivileged network namespace on this machine")
        ruleset = self._written_ruleset()
        for times in (1, 3):
            with self.subTest(times=times):
                script = (f'i=0; while [ $i -lt {times} ]; do '
                          f'/usr/sbin/nft -f "{ruleset}" || exit 9; i=$((i+1)); done; '
                          '/usr/sbin/nft list table inet rapi_ips')
                out = subprocess.run(["unshare", "-rn", "sh", "-c", script],
                                     capture_output=True, text=True)
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertEqual(out.stdout.count("queue"), 3, out.stdout)

    def test_nothing_in_the_ruleset_text_is_run_while_writing_it(self):
        # It is an unquoted heredoc, so a backtick in one of its comments is a
        # command. One went in with the fix above, as `nft -f` and `queue`, and
        # the helper ran both, as root, every time it wrote the file.
        start = self.SCRIPT.index("nft_ruleset() {")
        end = self.SCRIPT.index("\nEOF\n", start)
        self.assertNotIn("`", self.SCRIPT[start:end])
        self.assertNotIn("$(", self.SCRIPT[start:end])

    def test_the_queue_rule_lets_packets_past_when_nothing_is_listening(self):
        # `bypass` is the fail-open half of the decision. Without it a stopped
        # engine takes the network with it, which for a device posted to
        # somebody else's site and left alone is a worse outcome than one that
        # stops inspecting.
        # Every queue rule the script writes, and there are three chains.
        rules = re.findall(r"queue num \S+[^\n]*", self.SCRIPT)
        self.assertEqual(len(rules), 3, rules)
        for rule in rules:
            with self.subTest(rule=rule):
                self.assertIn("bypass", rule)

    def test_loopback_is_never_queued(self):
        # The panel has to stay reachable while the engine restarts.
        self.assertIn('iifname "lo" accept', self.SCRIPT)
        self.assertIn('oifname "lo" accept', self.SCRIPT)

    def test_the_administration_ports_are_never_queued(self):
        """Switching to blocking used to hang up on the browser that did it.

        Queued, the panel's own HTTPS session reaches a freshly started engine
        as a stream picked up midway - stream.midstream is false by default and
        exception-policy resolves to drop-flow in IPS mode, so the connection
        was dropped by the switch the operator had just clicked. Loopback did
        not cover it: the panel is reached over the network, not over lo. On a
        device that has no other way in, that is a mode you can turn on and not
        off.
        """
        for port in ("22", "443"):
            with self.subTest(port=port):
                self.assertRegex(self.SCRIPT, rf"ADMIN_PORTS=.*\b{port}\b")
        self.assertIn("tcp dport { $ADMIN_PORTS } accept", self.SCRIPT)
        self.assertIn("tcp sport { $ADMIN_PORTS } accept", self.SCRIPT)
        # Before the queue rule in both chains, or it never fires.
        for chain in ("input", "output"):
            block = self.SCRIPT.split(f"chain {chain} {{")[1].split("\n  }")[0]
            with self.subTest(chain=chain):
                self.assertLess(block.index("ADMIN_PORTS"), block.index("queue num"))

    def test_the_forward_chain_is_not_exempted(self):
        # The exemption is the device's own management plane. Traffic passing
        # through it is the whole point of blocking and stays inspected.
        forward = self.SCRIPT.split("chain forward {")[1].split("\n  }")[0]
        self.assertNotIn("ADMIN_PORTS", forward)
        self.assertIn("queue num", forward)

    def test_the_drop_in_replaces_execstart_rather_than_adding_to_it(self):
        # Without the bare "ExecStart=" first, systemd appends, and the engine
        # is started twice with two different capture methods.
        self.assertRegex(self.SCRIPT, r"ExecStart=\nExecStart=")
        self.assertIn("-q $QUEUE", self.SCRIPT)

    def test_a_refused_ruleset_changes_nothing(self):
        # Half a switch is the worst outcome: a queue rule with nothing reading
        # it, and a panel reporting blocking that is not happening.
        self.assertIn('nft -f "$NFT" || die', self.SCRIPT)

    def test_an_engine_that_will_not_start_is_put_back(self):
        self.assertIn('nft delete table inet "$NFT_TABLE"', self.SCRIPT)
        self.assertIn("put back as it was", self.SCRIPT)

    def test_it_survives_a_machine_that_has_no_capture_interface_yet(self):
        # Not this helper - the banner - but the same failure and the same fix,
        # so it is checked where the shell conventions are checked. A fresh
        # image has no rapi-capture.yaml, `grep` matching nothing fails the
        # pipeline under `set -o pipefail`, and `set -e` took the script with
        # it: the banner failed on every NetworkManager event for a whole boot
        # and the login screen kept the placeholder.
        with tempfile.TemporaryDirectory() as tmp:
            issue = Path(tmp) / "issue"
            result = run_helper("rapi-issue", env={
                "RAPI_ISSUE": str(issue),
                "RAPI_CAPTURE_YAML": str(Path(tmp) / "nothing-here.yaml"),
            })
            self.assertEqual(result.returncode, 0, result.stderr)
            text = issue.read_text()
            self.assertIn("RaPi IDS", text)
            # And it says so rather than leaving a blank where the answer goes.
            self.assertIn("nothing yet", text)

    def test_the_panel_is_allowed_to_call_it(self):
        for word in ("status", "ips", "ids"):
            with self.subTest(word=word):
                self.assertIn(f"/usr/local/sbin/rapi-ips-mode {word}", SUDOERS)


class RulesUpdateTest(BackendTestCase):
    """The daily signature refresh.

    The panel had a button and nothing else, so an image flashed and left alone
    ran on the rules from the day it was built for as long as it was plugged in,
    and looked healthy doing it.
    """

    UNIT = (DEPLOY / "rapi-rules-update.service.in").read_text()
    TIMER = (DEPLOY / "rapi-rules-update.timer").read_text()

    def test_it_will_not_run_without_both_panel_files(self):
        # suricata-update without disable.conf rebuilds from the vendor set
        # alone, which switches every disabled category and every silenced
        # signature back on. Without drop.conf it rebuilds every rule as
        # `alert`, which switches blocking off. Neither is reported: the tool
        # succeeds either way.
        self.assertEqual(run_helper("rapi-rules-update").returncode, 2)
        self.assertEqual(run_helper("rapi-rules-update", "/tmp").returncode, 2)

    def test_a_file_that_is_not_there_is_refused(self):
        result = run_helper("rapi-rules-update", "/nonexistent/disable.conf", "/tmp/drop.conf")
        self.assertEqual(result.returncode, 3)
        self.assertIn("disable.conf", result.stderr)

    def test_a_missing_drop_conf_is_refused_too(self):
        # The half that is easy to forget, because an empty drop.conf changes
        # nothing visible until the day the engine is in the path.
        with tempfile.NamedTemporaryFile(suffix=".conf") as disable:
            result = run_helper("rapi-rules-update", disable.name, "/nonexistent/drop.conf")
            self.assertEqual(result.returncode, 3)
            self.assertIn("drop.conf", result.stderr)

    def test_a_download_that_fails_does_not_pass_for_an_update(self):
        # suricata-update as it behaves: without --fail a fetch error still
        # writes a rule file (the engine's own 445 rules) and exits 0. On
        # 2026-10-10 that removed 68 413 signatures from a live device and the
        # helper printed "ok".
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "suricata-update"
            fake.write_text(
                "#!/bin/sh\n"
                "for arg in \"$@\"; do [ \"$arg\" = --fail ] && exit 1; done\n"
                "echo 'Writing rules: total: 445; removed 68413'\nexit 0\n")
            fake.chmod(0o755)
            for name in ("suricatasc", "systemctl"):
                tool = Path(tmp) / name
                tool.write_text("#!/bin/sh\nexit 0\n")
                tool.chmod(0o755)
            conf = Path(tmp) / "x.conf"
            conf.write_text("")
            result = subprocess.run(
                ["bash", str(DEPLOY / "rapi-rules-update"), str(conf), str(conf)],
                env={**os.environ, "PATH": f"{tmp}:{os.environ['PATH']}"},
                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("keeps the rules it has", result.stderr)
        self.assertNotIn("ok signatures updated", result.stdout)

    def test_the_image_build_fails_its_fetch_the_same_way(self):
        customize = (PROJECT_ROOT / "image" / "customize.sh").read_text()
        self.assertIn("inch suricata-update --fail --no-test", customize)

    def test_the_unit_passes_both_files(self):
        self.assertIn("@DISABLE_CONF@", self.UNIT)
        self.assertIn("@DROP_CONF@", self.UNIT)
        self.assertIn(
            "ExecStart=/usr/local/sbin/rapi-rules-update @DISABLE_CONF@ @DROP_CONF@", self.UNIT)

    def test_the_unit_waits_for_the_network(self):
        # The rules come from the network. Starting before it is up means one
        # failed run a day, on the day that matters: the first boot somewhere new.
        self.assertIn("Wants=network-online.target", self.UNIT)
        self.assertIn("After=network-online.target", self.UNIT)

    def test_the_unit_allows_time_for_a_rebuild_on_a_pi(self):
        # Being killed halfway is how a rule file gets truncated.
        match = re.search(r"TimeoutStartSec=(\d+)", self.UNIT)
        self.assertIsNotNone(match)
        self.assertGreaterEqual(int(match.group(1)), 900)

    def test_a_missed_day_is_caught_up(self):
        # The sensor is not expected to be switched on at any given hour, and a
        # missed day is exactly the case this exists for.
        self.assertIn("Persistent=true", self.TIMER)

    def test_the_devices_do_not_all_ask_at_once(self):
        # Every copy of this image would otherwise fetch the same file at
        # midnight, from the same free rule server.
        self.assertIn("RandomizedDelaySec=", self.TIMER)

    def test_it_does_not_rebuild_during_boot(self):
        # A Pi booting straight into a rebuild of 68 000 rules is a Pi that
        # looks hung to whoever just plugged it in.
        self.assertIn("OnBootSec=", self.TIMER)


class CaptureProbeTest(BackendTestCase):
    """Frame classification, which is the only part that has any judgement in it."""

    @classmethod
    def setUpClass(cls):
        # Executed as source rather than imported: it is a script with no .py
        # name, and importing it would leave a __pycache__ in deploy/. The
        # main() guard means running the source defines the functions and
        # listens to nothing.
        cls.probe = types.SimpleNamespace()
        exec(compile((DEPLOY / "rapi-capture-probe").read_text(),
                     "rapi-capture-probe", "exec"), cls.probe.__dict__)

    def _frame(self, dst: bytes, src: bytes, ethertype: int = 0x0800,
               payload: bytes = b"") -> bytes:
        return dst + src + struct.pack("!H", ethertype) + payload

    def test_the_group_bit_is_what_makes_an_address_multicast(self):
        self.assertTrue(self.probe.is_multicast(b"\x01\x00\x5e\x00\x00\x01"))
        self.assertTrue(self.probe.is_multicast(self.probe.BROADCAST))
        self.assertFalse(self.probe.is_multicast(b"\xde\xad\xbe\xef\x00\x01"))

    def test_addresses_are_read_out_of_an_ipv4_frame(self):
        ip = bytes(12) + bytes([192, 168, 1, 10]) + bytes([8, 8, 8, 8])
        dst, src, ethertype, src_ip, dst_ip = self.probe.parse(
            self._frame(b"\x11" * 6, b"\x22" * 6, 0x0800, ip)
        )
        self.assertEqual((src_ip, dst_ip), ("192.168.1.10", "8.8.8.8"))
        self.assertEqual(ethertype, 0x0800)

    def test_a_vlan_tag_is_stepped_over(self):
        # A mirror port carries tagged frames; reading the header at the wrong
        # offset would turn every one of them into an unknown protocol.
        ip = bytes(12) + bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2])
        frame = (b"\x11" * 6 + b"\x22" * 6 + struct.pack("!H", 0x8100)
                 + b"\x00\x64" + struct.pack("!H", 0x0800) + ip)
        _, _, ethertype, src_ip, _ = self.probe.parse(frame)
        self.assertEqual(ethertype, 0x0800)
        self.assertEqual(src_ip, "10.0.0.1")

    def test_a_truncated_frame_yields_no_addresses_rather_than_raising(self):
        _, _, _, src_ip, dst_ip = self.probe.parse(self._frame(b"\x11" * 6, b"\x22" * 6))
        self.assertIsNone(src_ip)
        self.assertIsNone(dst_ip)

    def test_ipv6_addresses(self):
        payload = bytes(8) + bytes.fromhex("20010db8" + "0" * 24) + bytes.fromhex("20010db8" + "0" * 23 + "1")
        _, _, _, src_ip, dst_ip = self.probe.parse(
            self._frame(b"\x11" * 6, b"\x22" * 6, 0x86DD, payload)
        )
        self.assertEqual(src_ip, "2001:db8::")
        self.assertEqual(dst_ip, "2001:db8::1")

    def test_the_listening_time_is_capped_in_the_helper_too(self):
        # Not only in the panel: the helper is reachable through sudo.
        result = run_helper("rapi-capture-probe", _an_interface(), "600")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("between 1 and 30", result.stdout)

    def test_a_bad_interface_is_refused_before_the_socket(self):
        result = run_helper("rapi-capture-probe", "eth42", "1")
        self.assertIn("no such interface", result.stdout)

    def test_it_never_returns_a_payload(self):
        # Counts and addresses, never contents: the panel has no business
        # handing packet payloads to a browser, and a tool that could would be
        # worth stealing.
        source = (DEPLOY / "rapi-capture-probe").read_text()
        printed = source[source.rindex("print(json.dumps({"):]
        for forbidden in ("frame[", "payload", "recv(", "hex()", "decode("):
            self.assertNotIn(forbidden, printed)


def _an_interface() -> str:
    """Any interface this machine really has - the helpers check /sys."""
    return sorted(os.listdir("/sys/class/net"))[0]
