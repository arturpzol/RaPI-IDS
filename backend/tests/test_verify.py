"""The judgement inside scripts/verify.sh.

verify.sh itself is shell around two decisions, and both of them are here: what
counts as seeing both directions of a conversation, and what counts as watching
a segment the rule set considers inside. Both are counted over a log file, so
both can be run against one.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest

from .helpers import PRIVATE_DOCS, PRIVATE_DOCS_SKIP, PROJECT_ROOT, BackendTestCase

LIB = PROJECT_ROOT / "scripts" / "lib"


def flow(src="192.168.1.10", dest="203.0.113.5", to_server=5, to_client=5,
         proto="TCP", ts="2026-08-27T10:00:00+02:00") -> str:
    return json.dumps({
        "timestamp": ts, "event_type": "flow", "proto": proto,
        "src_ip": src, "dest_ip": dest,
        "flow": {"pkts_toserver": to_server, "pkts_toclient": to_client},
    }, separators=(",", ":"))


class EveHelperTestCase(BackendTestCase):
    def write(self, *lines: str):
        path = self.tmp / "eve.json"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def run_helper(self, name: str, *args: str) -> list[int]:
        result = subprocess.run(
            [sys.executable, str(LIB / name), *args],
            capture_output=True, text=True, check=True,
        )
        return [int(n) for n in result.stdout.split()]


class FlowDirectionTest(EveHelperTestCase):
    def test_a_conversation_seen_from_both_sides_counts(self):
        path = self.write(flow(), flow())
        self.assertEqual(self.run_helper("eve-flows.py", str(path)), [2, 2])

    def test_a_half_conversation_counts_only_towards_the_total(self):
        # The fault this exists for: with the VLAN id in the flow key every
        # conversation arrives as two of these and none of the pairs ever meet.
        path = self.write(flow(to_client=0), flow(to_server=0))
        self.assertEqual(self.run_helper("eve-flows.py", str(path)), [2, 0])

    def test_udp_is_not_counted_at_all(self):
        # The question is about TCP sessions, which is what has to be
        # established before any parser starts.
        path = self.write(flow(proto="UDP", to_client=0), flow())
        self.assertEqual(self.run_helper("eve-flows.py", str(path)), [1, 1])

    def test_records_from_before_the_engine_started_are_left_out(self):
        # eve.json outlives a restart. Counting the old records would report a
        # fault that has already been fixed, or hide one just made.
        path = self.write(
            flow(to_client=0, ts="2026-08-27T08:00:00+02:00"),
            flow(ts="2026-08-27T10:00:00+02:00"),
        )
        self.assertEqual(
            self.run_helper("eve-flows.py", str(path), "2026-08-27T09:00:00+02:00"),
            [1, 1],
        )

    def test_a_truncated_line_is_skipped_not_fatal(self):
        # The engine is writing to this file while we read it.
        path = self.write(flow(), '{"event_type":"flow","proto":"TC')
        self.assertEqual(self.run_helper("eve-flows.py", str(path)), [1, 1])

    def test_an_empty_file_is_an_answer_not_a_crash(self):
        path = self.tmp / "eve.json"
        path.write_text("", encoding="utf-8")
        self.assertEqual(self.run_helper("eve-flows.py", str(path)), [0, 0])


class HomeNetCoverageTest(EveHelperTestCase):
    HOME = "[192.168.1.0/24]"

    def test_either_end_inside_is_enough(self):
        path = self.write(
            flow(src="192.168.1.10", dest="203.0.113.5"),
            flow(src="203.0.113.5", dest="192.168.1.10"),
        )
        self.assertEqual(self.run_helper("eve-homenet.py", str(path), self.HOME), [2, 2])

    def test_a_segment_outside_home_net_is_what_this_catches(self):
        # 88 % of the rule set is written as HOME_NET -> EXTERNAL_NET or the
        # reverse. A sensor on a segment that is in neither loads every rule,
        # reports itself healthy, and matches almost nothing.
        path = self.write(*[flow(src="10.9.9.9", dest="203.0.113.5")] * 3)
        self.assertEqual(self.run_helper("eve-homenet.py", str(path), self.HOME), [3, 0])

    def test_several_networks_are_read_from_the_stored_form(self):
        # The string is what the panel writes to /etc/suricata/rapi-home-net.
        path = self.write(flow(src="10.0.0.4"), flow(src="172.16.0.4"))
        self.assertEqual(
            self.run_helper("eve-homenet.py", str(path), "[10.0.0.0/8,172.16.0.0/12]"),
            [2, 2],
        )

    def test_ipv6_is_counted_by_the_same_rule(self):
        # A dual stack network with an IPv4-only HOME_NET is the same fault as
        # a sensor on the wrong segment, and it looks identical from any screen.
        path = self.write(flow(src="2001:db8::1", dest="2001:db8::2"))
        self.assertEqual(self.run_helper("eve-homenet.py", str(path), self.HOME), [1, 0])
        self.assertEqual(
            self.run_helper("eve-homenet.py", str(path), "[2001:db8::/32]"), [1, 1],
        )

    def test_a_home_net_that_is_not_a_network_is_ignored_not_fatal(self):
        path = self.write(flow(src="192.168.1.10"))
        self.assertEqual(
            self.run_helper("eve-homenet.py", str(path), "[nonsense,192.168.1.0/24]"),
            [1, 1],
        )


class VerifyScriptTest(BackendTestCase):
    SCRIPT = PROJECT_ROOT / "scripts" / "verify.sh"

    def test_it_is_executable(self):
        self.assertTrue(self.SCRIPT.stat().st_mode & 0o100)

    def test_the_end_to_end_rule_needs_a_session(self):
        """The check is worthless with a rule that matches one packet.

        The check we used to do by hand fired GPL 2100498, which is
        `alert ip any any -> any any` with a bare content match: it fires on a
        sensor that has no stream tracking, no HTTP parser and a HOME_NET
        pointing at the wrong segment. It reported success while the whole TCP
        side of detection was dead. 2007961 needs flow:established, http.
        """
        text = self.SCRIPT.read_text(encoding="utf-8")
        self.assertIn("TEST_SID=2007961", text)
        self.assertNotIn("TEST_SID=2100498", text)
        # The user agent has to be the one the rule matches, or the request is
        # an ordinary request and the check passes only by accident.
        self.assertIn('TEST_AGENT="wget 3.0"', text)

    def test_the_panel_and_the_readme_tell_you_to_run_what_it_runs(self):
        """One command, three places, and they drifted.

        The target used to be testmynids.org, which stopped existing - NXDOMAIN
        from four independent resolvers - and had to be changed by hand in
        verify.sh, in the dashboard's empty-alert hint and in the README. The
        panel had been telling people to query a dead domain, and the older two
        of the three were also using a weaker rule: a bare content match that
        passes on a sensor seeing nothing at all.

        The domain dying is not something a test can catch without a network.
        The three copies disagreeing is, and that is the half that keeps
        happening.
        """
        text = (PROJECT_ROOT / "scripts" / "verify.sh").read_text()
        url = re.search(r'TEST_URL="\$\{RAPI_VERIFY_URL:-(\S+?)\}"', text).group(1)
        agent = re.search(r'TEST_AGENT="(.+?)"', text).group(1)

        for name, path in (
            ("the dashboard", PROJECT_ROOT / "frontend" / "src" / "app" / "features"
                              / "dashboard" / "dashboard.html"),
            ("the README", PROJECT_ROOT / "README.md"),
        ):
            with self.subTest(where=name):
                if name == "the README" and not PRIVATE_DOCS:
                    self.skipTest(PRIVATE_DOCS_SKIP)
                shown = path.read_text(encoding="utf-8")
                # Stops at "<" as well as at whitespace: in the template the
                # command is inside a <code> tag and the closing one would come
                # along for the ride.
                command = re.search(r"curl -4 -A '(.+?)' ([^\s<]+)", shown)
                self.assertIsNotNone(command, f"{name} shows no detection test command")
                self.assertEqual(command.group(1), agent)
                self.assertEqual(command.group(2), url)

    def test_it_forces_ipv4_for_its_own_request(self):
        # HOME_NET is a list of IPv4 networks, so the same request over IPv6
        # comes from an address no HOME_NET rule considers inside - and this
        # host resolves the test name to IPv6 first.
        self.assertIn("curl -4", self.SCRIPT.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()


class VerifyRunTest(BackendTestCase):
    """The release gate itself, run against a device made of files.

    Every command it asks the machine is a stub: the engine's counters, the
    probe, the service state, the one request it makes. Nothing leaves this
    process and nothing needs root, which is also why this is not left to be
    found on a real device: the gate is what decides a release, and the day it
    reports a working sensor as broken, or the reverse, is the day it matters.
    """

    SCRIPT = PROJECT_ROOT / "scripts" / "verify.sh"

    def setUp(self):
        super().setUp()
        self.bin = self.tmp / "verify-bin"
        self.bin.mkdir()
        self.logs = self.tmp / "verify-logs"
        self.logs.mkdir()
        (self.logs / "eve.json").write_text("")
        self.data = self.tmp / "verify-data"
        self.data.mkdir()
        (self.data / "disable.conf").write_text("# nothing silenced\n")
        self.rules = self.tmp / "suricata.rules"
        self.rules.write_text('alert tcp any any -> any any (msg:"ET MALWARE X"; sid:1;)\n')
        self.home_net = self.tmp / "rapi-home-net"
        self.home_net.write_text("[10.0.0.0/8]\n")
        self.capture = self.tmp / "rapi-capture.yaml"
        self.mirror()
        self.counters({"capture": {"kernel_packets": 1000, "kernel_drops": 0},
                       "decoder": {"pkts": 1000}, "uptime": 60})
        self.foreign(40)
        # The gate spells the probe's path out, as sudoers grants it, so the
        # stub sudo is where that one command is pointed at the stub probe.
        self.stub("sudo", 'if [ "$1" = "-n" ]; then shift; fi\n'
                          'if [ "$1" = /usr/local/sbin/rapi-capture-probe ]; then\n'
                          f'  shift; exec "{self.bin}/rapi-capture-probe" "$@"\n'
                          'fi\nexec "$@"')
        self.stub("systemctl", "exit 0")
        self.stub("suricata", f'echo "default-log-dir = {self.logs}/"')
        # The one request the gate makes. Answers with no address, so the check
        # reports that it could not generate traffic rather than going out.
        self.stub("curl", "exit 0")

    def stub(self, name, body):
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def counters(self, message):
        (self.tmp / "counters.json").write_text(json.dumps({"message": message}))
        self.stub("suricatasc", f'cat "{self.tmp / "counters.json"}"')

    def foreign(self, frames):
        self.stub("rapi-capture-probe", f"echo '{{\"foreign_unicast\": {frames}}}'")

    def mirror(self):
        self.capture.write_text("af-packet:\n  - interface: eth0\n    cluster-id: 99\n")

    def bridge(self):
        self.capture.write_text("af-packet:\n  - interface: br-rapi\n    cluster-id: 99\n")

    def pair(self):
        self.capture.write_text("af-packet:\n  - interface: eth0\n    copy-mode: ips\n"
                                "    copy-iface: eth1\n  - interface: eth1\n"
                                "    copy-mode: ips\n    copy-iface: eth0\n")

    def run_gate(self):
        env = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "HOME": str(self.tmp),
            "RAPI_SURICATA_YAML": str(self.tmp / "suricata.yaml"),
            "RAPI_SURICATA_CAPTURE": str(self.capture),
            "RAPI_HOME_NET_STATE": str(self.home_net),
            "RAPI_RULES_FILE": str(self.rules),
            "RAPI_CAPTURE_PROBE_BIN": str(self.bin / "rapi-capture-probe"),
            "RAPI_DATA_DIR": str(self.data),
            "RAPI_VERIFY_ALERT_TIMEOUT": "1",
        }
        proc = subprocess.run(["bash", str(self.SCRIPT)], capture_output=True,
                              text=True, env=env, timeout=120)
        return re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout)

    # --- the layout decides the words ---------------------------------------

    def test_a_mirror_is_checked_as_a_mirror(self):
        self.foreign(0)
        out = self.run_gate()
        self.assertIn("2. Mirror port", out)
        self.assertIn("watching itself", out)

    def test_a_link_through_the_device_is_not_asked_about_a_mirror(self):
        """The inline bridge: frames for other machines cross it because it
        carries the link. Told to check a mirror, the operator goes looking for
        a switch setting their layout does not use."""
        self.bridge()
        self.foreign(0)
        out = self.run_gate()
        self.assertIn("2. Traffic crosses the link", out)
        self.assertNotIn("Mirror port", out)
        self.assertNotIn("watching itself", out)
        self.assertIn("both cables", out)

    def test_the_blocking_pair_counts_as_a_link_too(self):
        self.pair()
        self.foreign(0)
        self.assertIn("2. Traffic crosses the link", self.run_gate())

    def test_the_request_is_sent_from_behind_the_link_not_from_a_mirror(self):
        # The panel is reached another way on an inline layout, so its own
        # request never crosses the link and the gate has to say where to run it.
        self.bridge()
        self.stub("curl", 'echo 192.0.2.9')
        out = self.run_gate()
        self.assertIn("machine behind the link", out)
        self.assertNotIn("mirrored segment", out)

    # --- a queue is not a dead sensor ---------------------------------------

    def test_a_netfilter_queue_is_not_reported_as_seeing_nothing(self):
        # No ring, so no capture section: read as zero, the gate failed a
        # sensor that had inspected every packet it was given.
        self.counters({"decoder": {"pkts": 5000}, "ips": {"accepted": 5000},
                       "uptime": 60})
        out = self.run_gate()
        self.assertNotIn("no packets have reached the engine", out)
        self.assertIn("not reported on a netfilter queue", out)

    def test_an_engine_that_saw_nothing_still_fails(self):
        self.counters({"capture": {"kernel_packets": 0, "kernel_drops": 0},
                       "decoder": {"pkts": 0}, "uptime": 60})
        self.assertIn("no packets have reached the engine at all", self.run_gate())

    # --- silenced means out, whatever the action ----------------------------

    def test_a_silenced_rule_still_loaded_as_drop_is_caught(self):
        """With blocking on, an enabled category is loaded as drop.

        The check looked for `alert` only, so a silenced signature still in
        the rule set as a drop passed it, while it went on firing and stopping
        traffic. The one check written for "reports success, does nothing".
        """
        (self.data / "disable.conf").write_text("# silenced\n2000001\n")
        self.rules.write_text(
            'drop tcp any any -> any any (msg:"ET MALWARE X"; sid:2000001; rev:1;)\n')
        out = self.run_gate()
        self.assertIn("signatures the panel silenced are still enabled: 2000001", out)

    def test_a_silenced_rule_that_is_really_out_passes(self):
        (self.data / "disable.conf").write_text("# silenced\n2000001\n")
        self.rules.write_text(
            '# drop tcp any any -> any any (msg:"ET MALWARE X"; sid:2000001; rev:1;)\n')
        self.assertIn("every silenced signature is out of the rule set", self.run_gate())

    def test_nothing_it_runs_here_reaches_the_network(self):
        # The stubbed curl records nothing and the gate says it could not
        # generate traffic: the proof that no request left this test.
        self.assertIn("no way to generate test traffic", self.run_gate())
