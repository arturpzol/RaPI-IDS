"""Detection categories, silenced signatures and the rule set rebuild."""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from unittest.mock import patch

from app import config, settings
from app.modules.network import capture as network_capture
from app.modules.network import topology as network_topology
from app.modules.suricata import protection

from .helpers import BackendTestCase, run_helper

RULES = b"""# comment line, not a rule
alert tcp any any -> any any (msg:"ET MALWARE Something Bad"; sid:2000001; rev:1; metadata:signature_severity Major, created_at 2020_01_01;)
alert tcp any any -> any any (msg:"ET INFO GNU/Linux APT User-Agent"; sid:2013504; rev:5; metadata:signature_severity Informational, created_at 2020_01_01;)
# alert tcp any any -> any any (msg:"ET INFO Disabled One"; sid:2013505; rev:1; metadata:signature_severity Informational;)
alert ip any any -> any any (msg:"SURICATA Ethertype unknown"; sid:2200121; rev:2;)
drop tcp any any -> any any (msg:"GPL SCAN nmap"; sid:2100628; rev:3;)
alert tcp any any -> any any (msg:"ET NOSUCHGROUP Whatever"; sid:2999999; rev:1;)
alert ip any any -> any any (msg:"ET Threatview.io High Confidence Cobalt Strike C2 IP group 1"; sid:2400001; rev:1;)
"""


class RuleScanTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.rules_dir = self.tmp / "rules"
        self.rules_dir.mkdir()
        (self.rules_dir / "suricata.rules").write_bytes(RULES)
        self.enterContext(patch.object(config, "SURICATA_RULES_DIR", self.rules_dir))
        protection._scan_cache = None
        self.addCleanup(setattr, protection, "_scan_cache", None)

    def test_counts_total_and_enabled(self):
        scan = protection.scan_rules(force=True)
        self.assertEqual(scan.total, 7)
        self.assertEqual(scan.enabled, 6)  # one is commented out

    def test_a_group_written_in_lower_case_is_still_a_group(self):
        """The one Emerging Threats does not write in capitals.

        "ET Threatview.io High Confidence Cobalt Strike C2" - with the group
        pattern limited to [A-Z0-9_] that matched a bare "T", missed the index
        and left 22 high confidence C2 rules in the residual bucket. They were
        detecting the whole time; they were filed under nothing, and the bucket
        is locked, so they could not be managed with the rest of the threat
        intelligence they belong to. UniFi lists the same group as
        THREATVIEW_CS_C2.
        """
        per = protection.scan_rules(force=True).per_category
        self.assertEqual(per["botnet"]["total"], 1)
        self.assertEqual(per["other"]["total"], 1)   # only ET NOSUCHGROUP left

    def test_signatures_land_in_the_right_category(self):
        per = protection.scan_rules(force=True).per_category
        self.assertEqual(per["malware"]["total"], 1)
        self.assertEqual(per["info"]["total"], 2)
        self.assertEqual(per["info"]["enabled"], 1)
        self.assertEqual(per["attack"]["total"], 1)      # GPL SCAN
        self.assertEqual(per["protocol"]["total"], 1)    # SURICATA, whole family
        self.assertEqual(per["other"]["total"], 1)       # unknown group

    def test_the_rating_is_counted_across_the_categories_not_inside_them(self):
        # A rule sits in exactly one category and, separately, may or may not
        # carry an informational rating - the rating is in the metadata, the
        # category comes from the msg prefix. So these two numbers overlap the
        # per-category ones and must never be added to them.
        scan = protection.scan_rules(force=True)
        self.assertEqual(scan.informational["total"], 2)
        self.assertEqual(scan.informational["enabled"], 1)   # one is commented out
        self.assertEqual(scan.total, 7)                      # unchanged by the above

    def test_a_rule_with_no_metadata_is_not_informational(self):
        self.assertEqual(protection.scan_rules(force=True).informational["total"], 2)
        (self.rules_dir / "suricata.rules").write_bytes(
            b'alert ip any any -> any any (msg:"GPL SCAN nmap"; sid:1; rev:1;)\n'
        )
        self.assertEqual(protection.scan_rules(force=True).informational["total"], 0)

    def test_missing_rule_file_is_an_empty_scan_not_a_crash(self):
        (self.rules_dir / "suricata.rules").unlink()
        self.assertEqual(protection.scan_rules(force=True).total, 0)

    def test_the_cache_follows_the_file(self):
        first = protection.scan_rules(force=True)
        self.assertIs(protection.scan_rules(), first)  # unchanged file, same object
        path = self.rules_dir / "suricata.rules"
        path.write_bytes(RULES + b'alert ip any any -> any any (msg:"ET TOR Exit"; sid:3; rev:1;)\n')
        self.assertEqual(protection.scan_rules().total, 8)


class StateTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        protection.STATE_PATH.unlink(missing_ok=True)
        self.addCleanup(protection.STATE_PATH.unlink, True)

    def test_default_is_everything_on(self):
        state = protection.load_state()
        self.assertTrue(all(state["categories"].values()))
        self.assertEqual(state["muted"], {})

    def test_round_trip(self):
        state = protection.load_state()
        state["categories"]["info"] = False
        state["muted"]["2013504"] = "ET INFO GNU/Linux APT User-Agent"
        protection.save_state(state)
        loaded = protection.load_state()
        self.assertFalse(loaded["categories"]["info"])
        self.assertEqual(loaded["muted"]["2013504"], "ET INFO GNU/Linux APT User-Agent")

    def test_unknown_category_and_non_numeric_sid_are_dropped(self):
        protection.STATE_PATH.write_text(json.dumps({
            "categories": {"info": False, "made_up": False},
            "muted": {"2013504": "one", "not-a-sid": "two"},
        }))
        state = protection.load_state()
        self.assertNotIn("made_up", state["categories"])
        self.assertEqual(list(state["muted"]), ["2013504"])

    def test_corrupt_state_falls_back_to_the_default(self):
        protection.STATE_PATH.write_text("{ half a file")
        self.assertTrue(all(protection.load_state()["categories"].values()))


class DisableConfTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        protection.STATE_PATH.unlink(missing_ok=True)
        protection.DISABLE_CONF.unlink(missing_ok=True)
        protection.DROP_CONF.unlink(missing_ok=True)
        self.addCleanup(protection.STATE_PATH.unlink, True)
        self.addCleanup(protection.DISABLE_CONF.unlink, True)
        self.addCleanup(protection.DROP_CONF.unlink, True)

    # --- drop.conf: the other half of the same idea ------------------------
    #
    # disable.conf decides which rules exist. drop.conf decides which of them
    # load with `drop` instead of `alert`. Proven against the real rule set: a
    # drop.conf naming 2007961 turns
    #   alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET ADWARE_PUP ...
    # into `drop http ...`, and the number of drop rules in the merged file went
    # from 1 - a built-in stream event - to 2.

    def test_an_empty_drop_conf_is_still_written(self):
        # suricata-update given no --drop-conf rebuilds every rule as `alert`
        # and reports success, so a file that stops being passed is a rule set
        # that quietly stops blocking. It has to exist even when it says nothing.
        text = protection.write_drop_conf(protection.load_state()).read_text()
        self.assertTrue(protection.DROP_CONF.exists())
        self.assertIn("Generated by RaPi IDS Panel", text)

    def test_the_policy_is_written_even_with_nothing_chosen(self):
        # The categories decide what blocks, so a fresh state already has a
        # policy, and the daily refresh reads it from this file.
        text = protection.write_drop_conf(protection.load_state()).read_text()
        self.assertIn(protection.blocking_pattern({}), text.splitlines())
        digits = [l for l in text.splitlines() if l.strip().isdigit()]
        self.assertEqual(digits, [])

    def test_nothing_in_the_policy_line_can_be_cut_by_suricata_update(self):
        # parse_matchers cuts every line at " #" and skips lines starting "#".
        line = protection.blocking_pattern({"2013031": "x", "2100498": "y"})
        self.assertNotIn("#", line)

    def test_an_allowed_signature_is_never_also_written_as_a_drop(self):
        state = protection.load_state()
        state["dropped"] = {"2007961": "ET ADWARE_PUP Fake Wget User-Agent"}
        state["allowed"] = {"2007961": "ET ADWARE_PUP Fake Wget User-Agent"}
        text = protection.write_drop_conf(state).read_text()
        self.assertNotIn("\n2007961\n", text)
        self.assertIn(protection.blocking_pattern(state["allowed"]), text.splitlines())

    def test_allowed_signatures_survive_a_reload_of_the_state(self):
        state = protection.load_state()
        state["allowed"] = {"2013031": "ET REMOTE_ACCESS AnyDesk", "x": "not a sid"}
        protection.save_state(state)
        self.assertEqual(protection.load_state()["allowed"],
                         {"2013031": "ET REMOTE_ACCESS AnyDesk"})

    def test_a_chosen_signature_becomes_a_bare_sid(self):
        state = protection.load_state()
        state["dropped"] = {"2007961": "ET ADWARE_PUP Fake Wget User-Agent"}
        text = protection.write_drop_conf(state).read_text()
        # The label is for whoever reads the file; suricata-update wants the
        # number on a line of its own.
        self.assertIn("# ET ADWARE_PUP Fake Wget User-Agent", text)
        self.assertIn("\n2007961\n", text)

    def test_dropped_signatures_survive_a_reload_of_the_state(self):
        state = protection.load_state()
        state["dropped"] = {"2007961": "ET ADWARE_PUP Fake Wget User-Agent"}
        protection.save_state(state)
        self.assertEqual(protection.load_state()["dropped"],
                         {"2007961": "ET ADWARE_PUP Fake Wget User-Agent"})

    def test_all_categories_on_writes_no_rules(self):
        text = protection.write_disable_conf(protection.load_state()).read_text()
        self.assertNotIn("re:msg:", text)

    def test_a_disabled_category_becomes_one_line_per_group(self):
        state = protection.load_state()
        state["categories"]["p2p"] = False
        text = protection.write_disable_conf(state).read_text()
        self.assertIn(r're:msg:\s*"ET P2P[^A-Za-z0-9_.]', text)
        self.assertIn(r're:msg:\s*"ET TOR[^A-Za-z0-9_.]', text)
        # The trailing class stops "ET DNS" from also disabling "ET DNS_FOO".
        self.assertNotIn('"ET P2P"', text)

    def test_a_whole_family_has_no_group_part(self):
        state = protection.load_state()
        state["categories"]["protocol"] = False
        self.assertIn(r're:msg:\s*"SURICATA[^A-Za-z0-9_.]',
                      protection.write_disable_conf(state).read_text())

    def test_muted_signatures_survive_a_category_change(self):
        # Writing the file from the categories alone used to wipe the silenced
        # signatures, which un-silenced them on the next rule update.
        state = protection.load_state()
        state["muted"]["2013504"] = "ET INFO GNU/Linux APT User-Agent"
        state["categories"]["info"] = False
        text = protection.write_disable_conf(state).read_text()
        self.assertIn("\n2013504\n", text)
        self.assertIn("# ET INFO GNU/Linux APT User-Agent", text)

    def test_a_group_name_is_escaped_before_it_becomes_a_regex(self):
        # These lines are regular expressions to suricata-update, and one group
        # name has a dot in it. Unescaped, "ET Threatview.io" would match
        # "ET ThreatviewXio" as well - and the trailing class excludes lower
        # case and the dot too, or "Threatview.io" would also disable
        # "Threatview.ionosphere".
        state = protection.load_state()
        state["categories"]["botnet"] = False
        text = protection.write_disable_conf(state).read_text()
        self.assertIn(r're:msg:\s*"ET Threatview\.io[^A-Za-z0-9_.]', text)
        self.assertNotIn('"ET Threatview.io[', text)

    def test_the_generated_expressions_match_what_they_mean_to(self):
        """Compiled and run, not compared as text.

        suricata-update reads these with Python's own `re`, so the check that
        matters is what they match. Two things go wrong silently otherwise: an
        unescaped dot makes "Threatview.io" match "ThreatviewXio", and a
        trailing class that allows lower case makes it match
        "Threatview.ionosphere" as well. Neither shows up in a string
        comparison, and both would disable rules nobody asked to disable.
        """
        state = protection.load_state()
        state["categories"]["botnet"] = False
        state["categories"]["protocol"] = False
        text = protection.write_disable_conf(state).read_text()

        patterns = [re.compile(line[len("re:"):])
                    for line in text.splitlines() if line.startswith("re:")]

        def hits(msg: str) -> int:
            line = f'alert ip any any -> any any (msg:"{msg}"; sid:1; rev:1;)'
            return sum(1 for p in patterns if p.search(line))

        self.assertEqual(hits("ET Threatview.io High Confidence Cobalt Strike C2"), 1)
        self.assertEqual(hits("ET ThreatviewXio Something"), 0)
        self.assertEqual(hits("ET Threatview.ionosphere Something"), 0)
        # The reason the trailing class was there in the first place.
        self.assertEqual(hits("ET DNS Query"), 1)
        self.assertEqual(hits("ET DNS_SOMETHING Query"), 0)
        # A whole family, matched without a group part.
        self.assertEqual(hits("SURICATA STREAM excessive retransmissions"), 1)
        self.assertEqual(hits("SURICATAX Something"), 0)
        # And nothing from a category that stayed on.
        self.assertEqual(hits("ET MALWARE Something Bad"), 0)

    def test_a_label_cannot_break_the_file_over_two_lines(self):
        state = protection.load_state()
        state["muted"]["2000001"] = "line one\nre:msg:\"ET MALWARE"
        text = protection.write_disable_conf(state).read_text()
        for line in text.splitlines():
            self.assertFalse(line.startswith("re:msg:"), line)


class SnapshotTest(BackendTestCase):
    """What the protection screen is handed."""

    def setUp(self):
        super().setUp()
        self.rules_dir = self.tmp / "rules"
        self.rules_dir.mkdir()
        self.enterContext(patch.object(config, "SURICATA_RULES_DIR", self.rules_dir))
        protection._scan_cache = None
        self.addCleanup(setattr, protection, "_scan_cache", None)
        protection.STATE_PATH.unlink(missing_ok=True)
        self.addCleanup(protection.STATE_PATH.unlink, True)

    def write(self, text: bytes):
        (self.rules_dir / "suricata.rules").write_bytes(text)

    def ids(self):
        return [c["id"] for c in protection.snapshot()["categories"]]

    def test_the_residual_bucket_shows_while_something_is_in_it(self):
        # It exists so the per-category counts add up to the total, and so that
        # rules belonging to no category are visibly still running.
        self.write(RULES)
        self.assertIn("other", self.ids())

    def test_an_empty_residual_bucket_is_not_a_row(self):
        # With nothing enabled in it there is nothing to be honest about, and a
        # locked row reading "0 of 24" only invites the question of how it
        # differs from the rating switch below it.
        self.write(b'alert tcp any any -> any any (msg:"ET MALWARE X"; sid:1; rev:1;)\n')
        self.assertNotIn("other", self.ids())

    def test_each_category_carries_what_the_rating_would_take(self):
        self.write(RULES)
        by_id = {c["id"]: c for c in protection.snapshot()["categories"]}
        self.assertEqual(by_id["info"]["informational"], 2)
        self.assertEqual(by_id["malware"]["informational"], 0)


class SourceDateTest(BackendTestCase):
    """How old the detection is, as opposed to when the panel last rebuilt it.

    The screen used to show one number for both. The merged rule file is
    rewritten from the local cache by every category switch and every silenced
    signature, so one click on a device that had not downloaded rules in a month
    made it read as current.
    """

    def setUp(self):
        super().setUp()
        self.rules_dir = self.tmp / "rules"
        self.rules_dir.mkdir()
        self.rules = self.rules_dir / "suricata.rules"
        self.rules.write_bytes(RULES)
        self.enterContext(patch.object(config, "SURICATA_RULES_DIR", self.rules_dir))
        protection._scan_cache = None
        self.addCleanup(setattr, protection, "_scan_cache", None)
        protection.STATE_PATH.unlink(missing_ok=True)
        self.addCleanup(protection.STATE_PATH.unlink, True)
        # A helper that is there, so the run is attempted and sudo is stubbed.
        helper = self.tmp / "rapi-rules-date"
        helper.write_text("")
        self.enterContext(patch.object(protection, "RULES_DATE_HELPER", str(helper)))

    def helper_says(self, stdout: str = "built 1788381900\nfetched 1788399072\n",
                    returncode: int = 0):
        """Stand in for sudo, and count how often the panel reaches for it."""
        calls = []

        def run(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, returncode, stdout, "")

        self.enterContext(patch.object(protection.subprocess, "run", side_effect=run))
        return calls

    def test_the_screen_carries_the_vendor_date_and_the_download_date(self):
        self.helper_says()
        snapshot = protection.snapshot()
        self.assertEqual(snapshot["built_at"], 1788381900.0)
        self.assertEqual(snapshot["fetched_at"], 1788399072.0)

    def test_a_rebuild_does_not_make_an_old_set_look_fresh(self):
        """The bug this exists for.

        Silencing one signature rebuilds suricata.rules from the cached archive.
        The rule file is younger afterwards; the detection in it is exactly as
        old as it was.
        """
        self.helper_says()
        before = protection.snapshot()
        os.utime(self.rules, (time.time() + 3600, time.time() + 3600))
        self.rules.write_bytes(RULES + b'alert ip any any (msg:"x"; sid:9; rev:1;)\n')
        protection._scan_cache = None
        after = protection.snapshot()

        self.assertGreater(after["updated_at"], before["updated_at"])
        self.assertEqual(after["built_at"], before["built_at"])

    def test_the_helper_is_asked_once_per_rule_file_not_once_per_poll(self):
        # The protection screen polls. Nothing can change either date without
        # rewriting the rule file, so the answer is cached against it.
        calls = self.helper_says()
        for _ in range(5):
            protection.source_dates()
        self.assertEqual(len(calls), 1)

    def test_a_rebuild_asks_again(self):
        calls = self.helper_says()
        protection.source_dates()
        self.rules.write_bytes(RULES + b"# one more line\n")
        protection.source_dates()
        self.assertEqual(len(calls), 2)

    def test_an_unknown_answer_is_not_cached(self):
        """Installing the helper does not touch the rule file.

        Cached, the "unknown" from before the install would sit there until the
        next rebuild - outliving its own fix, on a screen that gives no hint
        which of the two it is showing.
        """
        calls = self.helper_says(stdout="", returncode=1)
        self.assertIsNone(protection.source_dates()["built"])
        self.assertIsNone(protection.source_dates()["built"])
        self.assertEqual(len(calls), 2)

    def test_a_helper_that_is_not_installed_costs_no_fork(self):
        calls = self.helper_says()
        with patch.object(protection, "RULES_DATE_HELPER", str(self.tmp / "gone")):
            self.assertEqual(protection.source_dates(),
                             {"built": None, "fetched": None})
        self.assertEqual(calls, [])

    def test_output_that_is_not_two_numbers_leaves_the_dates_unknown(self):
        # Rather than a traceback on the one screen that reports rule health.
        for stdout in ("", "built\n", "built later\nfetched soon\n", "nonsense"):
            with self.subTest(stdout=stdout):
                protection._source_cache = None
                with patch.object(protection.subprocess, "run",
                                  return_value=subprocess.CompletedProcess(
                                      [], 0, stdout, "")):
                    self.assertEqual(protection.source_dates(),
                                     {"built": None, "fetched": None})

    def test_half_an_answer_from_a_failed_run_is_not_an_answer(self):
        """The helper prints the build date before it reads the download date.

        A failure in between leaves a valid looking line on stdout and a
        non-zero exit, and taking the line would put a date on the screen that
        no successful run ever produced.
        """
        self.helper_says(stdout="built 1788381900\n", returncode=1)
        self.assertEqual(protection.source_dates(), {"built": None, "fetched": None})

    def test_a_helper_that_hangs_is_given_up_on(self):
        protection._source_cache = None
        with patch.object(protection.subprocess, "run",
                          side_effect=subprocess.TimeoutExpired([], 30)):
            self.assertEqual(protection.source_dates(),
                             {"built": None, "fetched": None})

    def test_no_rule_file_at_all_is_still_an_answer(self):
        # A checkout before the first rebuild: no merged file, but the archive
        # may well be in the cache already.
        self.helper_says()
        self.rules.unlink()
        protection._scan_cache = None
        protection._source_cache = None
        self.assertEqual(protection.source_dates()["built"], 1788381900.0)


class InformationalTest(BackendTestCase):
    """The rating that decides whether 15 023 of the 68 556 rules are loaded.

    It used to be a view filter: rows were stored and left out of the list by an
    SQL expression, with a Python twin for the mailer and a test pinning the two
    together. Three places had to agree about what informational means, none of
    them was the engine, and it was wrong four times in two days. Now the answer
    comes from the rule metadata and the rule simply is not compiled.
    """

    def setUp(self):
        super().setUp()
        protection.STATE_PATH.unlink(missing_ok=True)
        protection.DISABLE_CONF.unlink(missing_ok=True)
        protection.DROP_CONF.unlink(missing_ok=True)
        self.addCleanup(protection.STATE_PATH.unlink, True)
        self.addCleanup(protection.DISABLE_CONF.unlink, True)
        self.addCleanup(protection.DROP_CONF.unlink, True)

    def test_on_by_default_because_that_is_what_a_fresh_rule_set_looks_like(self):
        self.assertTrue(protection.load_state()["informational"])
        self.assertNotIn("metadata:",
                         protection.write_disable_conf(protection.load_state()).read_text())

    def test_turning_it_off_is_one_line_matched_on_the_metadata(self):
        state = protection.load_state()
        state["informational"] = False
        text = protection.write_disable_conf(state).read_text()
        self.assertIn("metadata: signature_severity Informational", text)

    def test_the_line_is_the_spelling_suricata_update_reads(self):
        # `metadata: <key> <value>`, one space after the colon. suricata-update
        # ignores a line it cannot parse instead of failing, so a typo here
        # would silently do nothing at all.
        state = protection.load_state()
        state["informational"] = False
        key, value = protection.INFORMATIONAL_METADATA
        lines = protection.write_disable_conf(state).read_text().splitlines()
        self.assertIn(f"metadata: {key} {value}", lines)

    def test_the_choice_survives_a_category_change(self):
        state = protection.load_state()
        state["informational"] = False
        protection.save_state(state)
        state = protection.load_state()
        state["categories"]["p2p"] = False
        text = protection.write_disable_conf(state).read_text()
        self.assertIn("metadata: signature_severity Informational", text)
        self.assertIn(r're:msg:\s*"ET P2P[^A-Za-z0-9_.]', text)

    def test_it_travels_with_the_categories_so_one_visit_is_one_rebuild(self):
        # Two endpoints would mean two rebuilds of 68 556 rules for one visit to
        # one screen, and a window in between where the file matches neither
        # half of what the operator asked for.
        with patch.object(protection, "rebuild", return_value=(True, "")) as rebuild:
            ok, _ = protection.apply_selection({"p2p": False}, informational=False)
        self.assertTrue(ok)
        rebuild.assert_called_once()
        text = protection.DISABLE_CONF.read_text()
        self.assertIn("metadata: signature_severity Informational", text)
        self.assertIn(r're:msg:\s*"ET P2P[^A-Za-z0-9_.]', text)
        state = protection.load_state()
        self.assertFalse(state["informational"])
        self.assertTrue(state["applied"])

    def test_leaving_it_out_does_not_change_it(self):
        # The categories form can be saved without touching this switch, and a
        # missing field must not read as "off".
        with patch.object(protection, "rebuild", return_value=(True, "")):
            protection.apply_selection({}, informational=False)
            protection.apply_selection({"p2p": False})
        self.assertFalse(protection.load_state()["informational"])

    def test_a_failed_rebuild_keeps_the_choice_but_not_the_applied_flag(self):
        with patch.object(protection, "rebuild", return_value=(False, "boom")):
            ok, _ = protection.apply_selection({}, informational=False)
        self.assertFalse(ok)
        state = protection.load_state()
        self.assertFalse(state["informational"])
        self.assertFalse(state["applied"])


class RebuildTest(BackendTestCase):
    def test_command_is_spelled_out_for_sudoers(self):
        self.assertEqual(
            protection.rebuild_command(offline=True),
            ["sudo", "-n", "suricata-update", "--offline", "--no-reload",
             "--disable-conf", str(protection.DISABLE_CONF),
             "--drop-conf", str(protection.DROP_CONF)],
        )
        online = protection.rebuild_command(offline=False)
        self.assertNotIn("--offline", online)
        # A failed download must fail the update, not replace the rule set
        # with the 445 rules that ship with the engine.
        self.assertIn("--fail", online)

    def test_the_mode_says_how_many_rules_could_stop_anything(self):
        # The number the switch is meaningless without: blocking on with nothing
        # set to drop reports itself as blocking and stops exactly nothing.
        rules = protection._rules_file()
        rules.parent.mkdir(parents=True, exist_ok=True)
        rules.write_text(
            'alert http any any -> any any (msg:"one"; sid:1;)\n'
            'drop http any any -> any any (msg:"two"; sid:2;)\n'
            '# drop http any any -> any any (msg:"commented out"; sid:3;)\n'
            'drop tcp any any -> any any (msg:"four"; sid:4;)\n',
            encoding="utf-8")
        self.addCleanup(rules.unlink, True)
        self.assertEqual(protection.drop_rules(), 2)

    def test_a_rule_file_that_is_not_there_counts_zero_rather_than_raising(self):
        # This runs on every protection screen load, including before the rule
        # set has ever been built.
        protection._rules_file().unlink(missing_ok=True)
        self.assertEqual(protection.drop_rules(), 0)

    def _blocking(self):
        with patch.object(protection, "_yaml_capture", return_value={
                "interfaces": ["eth0"], "copy_mode_ips": False, "nfqueue": True}):
            return protection.mode_info()

    def test_blocking_says_when_the_rule_set_has_not_caught_up_with_the_policy(self):
        """The failure that looks most like success.

        A panel upgraded from before the policy existed: blocking on, every
        category enabled, and a rule file with one vendor drop rule and the rest
        still alerts. Everything else on the screen says "blocking".
        """
        protection._rules_file().write_bytes(
            b'alert tcp any any -> any any (msg:"ET MALWARE One"; sid:2000001; rev:1;)\n'
            b'alert tcp any any -> any any (msg:"ET MALWARE Two"; sid:2000002; rev:1;)\n'
            b'drop tcp any any -> any any (msg:"SURICATA STREAM x"; sid:2210057; rev:1;)\n')
        self.addCleanup(protection._rules_file().unlink, True)
        protection._scan_cache = None
        info = self._blocking()
        self.assertEqual(info["id"], "ips")
        self.assertEqual(info["drop_rules"], 1)
        self.assertEqual(info["drop_pending"], 2)
        self.assertIn("2 signatures do not follow the enabled categories yet",
                      info["reason"])
        self.assertIn("rebuilt", info["reason"])

    def test_a_rule_set_that_follows_the_policy_raises_no_warning(self):
        protection._rules_file().write_bytes(
            b'drop tcp any any -> any any (msg:"ET MALWARE One"; sid:2000001; rev:1;)\n')
        self.addCleanup(protection._rules_file().unlink, True)
        protection._scan_cache = None
        info = self._blocking()
        self.assertEqual(info["drop_pending"], 0)
        self.assertNotIn("rebuilt", info["reason"])
        self.assertIn("Signatures set to drop: 1.", info["reason"])

    def test_the_drop_count_does_not_read_as_a_rule_id(self):
        # "45491 rules are loaded with a drop action" opened a sentence, and a
        # reader took 45491 for the number of one rule.
        rules = b"".join(
            f'drop tcp any any -> any any (msg:"ET MALWARE {n}"; sid:{2000000 + n}; rev:1;)\n'.encode()
            for n in range(1234))
        protection._rules_file().write_bytes(rules)
        self.addCleanup(protection._rules_file().unlink, True)
        protection._scan_cache = None
        reason = self._blocking()["reason"]
        self.assertIn("Signatures set to drop: 1,234.", reason)
        self.assertNotRegex(reason, r"\b1234 rules\b")
        self.assertNotIn("..", reason)

    def test_blocking_does_not_promise_that_only_rules_stop_packets(self):
        """Measured false on this device: 266 packets stopped, none by a rule.

        The rest were the exception policy and streams picked up midway, both of
        which start the moment the switch is flipped. With or without rules
        waiting for a rebuild.
        """
        for pending in (0, 5):
            with self.subTest(pending=pending), \
                    patch.object(protection, "scan_rules",
                                 return_value=protection.RuleScan(blocking_pending=pending)):
                reason = self._blocking()["reason"].lower()
                self.assertIn("exception policy", reason)
                self.assertIn("midway", reason)

    def test_blocking_says_which_way_it_fails(self):
        # NFQUEUE with bypass: a stopped engine means traffic flows uninspected,
        # not that the link goes down. The wizard says the opposite elsewhere.
        self.assertIn("uninspected", self._blocking()["reason"].lower())

    def test_the_switch_is_only_offered_where_it_would_work(self):
        with patch.object(protection.Path, "exists", return_value=False):
            self.assertFalse(protection.mode_info()["can_switch"])

    def test_a_mode_change_the_panel_may_not_make_is_reported_not_swallowed(self):
        with patch.object(protection.subprocess, "run") as run:
            run.return_value.returncode = 1
            run.return_value.stdout = "sudo: a password is required"
            run.return_value.stderr = ""
            ok, output = protection.set_mode(True)
        self.assertFalse(ok)
        self.assertIn("sudoers", output)

    def test_the_mode_command_is_spelled_out_for_sudoers(self):
        with patch.object(protection.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = ""
            run.return_value.stderr = ""
            protection.set_mode(True)
            self.assertEqual(run.call_args[0][0],
                             ["sudo", "-n", protection.IPS_MODE_BIN, "ips"])
            protection.set_mode(False)
            self.assertEqual(run.call_args[0][0],
                             ["sudo", "-n", protection.IPS_MODE_BIN, "ids"])

    def _on(self, profile: str, applied: bool = True) -> None:
        settings.set(network_topology.SETTINGS_KEY, {"profile": profile, "applied": applied})

    def test_a_mirror_refuses_blocking_before_touching_anything(self):
        """A copy cannot be stopped, and the queue would blind the engine.

        The queue mechanism starts the engine with -q instead of --af-packet,
        so on a mirror layout the switch made it stop reading the mirror port
        and inspect only this Pi's own traffic, while the screen said blocking.
        """
        self._on("mirror")
        with patch.object(protection.subprocess, "run") as run, \
                patch.object(protection, "_catch_up_rules") as catch_up, \
                self.assertRaises(protection.ModeRefused) as refused:
            protection.set_mode(True)
        self.assertIn("mirror port", str(refused.exception))
        run.assert_not_called()
        catch_up.assert_not_called()

    def test_the_layout_running_decides_not_the_one_saved(self):
        """A choice saved in the wizard is not the layout the engine runs.

        Saving a step stores the profile with applied false while the engine
        keeps the previous layout. Reading the saved "self" offered the queue
        on a device still reading a mirror port.
        """
        self._on("self", applied=False)
        mode = protection.mode_info()
        self.assertFalse(mode["blocking_possible"])
        self.assertEqual(mode["blocking_unavailable"], protection.LAYOUT_NOT_APPLIED)
        with patch.object(protection.subprocess, "run") as run, \
                self.assertRaises(protection.ModeRefused):
            protection.set_mode(True)
        run.assert_not_called()

    def test_a_mirror_saved_but_not_applied_is_still_called_a_mirror(self):
        # Applying it would not make blocking possible, so "apply it first"
        # would send the operator round in a circle.
        self._on("mirror", applied=False)
        self.assertEqual(protection.mode_info()["blocking_unavailable"],
                         protection.MIRROR_CANNOT_BLOCK)

    def test_a_refusal_is_a_409_with_the_reason_not_a_server_error(self):
        from fastapi import HTTPException
        from app.modules.suricata import router as suricata_router
        self._on("mirror")
        with self.assertRaises(HTTPException) as raised:
            suricata_router.set_protection_mode(suricata_router.ModeChoice(block=True))
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("mirror port", raised.exception.detail)

    def test_a_mirror_can_always_go_back_to_detection(self):
        # A device switched before the refusal existed has to be able to leave.
        self._on("mirror")
        with patch.object(protection.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = run.return_value.stderr = ""
            protection.set_mode(False)
        self.assertEqual(run.call_args[0][0],
                         ["sudo", "-n", protection.IPS_MODE_BIN, "ids"])

    def test_the_screen_is_told_blocking_is_not_possible_on_a_mirror(self):
        self._on("mirror")
        mode = protection.mode_info()
        self.assertFalse(mode["blocking_possible"])
        self.assertIn("inline", mode["blocking_unavailable"])
        for profile in ("self", ""):
            with self.subTest(profile=profile or "not chosen"):
                self._on(profile)
                mode = protection.mode_info()
                self.assertTrue(mode["blocking_possible"])
                self.assertEqual(mode["blocking_unavailable"], "")

    def test_a_mirror_in_detection_says_why_the_other_option_is_off(self):
        # The sentence under the switch, the only place a disabled button can
        # explain itself on a phone, where there is no hover.
        self._on("mirror")
        with patch.object(protection, "_yaml_capture", return_value={
                "interfaces": ["eth0"], "copy_mode_ips": False, "nfqueue": False}):
            reason = protection.mode_info()["reason"]
        self.assertEqual(reason, protection.MIRROR_CANNOT_BLOCK)

    def test_a_mirror_already_on_the_queue_is_told_it_sees_nothing(self):
        self._on("mirror")
        reason = self._blocking()["reason"]
        self.assertIn("not being read", reason)
        self.assertIn("Switch back to Detection", reason)
        self.assertNotIn("can drop it", reason)

    def test_the_rebuild_writes_both_files_if_either_is_missing(self):
        # A device upgraded from before drop.conf existed has one file and not
        # the other, and suricata-update refuses a path it cannot read - so the
        # daily refresh would start failing on every device already in the field,
        # and the only sign would be alerts quietly going stale.
        protection.write_disable_conf(protection.load_state())
        protection.DROP_CONF.unlink(missing_ok=True)
        with patch.object(protection.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = ""
            run.return_value.stderr = ""
            protection.rebuild(offline=True)
        self.assertTrue(protection.DROP_CONF.exists())

    def test_failure_explains_a_missing_sudoers_entry(self):
        with patch.object(protection.subprocess, "run") as run:
            run.return_value.returncode = 1
            run.return_value.stdout = "sudo: a password is required"
            run.return_value.stderr = ""
            ok, output = protection.rebuild()
        self.assertFalse(ok)
        self.assertIn("scripts/install-service.sh", output)

    def test_failure_explains_an_empty_offline_cache(self):
        with patch.object(protection.subprocess, "run") as run:
            run.return_value.returncode = 1
            run.return_value.stdout = "error: source has not yet been downloaded"
            run.return_value.stderr = ""
            ok, output = protection.rebuild(offline=True)
        self.assertFalse(ok)
        self.assertIn("Update signatures", output)

    def test_a_missing_tool_is_reported_not_raised(self):
        with patch.object(protection.subprocess, "run", side_effect=FileNotFoundError):
            ok, output = protection.rebuild()
        self.assertFalse(ok)
        self.assertIn("missing", output)


class MuteTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.rules_dir = self.tmp / "rules"
        self.rules_dir.mkdir()
        (self.rules_dir / "suricata.rules").write_bytes(RULES)
        self.enterContext(patch.object(config, "SURICATA_RULES_DIR", self.rules_dir))
        self.rebuild = self.enterContext(
            patch.object(protection, "rebuild", return_value=(True, "ok"))
        )
        protection.STATE_PATH.unlink(missing_ok=True)
        self.addCleanup(protection.STATE_PATH.unlink, True)

    def test_the_label_comes_from_the_rule_file(self):
        # Taken from the rules rather than from the caller, so the stored label
        # is what the engine would actually print.
        self.assertEqual(protection.lookup_signature(2013504),
                         "ET INFO GNU/Linux APT User-Agent")
        self.assertIsNone(protection.lookup_signature(1))

    def test_a_commented_out_rule_still_has_a_name(self):
        self.assertEqual(protection.lookup_signature(2013505), "ET INFO Disabled One")

    def test_mute_then_unmute(self):
        protection.mute(2013504)
        self.assertEqual(protection.muted_signatures(),
                         [{"signature_id": 2013504,
                           "signature": "ET INFO GNU/Linux APT User-Agent"}])
        self.assertIn("2013504", protection.DISABLE_CONF.read_text())
        protection.unmute(2013504)
        self.assertEqual(protection.muted_signatures(), [])

    def test_unmuting_something_that_was_not_muted_is_an_error(self):
        with self.assertRaises(KeyError):
            protection.unmute(2013504)

    def test_a_failed_rebuild_keeps_the_choice_but_not_the_applied_flag(self):
        self.rebuild.return_value = (False, "boom")
        ok, _ = protection.mute(2013504)
        self.assertFalse(ok)
        state = protection.load_state()
        self.assertIn("2013504", state["muted"])
        self.assertFalse(state["applied"])

    def test_apply_selection_saves_before_it_rebuilds(self):
        self.rebuild.return_value = (False, "boom")
        protection.apply_selection({"info": False})
        self.assertFalse(protection.load_state()["categories"]["info"])


SURICATA_UPDATE_PROBE = r"""
import sys
from suricata.update import main, matchers, rule
drop_conf, rules = sys.argv[1], sys.argv[2]
with open(drop_conf) as handle:
    filters = [matchers.DropRuleFilter(m) for m in main.parse_matchers(handle)]
for line in open(rules):
    parsed = rule.parse(line)
    if parsed is None:
        continue
    for fltr in filters:
        if fltr.match(parsed):
            parsed = fltr.run(parsed)
    print(parsed.sid, parsed.action, int(parsed.enabled))
"""


SURICATA_UPDATE_BUILD = r"""
import sys
from suricata.update import main, matchers, rule
drop_conf, rules, merged = sys.argv[1], sys.argv[2], sys.argv[3]
with open(drop_conf) as handle:
    filters = [matchers.DropRuleFilter(m) for m in main.parse_matchers(handle)]
rulemap = {}
for line in open(rules):
    parsed = rule.parse(line)
    if parsed is None:
        continue
    for fltr in filters:
        if fltr.match(parsed):
            parsed = fltr.run(parsed)
    rulemap[parsed.id] = parsed
# The step after the drop filter in suricata-update's own order.
main.resolve_flowbits(rulemap, [])
with open(merged, "w") as out:
    for parsed in rulemap.values():
        out.write(parsed.format() + "\n")
"""


class BlockingPolicyTest(BackendTestCase):
    """The policy read by the tool that applies it, not by a copy of its rules.

    suricata-update from the Debian package parses the drop.conf this panel
    writes and runs its own drop filter over a sample of the real rule shapes.
    What is checked is the action each rule comes out with.
    """

    RULES = (
        'alert tcp any any -> any any (msg:"ET MALWARE Bad Thing"; sid:2000001; rev:1;)\n'
        'alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; '
        'content:"uid=0|28|root|29|"; sid:2100498; rev:8;)\n'
        'alert udp any any -> any 53 (msg:"ET INFO DNS Query"; sid:2000002; rev:1;)\n'
        'alert tcp any any -> any any (msg:"ET HUNTING Odd"; sid:2000003; rev:1;)\n'
        'alert tcp any any -> any any (msg:"SURICATA STREAM ESTABLISHED invalid ack"; '
        'stream-event:est_invalid_ack; sid:2210029; rev:2;)\n'
        'alert tcp any any -> any 3389 (msg:"ET DOS RDP Flowbit Set"; flags:SA; '
        'flowbits:set,ms.rdp.synack; flowbits:noalert; sid:2014385; rev:6;)\n'
        'alert tcp any any -> any any (msg:"ET REMOTE_ACCESS AnyDesk Domain"; sid:2013031; rev:3;)\n'
        'alert tcp any any -> any any (msg:"ET NOSUCHGROUP Whatever"; sid:2999999; rev:1;)\n'
        'alert tcp any any -> any any (msg:"ET INFORMATIONAL Not the advisory group"; '
        'sid:2999998; rev:1;)\n'
        '# alert tcp any any -> any any (msg:"ET MALWARE Switched Off"; sid:2000004; rev:1;)\n'
    )

    def setUp(self):
        super().setUp()
        probe = subprocess.run(["/usr/bin/python3", "-c", "import suricata.update.main"],
                               capture_output=True)
        if probe.returncode != 0:
            self.skipTest("suricata-update is not installed")
        self.rules = self.tmp / "sample.rules"
        self.rules.write_text(self.RULES)
        protection.STATE_PATH.unlink(missing_ok=True)
        self.addCleanup(protection.STATE_PATH.unlink, True)
        self.addCleanup(protection.DROP_CONF.unlink, True)

    def actions(self, allowed=None):
        state = protection.load_state()
        state["allowed"] = allowed or {}
        conf = protection.write_drop_conf(state)
        proc = subprocess.run(["/usr/bin/python3", "-c", SURICATA_UPDATE_PROBE,
                               str(conf), str(self.rules)],
                              capture_output=True, text=True, check=True)
        return {int(sid): (action, enabled == "1") for sid, action, enabled in
                (line.split() for line in proc.stdout.splitlines())}

    def test_what_an_enabled_category_loads_is_a_drop(self):
        actions = self.actions()
        for sid in (2000001, 2100498, 2013031):
            self.assertEqual(actions[sid][0], "drop", sid)

    def test_a_signature_in_no_category_drops_too(self):
        # The residual bucket. A line per category would have left it alerting.
        self.assertEqual(self.actions()[2999999][0], "drop")

    def test_the_advisory_category_and_the_engine_events_only_alert(self):
        actions = self.actions()
        for sid in (2000002, 2000003, 2210029):
            self.assertEqual(actions[sid][0], "alert", sid)

    def test_a_group_that_only_starts_like_an_advisory_one_still_drops(self):
        # "ET INFO" must not reach "ET INFORMATIONAL".
        self.assertEqual(self.actions()[2999998][0], "drop")

    def test_a_rule_that_only_sets_a_flag_is_never_dropped(self):
        """RDP Syn/Ack Flowbit Set, loaded as drop, stops every RDP connection.

        And says nothing, because it is noalert. The gateway keeps all 315 of
        these as alerts, and suricata-update does the same on its own.
        """
        self.assertEqual(self.actions()[2014385][0], "alert")

    def test_an_allowed_signature_alerts_and_every_other_still_drops(self):
        actions = self.actions({"2013031": "ET REMOTE_ACCESS AnyDesk Domain",
                                "2100498": "GPL ATTACK_RESPONSE id check"})
        self.assertEqual(actions[2013031][0], "alert")
        self.assertEqual(actions[2100498][0], "alert")
        self.assertEqual(actions[2000001][0], "drop")

    def test_an_allowed_sid_does_not_reach_a_longer_one(self):
        actions = self.actions({"200000": "a prefix of 2000001"})
        self.assertEqual(actions[2000001][0], "drop")

    def build(self):
        """drop.conf, then the merge suricata-update does, into the rule file."""
        merged = config.SURICATA_RULES_DIR / "suricata.rules"
        merged.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["/usr/bin/python3", "-c", SURICATA_UPDATE_BUILD,
                        str(protection.write_drop_conf()), str(self.rules), str(merged)],
                       capture_output=True, text=True, check=True)
        protection._scan_cache = None
        return {protection._sid_of(line.encode()): line
                for line in merged.read_text().splitlines() if line.strip()}

    def test_a_rule_enabled_only_for_a_flowbit_is_never_a_silent_drop(self):
        """What the first rebuild with the policy did to 125 rules here.

        ET ships the rule that sets the flowbit disabled. suricata-update turns
        it into a drop, then switches it on for the rule that checks the bit,
        and marks it noalert: a packet stopped with no alert to find or allow.
        """
        self.rules.write_text(
            '# alert http any any -> any any (msg:"ET EXPLOIT_KIT Landing"; '
            'flowbits:set,et.ek; sid:2000010; rev:1;)\n'
            'alert http any any -> any any (msg:"ET EXPLOIT_KIT Payload"; '
            'flowbits:isset,et.ek; sid:2000011; rev:1;)\n')
        self.enterContext(patch.object(config, "SURICATA_RULES_DIR", self.tmp / "merged"))
        first = self.build()
        # The failure, as the tool produces it with the policy alone.
        self.assertTrue(first[2000010].startswith("drop "), first[2000010])
        self.assertIn("noalert", first[2000010])

        state = protection.load_state()
        self.assertTrue(protection.record_silent_drops(state))
        protection.save_state(state)
        second = self.build()
        self.assertTrue(second[2000010].startswith("alert "), second[2000010])
        self.assertTrue(second[2000011].startswith("drop "), second[2000011])
        self.assertEqual(protection.scan_rules(force=True).silent_drops, frozenset())

    def test_a_rule_back_from_a_mute_blocks_again(self):
        """Mute a rule another rule needs a flowbit from, rebuild, unmute.

        While muted, suricata-update brings it back for the flowbit as a silent
        drop, and the panel keeps its SID out of the policy. Unmuted, it is an
        ordinary rule again, and the SID must not keep it from blocking.
        """
        self.enterContext(patch.object(config, "SURICATA_RULES_DIR", self.tmp / "merged"))
        setter = ('alert http any any -> any any (msg:"ET MALWARE Setter"; '
                  'flowbits:set,et.x; sid:2000020; rev:1;)\n')
        checker = ('alert http any any -> any any (msg:"ET MALWARE Checker"; '
                   'flowbits:isset,et.x; sid:2000021; rev:1;)\n')

        self.rules.write_text("# " + setter + checker)      # muted
        self.build()
        state = protection.load_state()
        protection.record_silent_drops(state)
        self.assertIn("2000020", state["flowbit_only"])

        self.rules.write_text(setter + checker)             # unmuted
        self.build()
        state = protection.load_state()
        self.assertTrue(protection.record_silent_drops(state))
        self.assertNotIn("2000020", state["flowbit_only"])
        merged = self.build()
        self.assertTrue(merged[2000020].startswith("drop "), merged[2000020])
        self.assertNotIn("noalert", merged[2000020])
        self.assertEqual(protection.scan_rules(force=True).blocking_pending, 0)

    def test_a_switched_off_rule_stays_switched_off(self):
        self.assertEqual(self.actions()[2000004], ("drop", False))


class AllowTest(BackendTestCase):
    RULES = (b'alert tcp any any -> any any (msg:"ET MALWARE One"; sid:2000001; rev:1;)\n'
             b'alert tcp any any -> any any (msg:"ET MALWARE Two"; sid:2000002; rev:1;)\n'
             b'alert tcp any any -> any any (msg:"ET INFO Three"; sid:2000003; rev:1;)\n'
             b'alert tcp any any -> any any (msg:"SURICATA STREAM x"; sid:2210029; rev:1;)\n'
             b'alert tcp any any -> any any (msg:"ET MALWARE Flag"; flowbits:noalert; '
             b'sid:2000005; rev:1;)\n'
             b'# alert tcp any any -> any any (msg:"ET MALWARE Off"; sid:2000006; rev:1;)\n'
             b'drop tcp any any -> any any (msg:"ET MALWARE Four"; sid:2000004; rev:1;)\n')

    def setUp(self):
        super().setUp()
        self.rules_dir = self.tmp / "rules"
        self.rules_dir.mkdir()
        (self.rules_dir / "suricata.rules").write_bytes(self.RULES)
        self.enterContext(patch.object(config, "SURICATA_RULES_DIR", self.rules_dir))
        self.rebuild = self.enterContext(
            patch.object(protection, "rebuild", return_value=(True, "ok")))
        protection.STATE_PATH.unlink(missing_ok=True)
        self.addCleanup(protection.STATE_PATH.unlink, True)
        protection._scan_cache = None
        self.addCleanup(setattr, protection, "_scan_cache", None)

    def test_allow_then_block_again(self):
        protection.allow(2000001)
        self.assertEqual(protection.allowed_signatures(),
                         [{"signature_id": 2000001, "signature": "ET MALWARE One"}])
        self.assertIn(protection.blocking_pattern({"2000001": ""}),
                      protection.DROP_CONF.read_text().splitlines())
        self.rebuild.assert_called_once()
        protection.unallow(2000001)
        self.assertEqual(protection.allowed_signatures(), [])
        self.assertIn(protection.blocking_pattern({}),
                      protection.DROP_CONF.read_text().splitlines())

    def test_blocking_again_something_never_allowed_is_an_error(self):
        with self.assertRaises(KeyError):
            protection.unallow(2000001)

    def test_a_failed_rebuild_keeps_the_choice_but_not_the_applied_flag(self):
        self.rebuild.return_value = (False, "boom")
        ok, _ = protection.allow(2000001)
        self.assertFalse(ok)
        state = protection.load_state()
        self.assertIn("2000001", state["allowed"])
        self.assertFalse(state["applied"])

    def test_only_rules_the_policy_would_drop_count_as_pending(self):
        # Two malware alerts. Not the advisory one, not the engine event, not
        # the flag setter, not the switched-off rule, not the one already a drop.
        self.assertEqual(protection.scan_rules(force=True).blocking_pending, 2)

    def test_an_allowed_signature_is_not_pending_and_the_cache_knows_it(self):
        self.assertEqual(protection.scan_rules().blocking_pending, 2)
        protection.allow(2000002)
        # The rule file did not change, only the state did.
        self.assertEqual(protection.scan_rules().blocking_pending, 1)

    def test_rebuilding_from_the_state_writes_the_policy_first(self):
        protection.DROP_CONF.unlink(missing_ok=True)
        ok, _ = protection.rebuild_from_state()
        self.assertTrue(ok)
        self.assertIn(protection.blocking_pattern({}),
                      protection.DROP_CONF.read_text().splitlines())
        self.assertTrue(protection.load_state()["applied"])

    def test_a_silent_drop_counts_as_pending_and_is_named(self):
        (self.rules_dir / "suricata.rules").write_bytes(
            self.RULES + b'drop http any any -> any any (msg:"ET EXPLOIT_KIT Landing"; '
                         b'flowbits:set,et.ek; noalert; sid:2000010; rev:1;)\n')
        scan = protection.scan_rules(force=True)
        self.assertEqual(scan.silent_drops, frozenset({2000010}))
        self.assertEqual(scan.blocking_pending, 3)

    def _silent_after_rebuild(self, rounds):
        """A rebuild that writes silent drops for the first `rounds` calls."""
        rules = self.rules_dir / "suricata.rules"
        calls = []

        def rebuild(offline=True):
            calls.append(protection.DROP_CONF.read_text())
            tail = (b'drop http any any -> any any (msg:"ET EXPLOIT_KIT Landing"; '
                    b'flowbits:set,et.ek; noalert; sid:2000010; rev:1;)\n'
                    if len(calls) <= rounds else
                    b'alert http any any -> any any (msg:"ET EXPLOIT_KIT Landing"; '
                    b'flowbits:set,et.ek; noalert; sid:2000010; rev:1;)\n')
            rules.write_bytes(self.RULES + tail)
            return True, f"pass {len(calls)}"

        self.rebuild.side_effect = rebuild
        return calls

    def test_a_rebuild_that_writes_a_silent_drop_is_followed_by_one_that_does_not(self):
        calls = self._silent_after_rebuild(rounds=1)
        ok, output = protection.rebuild_from_state()
        self.assertTrue(ok)
        self.assertEqual(len(calls), 2)
        self.assertNotIn("2000010", calls[0])
        self.assertIn("2000010", calls[1])
        self.assertEqual(protection.load_state()["flowbit_only"], {"2000010": ""})
        self.assertIn("pass 2", output)

    def test_every_rebuild_path_keeps_silent_drops_out(self):
        for name, action in (("categories", lambda: protection.apply_selection({})),
                             ("allow", lambda: protection.allow(2000001)),
                             ("mute", lambda: protection.mute(2000002))):
            with self.subTest(name):
                protection.STATE_PATH.unlink(missing_ok=True)
                calls = self._silent_after_rebuild(rounds=1)
                action()
                self.assertEqual(len(calls), 2)

    def test_once_recorded_a_rebuild_needs_no_second_pass(self):
        state = protection.load_state()
        state["flowbit_only"] = {"2000010": ""}
        protection.save_state(state)
        calls = self._silent_after_rebuild(rounds=0)
        protection.rebuild_from_state()
        self.assertEqual(len(calls), 1)

    def test_a_recorded_rule_is_never_forgotten(self):
        # Gone from the list, the next rebuild would turn it into a drop again.
        # Last night's rebuild left no silent drop, because the rule is kept out.
        state = protection.load_state()
        state["flowbit_only"] = {"2000010": ""}
        protection.save_state(state)
        self._silent_after_rebuild(rounds=0)
        protection.rebuild_from_state()
        self.assertEqual(protection.load_state()["flowbit_only"], {"2000010": ""})
        self.assertIn(protection.blocking_pattern(["2000010"]),
                      protection.DROP_CONF.read_text().splitlines())

    def test_the_start_of_the_panel_records_last_nights_silent_drops(self):
        (self.rules_dir / "suricata.rules").write_bytes(
            self.RULES + b'drop http any any -> any any (msg:"ET EXPLOIT_KIT Landing"; '
                         b'flowbits:set,et.ek; noalert; sid:2000010; rev:1;)\n')
        protection.refresh_drop_conf()
        self.assertEqual(protection.load_state()["flowbit_only"], {"2000010": ""})
        self.assertIn(protection.blocking_pattern(["2000010"]),
                      protection.DROP_CONF.read_text().splitlines())
        self.rebuild.assert_not_called()

    def test_a_helper_back_as_an_ordinary_alert_leaves_the_list(self):
        state = protection.load_state()
        state["flowbit_only"] = {"2000001": "", "2000005": "", "2000006": ""}
        protection.save_state(state)
        # 2000001 is an ordinary enabled alert in the file, 2000005 still a
        # noalert helper, 2000006 switched off.
        self.assertTrue(protection.record_silent_drops(protection.load_state()))
        self.assertEqual(protection.load_state()["flowbit_only"],
                         {"2000005": "", "2000006": ""})

    def test_the_warning_clears_once_a_recovered_helper_blocks_again(self):
        """Kept out by SID for good, the rule counted as pending for good.

        The screen said "rebuilds on its own within ten minutes" forever, and
        the panel rebuilt and reloaded after every change to the file.
        """
        rules = self.rules_dir / "suricata.rules"
        rules.write_bytes(b'alert tcp any any -> any any (msg:"ET MALWARE One"; '
                          b'sid:2000001; rev:1;)\n')
        state = protection.load_state()
        state["flowbit_only"] = {"2000001": ""}
        protection.save_state(state)
        protection._scan_cache = None

        def rebuild(offline=True):
            excluded = "2000001" in protection.DROP_CONF.read_text()
            action = b"alert" if excluded else b"drop"
            rules.write_bytes(action + b' tcp any any -> any any (msg:"ET MALWARE One"; '
                                       b'sid:2000001; rev:1;)\n')
            return True, "ok"

        self.rebuild.side_effect = rebuild
        protection.rebuild_from_state()
        self.assertEqual(protection.scan_rules(force=True).blocking_pending, 0)
        self.assertNotIn("2000001", protection.load_state()["flowbit_only"])

    def test_the_second_pass_uses_the_cache_a_download_just_filled(self):
        calls = []
        rules = self.rules_dir / "suricata.rules"

        def rebuild(offline=True):
            calls.append(offline)
            if len(calls) == 1:
                rules.write_bytes(self.RULES + b'drop http any any -> any any '
                                  b'(msg:"ET EXPLOIT_KIT L"; noalert; sid:2000010; rev:1;)\n')
            return True, "ok"

        self.rebuild.side_effect = rebuild
        protection.rebuild_from_state(offline=False)
        self.assertEqual(calls, [False, True])

    def test_a_rebuild_waits_for_the_one_in_progress(self):
        import threading
        order = []
        started = threading.Event()
        release = threading.Event()

        def rebuild(offline=True):
            order.append("start")
            started.set()
            release.wait(5)
            order.append("end")
            return True, "ok"

        self.rebuild.side_effect = rebuild
        first = threading.Thread(target=protection.rebuild_from_state)
        first.start()
        started.wait(5)
        second = threading.Thread(target=protection.rebuild_from_state)
        second.start()
        second.join(0.3)
        release.set()
        first.join(5)
        second.join(5)
        self.assertEqual(order, ["start", "end", "start", "end"])

    def _download_in_progress(self, later):
        """A long rebuild holding the lock, and `later` run while it does.

        `later` is started once the download has begun and given half a second
        to get as far as it can before the download finishes.
        """
        import threading
        started, release = threading.Event(), threading.Event()
        calls = []

        def rebuild(offline=True):
            calls.append(offline)
            if len(calls) == 1:
                started.set()
                release.wait(5)
                return True, "downloaded"
            return self.later_result

        self.rebuild.side_effect = rebuild
        update = threading.Thread(target=protection.rebuild_from_state, kwargs={"offline": False})
        update.start()
        started.wait(5)
        waiting = [threading.Thread(target=fn) for fn in later]
        for thread in waiting:
            thread.start()
        for thread in waiting:
            thread.join(0.5)
        release.set()
        update.join(5)
        for thread in waiting:
            thread.join(5)

    def test_a_mute_made_during_a_download_is_not_overwritten_by_it(self):
        """The download read the state before it waited for nothing, and saved
        that old copy when it finished. A mute whose own rebuild then failed
        was gone from the state, and from the next disable.conf."""
        self.later_result = (False, "boom")
        self._download_in_progress([lambda: protection.mute(2000001)])
        self.assertIn("2000001", protection.load_state()["muted"])

    def test_two_changes_made_during_a_download_both_survive(self):
        self.later_result = (True, "ok")
        self._download_in_progress([lambda: protection.mute(2000001),
                                    lambda: protection.allow(2000002)])
        state = protection.load_state()
        self.assertIn("2000001", state["muted"])
        self.assertIn("2000002", state["allowed"])

    def test_a_rebuild_does_not_act_on_state_read_before_it_had_the_lock(self):
        """The narrow order: the rebuild reads, a mute takes the lock first.

        A rebuild that read the state before waiting for the lock wrote
        disable.conf and the state from that copy once it got in, after the
        mute had finished, and the mute was gone from both.
        """
        import threading
        read, go = threading.Event(), threading.Event()
        real_load = protection.load_state

        def load_state():
            state = real_load()
            if threading.current_thread().name == "update" and not read.is_set():
                # Read, and held here, before the rebuild has done anything else.
                read.set()
                go.wait(1)
            return state

        self.enterContext(patch.object(protection, "load_state", side_effect=load_state))
        confs = []
        self.rebuild.side_effect = lambda offline=True: (
            confs.append(protection.DISABLE_CONF.read_text()) or (True, "ok"))
        update = threading.Thread(target=protection.rebuild_from_state, name="update")
        update.start()
        read.wait(5)
        muting = threading.Thread(target=protection.mute, args=(2000001,))
        muting.start()
        muting.join(0.5)
        go.set()
        update.join(5)
        muting.join(5)
        self.assertIn("2000001", confs[-1])
        self.assertIn("2000001", real_load()["muted"])

    def test_the_screen_lists_what_is_allowed(self):
        protection.allow(2000001)
        self.assertEqual(protection.snapshot()["allowed"],
                         [{"signature_id": 2000001, "signature": "ET MALWARE One"}])

    def test_the_screen_is_told_which_categories_never_block(self):
        flags = {c["id"]: c["alert_only"] for c in protection.snapshot()["categories"]}
        self.assertTrue(flags["info"])
        self.assertFalse(flags["malware"])


class ModeTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.yaml = self.tmp / "suricata.yaml"
        self.enterContext(patch.object(protection, "SURICATA_YAML", self.yaml))
        self.enterContext(patch.object(protection, "_suricata_cmdline", return_value=""))

    def test_af_packet_interfaces_are_listed_without_the_template(self):
        self.yaml.write_text(
            "af-packet:\n"
            "  - interface: eth0\n"
            "    cluster-id: 99\n"
            "  - interface: default\n"
            "    cluster-type: cluster_flow\n"
            "app-layer:\n"
            "  protocols:\n"
            "    - interface: not-this-one\n"
        )
        mode = protection.mode_info()
        self.assertEqual(mode["interfaces"], ["eth0"])
        self.assertEqual(mode["id"], "ids")
        self.assertFalse(mode["can_block"])

    def test_copy_mode_ips_means_blocking(self):
        self.yaml.write_text("af-packet:\n  - interface: eth0\n    copy-mode: ips\n")
        mode = protection.mode_info()
        self.assertEqual(mode["id"], "ips")
        self.assertTrue(mode["can_block"])

    def test_nfqueue_on_the_command_line_means_blocking(self):
        self.yaml.write_text("af-packet:\n  - interface: eth0\n")
        with patch.object(protection, "_suricata_cmdline",
                          return_value="/usr/bin/suricata -q 0 -c /etc/suricata/suricata.yaml"):
            mode = protection.mode_info()
        self.assertEqual(mode["capture"], "nfqueue")
        self.assertTrue(mode["can_block"])

    def test_a_missing_file_is_detection_only(self):
        self.assertEqual(protection.mode_info()["id"], "ids")

    # --- the include chain ------------------------------------------------
    #
    # The panel writes its own af-packet block into a file it includes, and
    # include does not merge: a key defined lower down replaces the one above.
    # Checked against the engine, not assumed: suricata --dump-config on a yaml
    # that says eth0 and includes a file that says eth1 answers eth1.
    #
    # Reading only the packaged file meant the panel named the interface the
    # engine had stopped using the moment the wizard applied anything, which is
    # what the "no traffic is reaching the engine" banner watches.

    def _with_include(self, included: str, name: str = "rapi-capture.yaml") -> None:
        self.yaml.write_text(
            "af-packet:\n"
            "  - interface: eth0\n"
            "    cluster-id: 99\n"
            "include:\n"
            f"  - {name}\n"
        )
        (self.tmp / name).write_text(included)

    def test_an_included_file_replaces_the_capture_block(self):
        self._with_include("af-packet:\n  - interface: eth1\n    cluster-id: 99\n")
        self.assertEqual(protection.mode_info()["interfaces"], ["eth1"])

    def test_an_absolute_include_is_followed_too(self):
        other = self.tmp / "elsewhere.yaml"
        other.write_text("af-packet:\n  - interface: eth2\n")
        self.yaml.write_text(
            "af-packet:\n  - interface: eth0\n"
            f"include:\n  - {other}\n"
        )
        self.assertEqual(protection.mode_info()["interfaces"], ["eth2"])

    def test_an_include_that_says_nothing_about_capture_changes_nothing(self):
        # Four of the five files the panel includes never mention af-packet.
        # Treating "included" as "replaces" would have blanked the interface.
        self._with_include("vars:\n  address-groups:\n    HOME_NET: \"[10.0.0.0/8]\"\n",
                           name="rapi-home-net.yaml")
        self.assertEqual(protection.mode_info()["interfaces"], ["eth0"])

    def test_a_single_line_include_is_followed_too(self):
        """rapi-include keeps a site's own `include: file` next to its block.

        An af-packet key in one of those was invisible, and the panel named the
        wrong capture interface again.
        """
        (self.tmp / "site.yaml").write_text("af-packet:\n  - interface: eth3\n")
        self.yaml.write_text(
            "af-packet:\n  - interface: eth0\n"
            "include: site.yaml\n"
        )
        self.assertEqual(protection.mode_info()["interfaces"], ["eth3"])

    def test_an_include_inside_an_included_file_is_followed(self):
        (self.tmp / "outer.yaml").write_text("include:\n  - inner.yaml\n")
        (self.tmp / "inner.yaml").write_text("af-packet:\n  - interface: eth4\n")
        self.yaml.write_text("af-packet:\n  - interface: eth0\ninclude:\n  - outer.yaml\n")
        self.assertEqual(protection.mode_info()["interfaces"], ["eth4"])

    def test_files_that_include_each_other_do_not_recurse_forever(self):
        (self.tmp / "a.yaml").write_text("include:\n  - b.yaml\n")
        (self.tmp / "b.yaml").write_text("include:\n  - a.yaml\naf-packet:\n  - interface: eth5\n")
        self.yaml.write_text("include:\n  - a.yaml\n")
        self.assertEqual(protection.mode_info()["interfaces"], ["eth5"])

    def test_the_last_definition_wins(self):
        self.yaml.write_text(
            "af-packet:\n  - interface: eth0\n"
            "include:\n  - first.yaml\n  - second.yaml\n"
        )
        (self.tmp / "first.yaml").write_text("af-packet:\n  - interface: eth1\n")
        (self.tmp / "second.yaml").write_text("af-packet:\n  - interface: br-rapi\n")
        self.assertEqual(protection.mode_info()["interfaces"], ["br-rapi"])

    def test_a_missing_included_file_leaves_what_is_known(self):
        self._with_include("af-packet:\n  - interface: eth1\n")
        (self.tmp / "rapi-capture.yaml").unlink()
        self.assertEqual(protection.mode_info()["interfaces"], ["eth0"])

    def test_copy_mode_is_read_from_the_file_that_defines_the_block(self):
        self._with_include("af-packet:\n  - interface: eth1\n    copy-mode: ips\n")
        mode = protection.mode_info()
        self.assertEqual(mode["interfaces"], ["eth1"])
        self.assertEqual(mode["id"], "ips")


class CatchUpBeforeBlockingTest(BackendTestCase):
    """Turning blocking on rebuilds a rule set that lags the policy, first.

    The operator used to be sent to a second button, and the first one they
    found reloaded the same file and changed nothing.
    """

    def setUp(self):
        super().setUp()
        self.calls = []
        self.pending = 0
        self.rebuilt = (True, "ok")
        self.enterContext(patch.object(
            protection, "scan_rules",
            side_effect=lambda *a, **k: protection.RuleScan(blocking_pending=self.pending)))
        self.enterContext(patch.object(
            protection, "rebuild_from_state",
            side_effect=lambda *a, **k: self.calls.append("rebuild") or self.rebuilt))
        self.enterContext(patch.object(
            protection, "_run_ips_mode",
            side_effect=lambda word: self.calls.append(f"queue {word}") or (True, "ok")))
        self.enterContext(patch.object(
            network_capture, "set_inline_blocking",
            side_effect=lambda block: self.calls.append(f"inline {block}") or (True, "ok")))

    def _inline(self, inline):
        self.enterContext(patch.object(protection, "_inline_layout",
                                       return_value=["eth0", "eth1"] if inline else []))

    def test_a_lagging_rule_set_is_rebuilt_before_the_switch(self):
        for inline, switch in ((True, "inline True"), (False, "queue ips")):
            with self.subTest(inline=inline):
                self.calls.clear()
                self.pending = 45262
                with patch.object(protection, "_inline_layout",
                                  return_value=["eth0", "eth1"] if inline else []):
                    ok, _ = protection.set_mode(True)
                self.assertTrue(ok)
                self.assertEqual(self.calls, ["rebuild", switch])

    def test_a_rule_set_that_follows_the_policy_is_left_alone(self):
        self._inline(True)
        protection.set_mode(True)
        self.assertEqual(self.calls, ["inline True"])

    def test_going_back_to_detection_never_rebuilds(self):
        # Alerts and drops behave alike on an engine reading a copy.
        self._inline(True)
        self.pending = 45262
        protection.set_mode(False)
        self.assertEqual(self.calls, ["inline False"])

    def test_a_rebuild_that_fails_leaves_the_link_as_it_was(self):
        self._inline(True)
        self.pending = 45262
        self.rebuilt = (False, "error: the source has not yet been downloaded")
        ok, output = protection.set_mode(True)
        self.assertFalse(ok)
        self.assertEqual(self.calls, ["rebuild"])
        self.assertIn("blocking was not switched on", output)
        self.assertIn("has not yet been downloaded", output)


class ModeMechanismTest(BackendTestCase):
    """Which mechanism "Detection and blocking" means, which the layout decides.

    On a host the Pi is, NFQUEUE on its own input and output is what there is,
    and it protects this device rather than the network it watches. On a layout
    the traffic crosses, NFQUEUE cannot work at all: its rules hang on the IP
    forward hook and bridged frames never reach it without br_netfilter. There
    blocking means handing the forwarding to the engine.

    One switch, two mechanisms, and picking the wrong one is a panel that
    reports blocking and stops nothing.
    """

    def setUp(self):
        super().setUp()
        self.helper = self.enterContext(
            patch.object(protection.subprocess, "run"))
        self.helper.return_value.returncode = 0
        self.helper.return_value.stdout = "ok"
        self.helper.return_value.stderr = ""

    def _inline(self):
        # In effect: applied, with the home networks the swap rewrites.
        settings.set(network_topology.SETTINGS_KEY, {
            "profile": "bridge",
            "roles": {"bridge_a": "eth0", "bridge_b": "eth1", "management": "wlan0"},
            "home_net": "[10.10.0.0/16]", "applied": True,
        })

    def test_the_sentence_on_the_screen_matches_the_mechanism(self):
        """The one line an operator reads before accepting the outage risk.

        Netfilter with bypass lets traffic past when the engine stops. An
        engine that is doing the forwarding takes the link with it. Printing the
        first on a device doing the second tells them the exact opposite of what
        they are agreeing to.
        """
        self._inline()
        with patch.object(protection, "_yaml_capture", return_value={
                "interfaces": ["eth0", "eth1"], "copy_mode_ips": True,
                "nfqueue": False, "cmdline": ""}):
            reason = protection.mode_info()["reason"]
        self.assertIn("nothing crosses this link", reason)
        self.assertNotIn("netfilter lets the traffic past", reason)

    def test_a_queue_on_a_bridged_layout_is_named_as_the_dead_end_it_is(self):
        """Cabled inline and still carrying the drop-in.

        An upgrade with blocking already on, or a swap that failed halfway. The
        rules are on the IP forward hook, bridged frames never reach it, and
        every other thing on the screen says blocking. Nothing is inspected and
        nothing is stopped, which is the failure that looks most like success.
        """
        self._inline()
        with patch.object(protection, "_yaml_capture", return_value={
                "interfaces": ["br-rapi"], "copy_mode_ips": False,
                "nfqueue": True, "cmdline": "-q 0"}):
            reason = protection.mode_info()["reason"]
        self.assertIn("never reach it", reason)
        self.assertIn("nothing is being blocked", reason)
        self.assertNotIn("can drop it", reason)

    def test_the_queue_sentence_survives_where_the_queue_is_what_runs(self):
        # On "self". On a mirror the queue runs and sees nothing of the network,
        # which has its own sentence (test_a_mirror_already_on_the_queue_...).
        settings.set(network_topology.SETTINGS_KEY,
                     {"profile": "self", "applied": True, "roles": {"capture": "eth0"}})
        with patch.object(protection, "_yaml_capture", return_value={
                "interfaces": ["eth0"], "copy_mode_ips": False,
                "nfqueue": True, "cmdline": "-q 0"}):
            reason = protection.mode_info()["reason"]
        self.assertIn("netfilter lets the traffic past", reason)

    def test_an_inline_layout_can_switch_without_the_queue_helper(self):
        # The helper owns the queue and the inline swap never goes through it,
        # so an image missing it can still turn blocking on where it is real.
        self._inline()
        with patch.object(protection.Path, "exists", return_value=False):
            self.assertTrue(protection.mode_info()["can_switch"])

    def test_the_screen_is_told_which_mechanism_applies(self):
        # The confirmation before the switch describes a different operation in
        # the two cases, so the answer has to reach the screen rather than be
        # guessed there.
        self._inline()
        self.assertTrue(protection.mode_info()["inline"])
        settings.set(network_topology.SETTINGS_KEY,
                     {"profile": "mirror", "roles": {"capture": "eth0"}})
        self.assertFalse(protection.mode_info()["inline"])

    def test_a_host_layout_uses_the_queue(self):
        # "self": the engine watches this Pi's own traffic, which is exactly
        # what the queue holds. This used to be "mirror", where the queue
        # blinds the engine instead; see test_a_mirror_refuses_blocking_...
        settings.set(network_topology.SETTINGS_KEY,
                     {"profile": "self", "applied": True, "roles": {"capture": "eth0"}})
        ok, _ = protection.set_mode(True)
        self.assertTrue(ok)
        self.assertEqual(self.helper.call_args.args[0][:3],
                         ["sudo", "-n", protection.IPS_MODE_BIN])

    def test_an_inline_layout_blocks_by_swapping_the_forwarding(self):
        self._inline()
        with patch.object(network_capture, "set_inline_blocking",
                          return_value=(True, "done")) as swap:
            ok, output = protection.set_mode(True)
        self.assertTrue(ok)
        self.assertEqual(output, "done")
        swap.assert_called_once_with(True)

    def test_going_back_to_watching_takes_the_same_road(self):
        self._inline()
        with patch.object(network_capture, "set_inline_blocking",
                          return_value=(True, "done")) as swap:
            protection.set_mode(False)
        swap.assert_called_once_with(False)

    def test_an_inline_layout_never_asks_the_queue_helper_anything(self):
        """The swap helper clears the queue itself, without a restart.

        Asked from here, `ids` cost a restart of its own that on the way back
        landed while the engine was still forwarding, and a `status` that
        failed was read as nothing to clear, so the swap ran on top of a drop-in
        that makes the engine ignore its new configuration.
        """
        self._inline()
        for block in (True, False):
            with self.subTest(block=block), \
                 patch.object(network_capture, "set_inline_blocking",
                              return_value=(True, "done")):
                protection.set_mode(block)
        self.helper.assert_not_called()

    def test_a_layout_only_chosen_refuses_blocking(self):
        # Not in effect yet, so nothing inline to swap, and the panel cannot
        # tell which layout the engine is still running. This used to switch to
        # the queue anyway, which on a device still reading a mirror port
        # blinded the engine. Refused, with the way out named.
        settings.set(network_topology.SETTINGS_KEY, {
            "profile": "bridge", "applied": False, "home_net": "",
            "roles": {"bridge_a": "eth0", "bridge_b": "eth1", "management": "wlan0"},
        })
        with patch.object(network_capture, "set_inline_blocking") as swap, \
                self.assertRaises(protection.ModeRefused) as refused:
            protection.set_mode(True)
        swap.assert_not_called()
        self.helper.assert_not_called()
        self.assertIn("Apply the layout first", str(refused.exception))


class CaptureLinkTest(BackendTestCase):
    """What separates a quiet network from a deaf sensor.

    The engine reports itself as running either way and its counters simply stop
    moving, so this reads the kernel instead of the packet count.
    """

    def setUp(self):
        super().setUp()
        self.yaml = self.tmp / "suricata.yaml"
        self.sys_net = self.tmp / "class-net"
        self.sys_net.mkdir()
        self.enterContext(patch.object(protection, "SURICATA_YAML", self.yaml))
        self.enterContext(patch.object(protection, "SYS_NET", self.sys_net))
        self.enterContext(patch.object(protection, "_suricata_cmdline", return_value=""))
        self.yaml.write_text("af-packet:\n  - interface: eth0\n")

    def _iface(self, name: str, operstate: str = "up", carrier: str | None = "1",
               flags: str = "0x1103") -> None:
        path = self.sys_net / name
        path.mkdir(exist_ok=True)
        (path / "operstate").write_text(operstate + "\n")
        if carrier is not None:
            (path / "carrier").write_text(carrier + "\n")
        # As the kernel writes it: hex, with IFF_PROMISC (0x100) set by default
        # because that is what a working capture interface looks like.
        (path / "flags").write_text(flags + "\n")

    def test_promiscuous_mode_is_read_from_the_kernel(self):
        # A mirror port delivers frames addressed to other machines and nothing
        # else. Without this flag the kernel drops every one of them before the
        # engine is offered anything, which looks exactly like a quiet segment.
        self._iface("eth0")
        self.assertTrue(protection.capture_link()["interfaces"][0]["promisc"])

    def test_an_interface_out_of_promiscuous_mode_is_reported_as_such(self):
        self._iface("eth0", flags="0x1003")
        self.assertFalse(protection.capture_link()["interfaces"][0]["promisc"])

    def test_an_unreadable_flag_word_is_not_a_crash(self):
        self._iface("eth0", flags="not a number")
        self.assertFalse(protection.capture_link()["interfaces"][0]["promisc"])

    def test_a_missing_interface_still_answers_the_question(self):
        # The System page asks every row, including ones the kernel lost.
        link = protection.capture_link()["interfaces"][0]
        self.assertEqual((link["present"], link["promisc"]), (False, False))

    def test_a_working_interface_says_nothing(self):
        # Silence is the point. A banner that is always up is a banner nobody
        # reads on the day it matters.
        self._iface("eth0")
        link = protection.capture_link()
        self.assertEqual(link["state"], "ok")
        self.assertIsNone(link["problem"])
        self.assertTrue(link["interfaces"][0]["carrier"])

    def test_an_interface_that_is_down_is_the_bad_case(self):
        self._iface("eth0", operstate="down", carrier=None)
        link = protection.capture_link()
        self.assertEqual(link["state"], "bad")
        self.assertIn("eth0", link["problem"])
        self.assertIn("down", link["problem"])

    def test_the_carrier_file_the_kernel_refuses_to_answer(self):
        # Reading carrier on an interface that is administratively down fails
        # with EINVAL. That has to read as "no carrier", not as an exception.
        self._iface("eth0", operstate="down", carrier=None)
        self.assertFalse(protection.capture_link()["interfaces"][0]["carrier"])

    def test_no_cable_is_a_warning_and_not_a_failure(self):
        # The panel did its part here: the interface is up and prepared. What is
        # missing is at the other end of the cable, so the wording differs.
        self._iface("eth0", operstate="up", carrier="0")
        link = protection.capture_link()
        self.assertEqual(link["state"], "warn")
        self.assertIn("carrier", link["problem"])

    def test_an_interface_the_kernel_does_not_have(self):
        link = protection.capture_link()
        self.assertEqual(link["state"], "bad")
        self.assertFalse(link["interfaces"][0]["present"])
        self.assertIn("does not have", link["problem"])

    def test_nfqueue_has_no_link_to_have_an_opinion_about(self):
        # Blocking through netfilter takes packets from the firewall, not from
        # an interface. Judging a link there would invent a fault.
        self._iface("eth0", operstate="down", carrier=None)
        with patch.object(protection, "_suricata_cmdline",
                          return_value="/usr/bin/suricata -q 0"):
            link = protection.capture_link()
        self.assertEqual(link["state"], "ok")
        self.assertIsNone(link["problem"])

    def test_both_sides_of_a_bridge_are_named_in_one_sentence(self):
        self.yaml.write_text("af-packet:\n  - interface: eth0\n  - interface: eth1\n")
        self._iface("eth0", operstate="down", carrier=None)
        self._iface("eth1", operstate="down", carrier=None)
        self.assertIn("eth0 and eth1", protection.capture_link()["problem"])

    def test_a_missing_configuration_file_claims_nothing(self):
        self.yaml.unlink()
        link = protection.capture_link()
        self.assertEqual(link["state"], "ok")
        self.assertEqual(link["interfaces"], [])


class StartupDropConfTest(BackendTestCase):
    """The daily refresh reads drop.conf as it is on disk.

    A panel upgraded to the blocking policy kept rebuilding every night with
    the empty file the previous version wrote, until somebody happened to
    change a category.
    """

    def setUp(self):
        super().setUp()
        protection.DROP_CONF.write_text("# Generated by an older panel\n")
        self.addCleanup(protection.DROP_CONF.unlink, True)

    def test_the_panel_writes_the_policy_when_it_starts(self):
        from app import main
        main._refresh_drop_conf()
        self.assertIn(protection.blocking_pattern({}),
                      protection.DROP_CONF.read_text().splitlines())

    def test_it_happens_on_every_start(self):
        # Called from the lifespan, which starts the tailer and the notifier
        # and cannot be run from a test, so this reads the lifespan itself.
        import inspect
        from app import main
        self.assertIn("_refresh_drop_conf()", inspect.getsource(main.lifespan))

    def test_a_fresh_device_gets_a_disable_conf_on_first_start(self):
        """Without it the daily refresh exits 3 and a device never updates.

        Only a rebuild from the panel used to write it, so a device flashed
        without signatures (build with --no-rules, or a failed fetch) stayed
        without any: the timer refused, and the policy loop had no rule file.
        """
        from app import main
        protection.DISABLE_CONF.unlink(missing_ok=True)
        self.addCleanup(protection.DISABLE_CONF.unlink, True)
        main._refresh_drop_conf()
        self.assertTrue(protection.DISABLE_CONF.exists())
        # What the daily refresh itself demands before it runs.
        proc = run_helper("rapi-rules-update", str(protection.DISABLE_CONF),
                          str(protection.DROP_CONF),
                          path_prefix=self._suricata_update_stub())
        self.assertNotEqual(proc.returncode, 3, proc.stderr)

    def _suricata_update_stub(self):
        stub_dir = self.tmp / "stub-su"
        stub_dir.mkdir(exist_ok=True)
        for name in ("suricata-update", "suricatasc", "systemctl"):
            (stub_dir / name).write_text("#!/bin/sh\nexit 0\n")
            (stub_dir / name).chmod(0o755)
        return stub_dir

    def test_an_existing_disable_conf_is_never_rewritten_on_start(self):
        from app import main
        protection.DISABLE_CONF.write_text("# chosen on the screen\ngroup:emerging-games\n")
        self.addCleanup(protection.DISABLE_CONF.unlink, True)
        main._refresh_drop_conf()
        self.assertEqual(protection.DISABLE_CONF.read_text(),
                         "# chosen on the screen\ngroup:emerging-games\n")

    def test_a_file_it_cannot_write_does_not_stop_the_panel(self):
        from app import main
        # Logging is switched off for the suite, so the warning is read off the
        # logger call rather than captured.
        with patch.object(protection, "refresh_drop_conf", side_effect=PermissionError("ro")), \
                patch.object(main.log, "warning") as warning:
            main._refresh_drop_conf()
        self.assertIn("drop.conf could not be written", warning.call_args.args[0])


class KeepRulesOnPolicyTest(BackendTestCase):
    """The panel rebuilds a rule set that fell behind the policy on its own.

    It used to be a button on the screen, and the button somebody found first
    was the one that reloads the same file and changes nothing.
    """

    def setUp(self):
        super().setUp()
        self.rules_dir = self.tmp / "rules"
        self.rules_dir.mkdir()
        self.rules = self.rules_dir / "suricata.rules"
        self.rules.write_bytes(
            b'alert tcp any any -> any any (msg:"ET MALWARE One"; sid:2000001; rev:1;)\n')
        self.enterContext(patch.object(config, "SURICATA_RULES_DIR", self.rules_dir))
        self.enterContext(patch.object(protection, "_catch_up_tried", None))
        protection._scan_cache = None
        self.addCleanup(setattr, protection, "_scan_cache", None)
        self.rebuilt = True
        self.rebuild = self.enterContext(patch.object(
            protection, "rebuild_from_state", side_effect=self._rebuild))
        self.reload = self.enterContext(patch.object(
            protection, "reload_engine", return_value=(True, "ok")))

    def _rebuild(self, *a, **k):
        if self.rebuilt:
            self.rules.write_bytes(
                b'drop tcp any any -> any any (msg:"ET MALWARE One"; sid:2000001; rev:1;)\n')
        return self.rebuilt, "done" if self.rebuilt else "error: no cache"

    def test_a_rule_set_behind_the_policy_is_rebuilt_and_reloaded(self):
        done = protection.keep_rules_on_policy()
        self.rebuild.assert_called_once()
        self.reload.assert_called_once()
        self.assertIn("engine reloaded", done)

    def test_a_rule_set_that_follows_the_policy_is_left_alone(self):
        self.rules.write_bytes(
            b'drop tcp any any -> any any (msg:"ET MALWARE One"; sid:2000001; rev:1;)\n')
        self.assertIsNone(protection.keep_rules_on_policy())
        self.rebuild.assert_not_called()

    def test_a_failed_rebuild_is_not_repeated_on_the_same_file(self):
        self.rebuilt = False
        self.assertIn("rebuild failed: error: no cache", protection.keep_rules_on_policy())
        self.assertIsNone(protection.keep_rules_on_policy())
        self.assertEqual(self.rebuild.call_count, 1)
        self.reload.assert_not_called()

    def test_a_rebuild_whose_result_still_lags_is_not_repeated_either(self):
        # The file changed, but not into one that follows the policy. Retried
        # every ten minutes, that is a rebuild of 68 000 rules for ever.
        def rebuild(*a, **k):
            self.rules.write_bytes(self.rules.read_bytes() + b"# rebuilt\n")
            return True, "done"
        self.rebuild.side_effect = rebuild
        protection.keep_rules_on_policy()
        protection.keep_rules_on_policy()
        self.assertEqual(self.rebuild.call_count, 1)

    def test_a_new_rule_file_gets_a_new_attempt(self):
        self.rebuilt = False
        protection.keep_rules_on_policy()
        # The nightly refresh writes a different file.
        self.rules.write_bytes(
            b'alert tcp any any -> any any (msg:"ET MALWARE Two"; sid:2000002; rev:1;)\n')
        protection.keep_rules_on_policy()
        self.assertEqual(self.rebuild.call_count, 2)

    def test_an_engine_that_will_not_reload_is_reported(self):
        self.reload.return_value = (False, "socket not found")
        self.assertIn("would not reload it: socket not found",
                      protection.keep_rules_on_policy())

    def test_no_rule_file_is_nothing_to_do(self):
        self.rules.unlink()
        self.assertIsNone(protection.keep_rules_on_policy())


class ReloadEngineTest(BackendTestCase):
    def _proc(self, rc, out=""):
        proc = subprocess.CompletedProcess([], rc, out, "")
        return proc

    def test_the_socket_first_and_systemctl_only_if_it_fails(self):
        with patch.object(protection.subprocess, "run",
                          side_effect=[self._proc(1, "no socket"), self._proc(0, "")]) as run:
            ok, _ = protection.reload_engine()
        self.assertTrue(ok)
        self.assertEqual([c.args[0] for c in run.call_args_list], [
            ["sudo", "-n", "suricatasc", "-c", "reload-rules"],
            ["sudo", "-n", "systemctl", "reload", "suricata"]])

    def test_a_socket_that_works_is_the_only_call(self):
        with patch.object(protection.subprocess, "run", return_value=self._proc(0)) as run:
            self.assertTrue(protection.reload_engine()[0])
        self.assertEqual(run.call_count, 1)

    def test_both_failing_says_what_the_last_one_said(self):
        with patch.object(protection.subprocess, "run",
                          side_effect=[self._proc(1, "a"), FileNotFoundError()]):
            ok, output = protection.reload_engine()
        self.assertFalse(ok)
        self.assertIn("command not found", output)


class RulesPolicyLoopTest(BackendTestCase):
    def test_the_lifespan_is_a_context_manager_and_the_helper_a_plain_call(self):
        """A helper written between the decorator and the lifespan took the
        decorator. It still ran, by accident of how the decorator calls it, and
        the lifespan went to the server undecorated."""
        import inspect
        from app import main
        self.assertFalse(inspect.isasyncgenfunction(main.lifespan))
        with patch.object(protection, "refresh_drop_conf"):
            self.assertIsNone(main._refresh_drop_conf())

    def test_the_check_is_started_with_the_panel(self):
        import inspect
        from app import main
        self.assertIn("_rules_policy_loop()", inspect.getsource(main.lifespan))

    def test_one_check_logs_what_it_did(self):
        import asyncio
        from app import main
        with patch.object(protection, "keep_rules_on_policy", return_value="rebuilt"), \
                patch.object(main.log, "info") as info:
            asyncio.run(main._keep_rules_on_policy_once())
        self.assertIn("rebuilt", info.call_args.args)

    def test_a_check_that_raises_does_not_end_the_loop(self):
        import asyncio
        from app import main
        with patch.object(protection, "keep_rules_on_policy", side_effect=RuntimeError("x")), \
                patch.object(main.log, "exception") as logged:
            asyncio.run(main._keep_rules_on_policy_once())
        logged.assert_called_once()
