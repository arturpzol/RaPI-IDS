"""The eve.json reader: what gets stored, what stays in memory, what is shown."""
from __future__ import annotations

import json
import os
from datetime import datetime
from unittest.mock import patch

from app import db
from app.modules.suricata import tailer

from .helpers import BackendTestCase

ALERT = {
    "timestamp": "2026-08-23T10:15:00.123456+0200",
    "event_type": "alert",
    "src_ip": "203.0.113.7",
    "src_port": 44321,
    "dest_ip": "192.168.1.10",
    "dest_port": 443,
    "proto": "TCP",
    "app_proto": "tls",
    "in_iface": "eth0",
    "alert": {
        "signature": "ET MALWARE Test",
        "signature_id": 2000001,
        "category": "A Network Trojan was detected",
        "severity": 1,
    },
}


# One packet, reported twice, taken from the 2026-09-01 20:00 burst: the alert
# raised by Suricata's own event rule and the anomaly record for the same
# condition. Same timestamp to the microsecond, same flow.
QUIC_ALERT = {
    "timestamp": "2026-09-01T20:00:03.264376+0200",
    "flow_id": 1125591893090379,
    "in_iface": "eth1",
    "event_type": "alert",
    "src_ip": "203.0.113.229",
    "src_port": 443,
    "dest_ip": "192.168.1.10",
    "dest_port": 60172,
    "proto": "UDP",
    "app_proto": "quic",
    "alert": {
        "signature": "SURICATA QUIC error on data",
        "signature_id": 2231001,
        "category": "Generic Protocol Command Decode",
        "severity": 3,
    },
}

QUIC_ANOMALY = {
    "timestamp": "2026-09-01T20:00:03.264376+0200",
    "flow_id": 1125591893090379,
    "in_iface": "eth1",
    "event_type": "anomaly",
    "src_ip": "203.0.113.229",
    "src_port": 443,
    "dest_ip": "192.168.1.10",
    "dest_port": 60172,
    "proto": "UDP",
    "anomaly": {"app_proto": "quic", "type": "applayer",
                "event": "error_on_data", "layer": "proto_parser"},
}


class FlattenTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(tailer.geoip, "classify", return_value="US"))

    def test_the_columns_the_list_filters_on(self):
        row = tailer._flatten_alert(ALERT)
        self.assertEqual(row["signature_id"], 2000001)
        self.assertEqual(row["severity"], 1)
        self.assertEqual(row["iface"], "eth0")
        self.assertEqual(row["src_cc"], "US")
        # Seconds, not the engine's string: converted once here so nothing
        # downstream has to know the engine's timezone.
        self.assertEqual(
            row["ts"], int(datetime.fromisoformat(ALERT["timestamp"]).timestamp()))
        self.assertEqual(row["raw"], ALERT)

    def test_an_event_without_an_alert_block_still_flattens(self):
        row = tailer._flatten_alert({"event_type": "anomaly", "src_ip": "10.0.0.1"})
        # Named after what it is, not left empty: the list showed such rows as
        # "(unnamed)", which reads as a broken panel rather than as the engine
        # reporting on itself.
        self.assertEqual(row["signature"], "anomaly")
        self.assertTrue(row["ts"])  # filled in rather than left empty

    def test_an_anomaly_is_named_after_the_parser_and_the_event(self):
        row = tailer._flatten_alert({
            "event_type": "anomaly",
            "anomaly": {"type": "applayer", "app_proto": "http",
                        "event": "UNABLE_TO_MATCH_RESPONSE_TO_REQUEST"},
        })
        self.assertEqual(row["signature"],
                         "anomaly: http UNABLE_TO_MATCH_RESPONSE_TO_REQUEST")

    def test_an_anomaly_with_no_application_protocol_uses_the_layer(self):
        row = tailer._flatten_alert({
            "event_type": "anomaly",
            "anomaly": {"type": "decoder", "layer": "packet", "event": "IPV4_TRUNC_PKT"},
        })
        self.assertEqual(row["signature"], "anomaly: packet IPV4_TRUNC_PKT")

    def test_an_alert_keeps_its_own_signature(self):
        row = tailer._flatten_alert(ALERT)
        self.assertEqual(row["signature"], ALERT["alert"]["signature"])

    def test_the_country_is_resolved_once_on_the_way_in(self):
        with patch.object(tailer.geoip, "classify", return_value="PL") as classify:
            tailer._flatten_alert(ALERT)
        classify.assert_called_once_with("203.0.113.7")


class SummaryTest(BackendTestCase):
    def test_dns_tls_http_and_flow_get_a_detail_line(self):
        cases = [
            ({"event_type": "dns", "dns": {"rrname": "example.net"}}, "example.net"),
            ({"event_type": "tls", "tls": {"sni": "example.net"}}, "example.net"),
            ({"event_type": "http",
              "http": {"http_method": "GET", "hostname": "example.net", "url": "/a"}},
             "GET example.net/a"),
            ({"event_type": "flow", "flow": {"pkts_toserver": 3, "pkts_toclient": 4}},
             "3/4 pkt"),
        ]
        for event, detail in cases:
            with self.subTest(kind=event["event_type"]):
                self.assertEqual(tailer._summarize_event(event)["detail"], detail)

    def test_an_unknown_event_has_no_detail_and_no_crash(self):
        summary = tailer._summarize_event({"event_type": "smb"})
        self.assertEqual(summary["event_type"], "smb")
        self.assertNotIn("detail", summary)

    def test_the_summary_carries_no_payload(self):
        # The live feed goes to a browser; the full event does not.
        summary = tailer._summarize_event({"event_type": "http", "http": {"http_user_agent": "x"}})
        self.assertNotIn("raw", summary)


class StateSnapshotTest(BackendTestCase):
    def test_drop_rate_is_a_share_of_everything_offered(self):
        state = tailer.SuricataState()
        state.last_stats = {
            "capture": {"kernel_packets": 900, "kernel_drops": 100, "errors": 0},
            "decoder": {"pkts": 900, "bytes": 1234},
            "detect": {"alert": 5},
            "flow": {"total": 12},
            "uptime": 3600,
        }
        engine = state.snapshot()["engine"]
        self.assertEqual(engine["drop_rate_percent"], 10.0)
        self.assertEqual(engine["alerts_detected"], 5)
        self.assertEqual(engine["flows"], 12)

    def test_no_statistics_yet_is_unknown_and_not_a_division_by_zero(self):
        # Before the first report nothing is known, which is a third answer
        # beside "clean" and "faulty" and used to be reported as the first one.
        engine = tailer.SuricataState().snapshot()["engine"]
        self.assertIsNone(engine["drop_rate_percent"])
        self.assertFalse(engine["loss_measured"])
        self.assertEqual(engine["packets"], 0)

    def _engine(self, **stats):
        """The engine counters as the status endpoint would report them."""
        state = tailer.SuricataState()
        state.last_stats = {
            "capture": {"kernel_packets": stats.get("kernel_packets", 1_000_000),
                        "kernel_drops": stats.get("kernel_drops", 0),
                        "errors": stats.get("errors", 0)},
            "decoder": {"pkts": stats.get("pkts", 1_000_000), "bytes": 1},
            "tcp": {"sessions": stats.get("sessions", 20_000),
                    "reassembly_gap": stats.get("gaps", 0)},
            "detect": {"alert": 0},
            "flow": {"total": 0},
            "uptime": 3600,
        }
        return state.snapshot()["engine"]

    def test_the_stream_counters_come_through(self):
        # A reassembly gap is a TCP stream the engine could not put back
        # together: one connection whose content it inspected in part or not at
        # all. Suricata counts them; nothing was reading the counter.
        engine = self._engine(sessions=27_714, gaps=5)
        self.assertEqual(engine["tcp_sessions"], 27_714)
        self.assertEqual(engine["reassembly_gaps"], 5)
        self.assertEqual(engine["gap_rate_percent"], 0.018)

    def test_a_healthy_sensor_has_no_problem_to_report(self):
        """The case that used to be reported as a fault.

        The card that stood here counted the engine's decoder event rules,
        which fire per packet. Five "protocol detection skipped" in a week made
        it red on this device, which had dropped nothing at all out of 13.7
        million packets.
        """
        self.assertIsNone(self._engine(kernel_packets=13_738_238, pkts=13_738_238,
                                       sessions=27_714, gaps=5)["sensor_problem"])

    def test_loss_under_one_percent_is_not_a_fault(self):
        # Zeek documents capture loss as something that "should never exceed
        # 1%", and Security Onion colours its per-node loss on the same scale.
        # This panel is not stricter than either.
        self.assertIsNone(self._engine(pkts=99_600, kernel_drops=400)["sensor_problem"])

    def test_loss_over_one_percent_is(self):
        self.assertEqual(self._engine(pkts=98_000, kernel_drops=2_000)["sensor_problem"],
                         "drops")

    def test_one_capture_error_is_one_too_many(self):
        # Not a proportion of anything: the kernel saying the ring is broken.
        self.assertEqual(self._engine(errors=1)["sensor_problem"], "errors")

    def test_too_many_streams_that_could_not_be_reassembled(self):
        self.assertEqual(self._engine(sessions=1_000, gaps=42)["sensor_problem"], "gaps")

    def test_gaps_under_the_threshold_are_not_a_fault(self):
        self.assertIsNone(self._engine(sessions=1_000, gaps=9)["sensor_problem"])

    def test_dropping_packets_outranks_everything_else(self):
        # A dropped packet is traffic the engine never saw; a gap is one stream
        # it could not reassemble. Reporting the smaller one would send the
        # operator after the wrong thing.
        engine = self._engine(pkts=98_000, kernel_drops=2_000, errors=3,
                              sessions=1_000, gaps=42)
        self.assertEqual(engine["sensor_problem"], "drops")

    def test_a_broken_ring_outranks_a_gap(self):
        self.assertEqual(
            self._engine(errors=3, sessions=1_000, gaps=42)["sensor_problem"], "errors")

    def _inline(self, **stats):
        """The engine as it reports itself while inline on a netfilter queue.

        Taken from this device: `capture` is absent entirely and the drop
        counters live under `ips`. Nothing here is a fixture invention.
        """
        state = tailer.SuricataState()
        state.last_stats = {
            "ips": {"accepted": stats.get("accepted", 59974),
                    "blocked": stats.get("blocked", 266),
                    "drop_reason": {"rules": stats.get("by_rules", 0),
                                    "stream_midstream": 42,
                                    "exception_policy_flow_drop": 221}},
            "decoder": {"pkts": stats.get("pkts", 60241), "bytes": 1},
            "tcp": {"sessions": stats.get("sessions", 188),
                    "reassembly_gap": stats.get("gaps", 0)},
            "detect": {"alert": 0},
            "flow": {"total": 0},
            "uptime": 3600,
        }
        return state.snapshot()["engine"]

    def test_a_missing_capture_section_is_unknown_not_zero(self):
        """The evening this panel spent reporting a healthy sensor.

        Inline on a queue there is no ring to overflow, so Suricata publishes no
        `capture` section at all. Read as zero it makes every loss figure a
        clean measurement that was never taken: the card said "no packets
        dropped" while 266 had been destroyed and the mirror port was not being
        inspected at all.
        """
        engine = self._inline()
        self.assertFalse(engine["loss_measured"])
        self.assertIsNone(engine["kernel_drops"])
        self.assertIsNone(engine["kernel_packets"])
        self.assertIsNone(engine["capture_errors"])
        self.assertIsNone(engine["drop_rate_percent"])

    def _inline_pair(self, **stats):
        """The engine forwarding an af-packet pair, as it reports itself.

        Both sections at once, which is the case the old reading had no room
        for. Taken from this device on 2026-09-20: `ips` beside a `capture`
        with real kernel_packets.
        """
        state = tailer.SuricataState()
        state.last_stats = {
            "ips": {"accepted": 1192000, "blocked": 645,
                    "drop_reason": {"rules": 12}},
            "capture": {"kernel_packets": stats.get("pkts", 1192645),
                        "kernel_drops": stats.get("drops", 0), "errors": 0},
            "decoder": {"pkts": stats.get("pkts", 1192645), "bytes": 1},
            "tcp": {"sessions": 100, "reassembly_gap": 0},
            "detect": {"alert": 0},
            "flow": {"total": 0},
            "uptime": 3600,
        }
        return state.snapshot()["engine"]

    def test_the_mode_comes_from_the_engine_not_from_a_file(self):
        # The YAML the panel parses can be replaced wholesale by an include, and
        # the blocking switch changes the command line through a drop-in without
        # touching any YAML. The stats record is the engine's own account.
        self.assertEqual(self._inline()["capture_mode"], "nfqueue")
        self.assertEqual(self._engine()["capture_mode"], "af-packet")
        self.assertIsNone(tailer.SuricataState().snapshot()["engine"]["capture_mode"])

    def test_an_inline_pair_is_not_reported_as_a_netfilter_queue(self):
        """The two sections are not exclusive, and the old reading assumed they
        were: a kernel bridge carrying its own traffic was named a netfilter
        queue on every screen that named the mechanism."""
        engine = self._inline_pair()
        self.assertEqual(engine["capture_mode"], "af-packet")
        # And its capture loss is knowable, because there is a ring to overflow.
        self.assertTrue(engine["loss_measured"])
        self.assertEqual(engine["kernel_packets"], 1192645)

    def test_blocking_is_its_own_answer_in_both_mechanisms(self):
        # The chrome badge reads this, and it was reading the capture method.
        self.assertTrue(self._inline()["blocking"])
        self.assertTrue(self._inline_pair()["blocking"])
        self.assertFalse(self._engine()["blocking"])
        self.assertFalse(tailer.SuricataState().snapshot()["engine"]["blocking"])

    def test_an_unmeasurable_sensor_is_not_reported_as_faultless(self):
        # None is not zero. The verdict has to come back "no fault found"
        # without that meaning "measured and clean" - the screen tells them
        # apart by loss_measured.
        engine = self._inline()
        self.assertIsNone(engine["sensor_problem"])
        self.assertFalse(engine["loss_measured"])

    def test_what_was_stopped_and_how_much_of_it_any_rule_asked_for(self):
        """The two are different numbers and the screen promised they were one.

        Measured on this device: 266 packets stopped, `drop_reason.rules` zero
        for every one of them. The rest were the exception policy and streams
        picked up midway.
        """
        engine = self._inline(blocked=266, by_rules=0)
        self.assertEqual(engine["blocked"], 266)
        self.assertEqual(engine["blocked_by_rules"], 0)

    def test_a_capture_run_reports_no_blocking_counters(self):
        engine = self._engine()
        self.assertIsNone(engine["blocked"])
        self.assertIsNone(engine["blocked_by_rules"])
        self.assertTrue(engine["loss_measured"])

    def test_a_verdict_cannot_be_reached_from_counters_that_are_absent(self):
        # The signature itself is the guard: pass None and no fault comes back,
        # so a caller that reads a missing section as zero cannot launder it
        # into a clean bill of health here.
        self.assertIsNone(tailer.sensor_problem(None, None, 0.0))
        self.assertEqual(tailer.sensor_problem(None, 3, 0.0), "errors")
        self.assertEqual(tailer.sensor_problem(9.0, None, 0.0), "drops")

    def test_an_engine_that_has_not_reported_yet_is_not_called_faulty(self):
        # Silence is not health and it is not a fault either. The screen says
        # "Checking..." until the first stats record arrives.
        engine = tailer.SuricataState().snapshot()["engine"]
        self.assertIsNone(engine["sensor_problem"])
        self.assertEqual(engine["tcp_sessions"], 0)
        self.assertEqual(engine["gap_rate_percent"], 0.0)


class HandleEventTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.tailer = tailer.EveTailer.__new__(tailer.EveTailer)
        self.published = []
        self.tailer._publish = lambda topic, payload: self.published.append((topic, payload))
        self.enterContext(patch.object(tailer, "state", tailer.SuricataState()))

    def test_alerts_are_batched_and_everything_else_is_not(self):
        batch = []
        self.tailer._handle_event(ALERT, batch)
        self.tailer._handle_event({"event_type": "dns", "dns": {"rrname": "a.net"}}, batch)
        self.assertEqual(len(batch), 1)
        self.assertEqual(len(tailer.state.recent_events), 1)
        self.assertEqual(self.published[0][0], "suricata.event")

    def test_statistics_are_kept_and_broadcast_but_not_stored(self):
        batch = []
        self.tailer._handle_event(
            {"event_type": "stats", "timestamp": "2026-08-23T10:00:00+0200",
             "stats": {"uptime": 10}}, batch,
        )
        self.assertEqual(batch, [])
        self.assertEqual(tailer.state.last_stats, {"uptime": 10})
        self.assertEqual(self.published[0][0], "suricata.stats")

    def test_a_flush_stores_the_rows_and_announces_them_with_their_ids(self):
        batch = [tailer._flatten_alert(ALERT)]
        self.tailer._flush(batch)
        self.assertEqual(batch, [])
        stored = db.query_alerts()["items"]
        self.assertEqual(len(stored), 1)
        topic, payload = self.published[0]
        self.assertEqual(topic, "suricata.alert")
        self.assertEqual(payload["id"], stored[0]["id"])
        self.assertNotIn("raw", payload)   # the live feed does not carry the event
        self.assertFalse(payload["acknowledged"])

    def test_a_flush_does_not_store_a_record_already_covered(self):
        # The engine writes one QUIC parser complaint twice: as an alert from
        # its own event rule and as an anomaly. Filtered before the insert, not
        # after, so no cleanup has to remove a row somebody already saw.
        batch = [tailer._flatten_alert(QUIC_ALERT), tailer._flatten_alert(QUIC_ANOMALY)]
        self.tailer._flush(batch)
        self.assertEqual(db.query_alerts()["total"], 1)
        # And nothing on the live feed: a QUIC parser complaint is one of the
        # engine's own notes, not a finding.
        self.assertEqual(self.published, [])

    def test_the_engines_own_notes_are_stored_and_not_announced(self):
        """The split was in the queries and not on the live path.

        Everything stored went out as `suricata.alert` and into the mail queue
        behind it, so "SURICATA Ethertype unknown" - 16 584 rows with no source,
        no destination and no protocol, because the frame has no IP layer -
        counted as a new alert, sat in the recent list on the dashboard, and
        would be mailed to somebody as something to look at.
        """
        diagnostic = tailer._flatten_alert(QUIC_ALERT)
        threat = tailer._flatten_alert(ALERT)
        with patch.object(tailer.notifier, "submit") as submit:
            self.tailer._flush([diagnostic, threat])

        self.assertEqual(db.query_alerts()["total"], 2)          # both stored
        self.assertEqual(db.query_alerts(kind="diagnostic")["total"], 1)

        topics = [t for t, _ in self.published]
        self.assertEqual(topics, ["suricata.alert"])             # only the threat
        self.assertEqual(self.published[0][1]["signature_id"], ALERT["alert"]["signature_id"])

        self.assertEqual(submit.call_count, 1)
        self.assertEqual(submit.call_args[0][0]["signature_id"],
                         ALERT["alert"]["signature_id"])

    def test_an_anomaly_on_its_own_is_stored_and_not_announced(self):
        # No signature_id at all on these rows, so the split has to catch them
        # by event_type or they go out as findings.
        with patch.object(tailer.notifier, "submit") as submit:
            self.tailer._flush([tailer._flatten_alert(QUIC_ANOMALY)])
        self.assertEqual(db.query_alerts(kind="diagnostic")["total"], 1)
        self.assertEqual(self.published, [])
        submit.assert_not_called()

    def test_a_flush_of_nothing_but_duplicates_is_not_a_write(self):
        db.insert_alerts([tailer._flatten_alert(QUIC_ALERT)])
        with patch.object(db, "insert_alerts") as write:
            self.tailer._flush([tailer._flatten_alert(QUIC_ANOMALY)])
        write.assert_not_called()

    def test_a_failed_write_does_not_take_the_reader_down(self):
        with patch.object(db, "insert_alerts", side_effect=RuntimeError("locked")):
            self.tailer._flush([tailer._flatten_alert(ALERT)])
        self.assertEqual(self.published, [])

    def test_event_counters_follow_the_types_seen(self):
        batch = []
        for event in (ALERT, ALERT, {"event_type": "dns"}):
            self.tailer._handle_event(event, batch)
        self.assertEqual(tailer.state.event_counts["alert"], 2)
        self.assertEqual(tailer.state.event_counts["dns"], 1)


class ParseTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.tailer = tailer.EveTailer.__new__(tailer.EveTailer)
        self.enterContext(patch.object(tailer, "state", tailer.SuricataState()))

    def test_a_broken_line_is_counted_not_raised(self):
        self.assertIsNone(self.tailer._parse("{ half a line"))
        self.assertEqual(tailer.state.parse_errors, 1)

    def test_blank_lines_are_not_errors(self):
        self.assertIsNone(self.tailer._parse("\n"))
        self.assertEqual(tailer.state.parse_errors, 0)

    def test_a_whole_line_parses(self):
        self.assertEqual(self.tailer._parse(json.dumps(ALERT) + "\n")["event_type"], "alert")

    def test_valid_json_that_is_not_an_event_is_discarded(self):
        """A list and a bare null both parse. Neither has .get().

        The AttributeError that raised reached the outer loop, which treats any
        exception as a crash: it slept two seconds and resumed from the last
        saved offset, which is before the offending line. So it read the same
        line again, and again, for as long as the file existed. One malformed
        record could stop the panel ever seeing another alert, while the engine
        carried on detecting perfectly.
        """
        for line in ("[1, 2]", "null", '"a string"', "42"):
            with self.subTest(line=line):
                self.assertIsNone(self.tailer._parse(line + "\n"))
        self.assertEqual(tailer.state.parse_errors, 4)

    def test_an_offset_that_cannot_be_written_is_not_fatal(self):
        """The reader survives a database it cannot write to.

        This is the full disk case. insert_alerts was already guarded; the
        offset write next to it was not, so a full volume turned into a crash
        and restart every two seconds, each one logging a traceback onto the
        volume that was already full.
        """
        tailer_ = tailer.EveTailer.__new__(tailer.EveTailer)
        tailer_._path = "/tmp/eve.json"
        with patch.object(tailer.db, "save_reader_state", side_effect=OSError("no space")):
            tailer_._save_offset(1, 2)  # must not raise


class NumericFieldTest(BackendTestCase):
    """The one EVE field that has to be a number.

    Every other field stored here is text and survives whatever the line
    contained. This one is compared against a threshold and used as a
    dictionary key, so it is checked where it enters rather than at each of the
    places that later trust it.
    """

    def test_a_severity_that_is_not_a_number_is_stored_as_nothing(self):
        self.assertIsNone(tailer._as_int("high"))
        self.assertIsNone(tailer._as_int(None))
        self.assertIsNone(tailer._as_int([1]))

    def test_a_boolean_is_not_a_number_either(self):
        # bool is a subclass of int: `true` would be stored as priority 1.
        self.assertIsNone(tailer._as_int(True))
        self.assertIsNone(tailer._as_int(False))

    def test_a_real_priority_comes_through(self):
        self.assertEqual(tailer._as_int(2), 2)
        self.assertEqual(tailer._as_int(0), 0)

    def test_the_flattened_alert_carries_the_checked_value(self):
        row = tailer._flatten_alert({
            "event_type": "alert", "timestamp": "2026-09-12T10:00:00.000000+0200",
            "src_ip": "203.0.113.7", "dest_ip": "192.168.1.10",
            "alert": {"signature": "X", "signature_id": 1, "severity": "high"},
        })
        self.assertIsNone(row["severity"])


class ResumePointTest(BackendTestCase):
    """Where the reader starts again when the engine was writing mid-line.

    The file position is past the half written line, but the line has not been
    handled: it lives in a string in memory, which a restart does not survive.
    Saving the raw position meant the next run seeked past the start of that
    line, read its tail as a line of its own, failed to parse it and counted an
    error. One alert lost, silently, on any restart that lands mid-write.
    """

    def _read_to_eof(self, path):
        """The loop's own reading, down to the partial line it holds back."""
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            partial = ""
            while True:
                line = fh.readline()
                if not line:
                    break
                if not line.endswith("\n"):
                    partial += line
                    continue
            return tailer._resume_at(fh, partial), partial

    def test_the_unfinished_line_is_read_again_from_its_start(self):
        path = self.tmp / "eve.json"
        head = '{"event_type": "alert", "n": 1}\n'
        tail_start = '{"event_type": "alert", "n": 2'
        path.write_text(head + tail_start, encoding="utf-8")

        offset, partial = self._read_to_eof(path)
        self.assertEqual(partial, tail_start)

        # The engine finishes the line while the panel is down.
        path.write_text(head + tail_start + '}\n', encoding="utf-8")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            self.assertEqual(fh.readline(), tail_start + '}\n')

    def test_a_line_that_was_finished_leaves_the_position_alone(self):
        # Nothing pending, nothing to rewind: rewinding here would re-read the
        # last line on every save and store it again.
        path = self.tmp / "eve.json"
        path.write_text('{"n": 1}\n{"n": 2}\n', encoding="utf-8")
        offset, partial = self._read_to_eof(path)
        self.assertEqual(partial, "")
        self.assertEqual(offset, path.stat().st_size)

    def test_a_signature_outside_ascii_does_not_shift_the_offset(self):
        # The position counts bytes and len() counts characters. A rule name
        # with one accented letter would leave the resume point inside the
        # previous line, which parses as nothing.
        path = self.tmp / "eve.json"
        head = '{"signature": "ET INFO zazolc gesla jazn"}\n'
        tail_start = '{"signature": "ET INFO zazolc ge\u015bl'
        path.write_text(head + tail_start, encoding="utf-8")
        offset, _ = self._read_to_eof(path)
        self.assertEqual(offset, len(head.encode("utf-8")))


class RotationTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.path = self.tmp / "eve.json"
        self.path.write_text("{}\n")
        self.tailer = tailer.EveTailer.__new__(tailer.EveTailer)
        self.tailer._path = str(self.path)

    def test_a_new_inode_means_rotated(self):
        stat = os.stat(self.path)
        with open(self.path) as handle:
            handle.seek(0, os.SEEK_END)
            self.assertFalse(self.tailer._rotated(stat, handle))
            self.path.unlink()
            self.path.write_text("{}\n")     # same name, new inode
            self.assertTrue(self.tailer._rotated(stat, handle))

    def test_a_shorter_file_means_truncated(self):
        # logrotate copytruncate keeps the inode and empties the file.
        self.path.write_text("{}\n{}\n{}\n")
        stat = os.stat(self.path)
        with open(self.path) as handle:
            handle.seek(0, os.SEEK_END)
            self.path.write_text("")
            self.assertTrue(self.tailer._rotated(stat, handle))

    def test_a_missing_file_means_rotated(self):
        stat = os.stat(self.path)
        with open(self.path) as handle:
            self.path.unlink()
            self.assertTrue(self.tailer._rotated(stat, handle))
