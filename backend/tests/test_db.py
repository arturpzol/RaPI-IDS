"""SQLite layer: what is stored, what is filtered, what the dashboard adds up."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from app import db

from .helpers import BackendTestCase, alert


class AlertStorageTest(BackendTestCase):
    def test_insert_returns_ids_in_order(self):
        ids = db.insert_alerts([alert(signature="one"), alert(signature="two")])
        self.assertEqual(len(ids), 2)
        self.assertEqual(ids[1], ids[0] + 1)

    def test_empty_batch_touches_nothing(self):
        self.assertEqual(db.insert_alerts([]), [])
        self.assertEqual(db.query_alerts()["total"], 0)

    def test_raw_event_comes_back_only_on_the_detail_view(self):
        # The list view is polled; shipping the full JSON with every row would
        # multiply the payload for a field nothing on the list draws.
        alert_id = db.insert_alerts([alert(raw={"http": {"hostname": "example.net"}})])[0]
        listed = db.query_alerts()["items"][0]
        self.assertNotIn("raw", listed)
        self.assertEqual(db.get_alert(alert_id)["raw"]["http"]["hostname"], "example.net")

    def test_missing_alert_is_none(self):
        self.assertIsNone(db.get_alert(4242))

    def test_acknowledge_reports_whether_a_row_changed(self):
        alert_id = db.insert_alerts([alert()])[0]
        self.assertTrue(db.set_acknowledged(alert_id, True))
        self.assertTrue(db.get_alert(alert_id)["acknowledged"])
        self.assertFalse(db.set_acknowledged(9999, True))

    def test_retention_drops_old_rows_only(self):
        db.insert_alerts([alert(ts=_ago(days=40)), alert()])
        self.assertEqual(db.purge_old_alerts(30), 1)
        self.assertEqual(db.query_alerts()["total"], 1)


def _ago(**delta: int) -> int:
    """A timestamp N units in the past, in the seconds the column holds."""
    return int((datetime.now(timezone.utc) - timedelta(**delta)).timestamp())


class AlertQueryTest(BackendTestCase):

    def setUp(self):
        super().setUp()
        db.insert_alerts([
            alert(severity=1, et_severity="Critical", src_ip="203.0.113.7",
                  src_cc="US", signature_id=1001, signature="ET MALWARE One"),
            alert(severity=3, et_severity="Informational", src_ip="198.51.100.4",
                  src_cc="DE", signature_id=1002, signature="ET INFO Two",
                  dest_ip="192.168.1.11"),
            alert(severity=3, et_severity="Informational", src_ip="198.51.100.4",
                  src_cc="DE", signature_id=1002, signature="ET INFO Two"),
        ])

    def test_filters(self):
        self.assertEqual(db.query_alerts(severity="Critical")["total"], 1)
        self.assertEqual(db.query_alerts(src_ip="198.51.100.4")["total"], 2)
        self.assertEqual(db.query_alerts(dest_ip="192.168.1.11")["total"], 1)
        self.assertEqual(db.query_alerts(src_cc="DE")["total"], 2)
        self.assertEqual(db.query_alerts(signature_id=1001)["total"], 1)
        self.assertEqual(db.query_alerts(acknowledged=False)["total"], 3)

    def test_search_covers_signature_and_addresses(self):
        self.assertEqual(db.query_alerts(search="MALWARE")["total"], 1)
        self.assertEqual(db.query_alerts(search="198.51.100")["total"], 2)

    def test_filters_combine_with_and(self):
        self.assertEqual(db.query_alerts(severity="Informational", src_cc="US")["total"], 0)

    def test_paging_reports_the_unpaged_total(self):
        page = db.query_alerts(limit=2, offset=0)
        self.assertEqual((page["total"], len(page["items"])), (3, 2))
        self.assertEqual(len(db.query_alerts(limit=2, offset=2)["items"]), 1)

    def test_the_rating_column_is_what_the_rule_set_said(self):
        """The column exists because the engine number is a different scale.

        ET rates `GPL ATTACK_RESPONSE id check returned root` Informational
        while the engine gives it priority 2; 296 rules ET calls Critical or
        Major carry priority 3. Nothing here filters on either - whether a rule
        is loaded at all is decided in disable.conf - but the label has to
        survive storage, because it is what the list and the map colour by.
        """
        db.insert_alerts([
            alert(severity=2, et_severity="Informational", signature_id=2100498,
                  signature="GPL ATTACK_RESPONSE id check returned root"),
            alert(severity=3, et_severity="Major", signature_id=2019386,
                  signature="ET EXPLOIT Serialized Java Object"),
        ])
        self.assertEqual(db.query_alerts(severity="Informational")["total"], 3)
        self.assertEqual(
            [a["signature_id"] for a in db.query_alerts(severity="Major")["items"]],
            [2019386],
        )

    def test_a_rule_the_rule_set_never_rated_is_asked_for_by_name(self):
        # GPL rules and Suricata's own stream events carry no ET metadata. An
        # absence cannot be put in a URL, so "unrated" is the name for it.
        db.insert_alerts([
            alert(severity=None, et_severity=None, signature="Broken", signature_id=1),
            alert(severity=3, et_severity=None, signature="SURICATA STREAM x", signature_id=2),
        ])
        found = [a["signature_id"] for a in db.query_alerts(severity="unrated")["items"]]
        self.assertEqual(sorted(found), [1, 2])

    def test_window_excludes_older_rows(self):
        db.insert_alerts([alert(ts=_ago(hours=48))])
        self.assertEqual(db.query_alerts(since_hours=24)["total"], 3)
        self.assertEqual(db.query_alerts()["total"], 4)

    def _old_shaped_table(self, rows: list[str]) -> sqlite3.Connection:
        """An alerts table as it was declared before the change: ts TEXT.

        The declaration is the whole point. In SQLite a declared type is an
        affinity applied to every write, so a TEXT column turns an integer
        straight back into a string - which is what made the first version of
        this migration destroy the data it was converting.
        """
        conn = db.connect()
        with db._write_lock:
            conn.execute("DROP TABLE alerts")
            conn.execute("""CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, event_type TEXT NOT NULL,
                src_ip TEXT, src_port INTEGER, dest_ip TEXT, dest_port INTEGER,
                proto TEXT, app_proto TEXT, signature TEXT, signature_id INTEGER,
                category TEXT, severity INTEGER, et_severity TEXT, iface TEXT,
                src_cc TEXT, acknowledged INTEGER NOT NULL DEFAULT 0,
                raw TEXT NOT NULL)""")
            conn.execute("CREATE INDEX idx_alerts_ts ON alerts(ts DESC)")
            for i, ts in enumerate(rows):
                conn.execute(
                    "INSERT INTO alerts (ts, event_type, signature, src_ip, raw)"
                    " VALUES (?, 'alert', ?, '203.0.113.7', '{}')", (ts, f"row {i}"))
            conn.commit()
        return conn

    def test_the_migration_converts_a_text_column_without_losing_a_row(self):
        """The regression this exists for destroyed 1220 rows on a live device.

        Written as an in-place UPDATE it stored every integer back as a string,
        because the column's declared type said TEXT. The row still answered
        typeof(ts) = 'text', so the loop read it again, failed to parse a bare
        number as a date, and deleted it. It reported "converted 1220, dropped
        1220" - the same rows, counted twice, and an empty table.
        """
        conn = self._old_shaped_table([
            "2026-08-23T10:15:00.123456+0200",
            "2026-08-23T11:15:00.000000+0200",
            "not a timestamp",
        ])

        with db._write_lock:
            db._migrate(conn)
            conn.commit()

        kinds = dict(conn.execute(
            "SELECT typeof(ts), COUNT(*) FROM alerts GROUP BY 1").fetchall())
        self.assertEqual(kinds, {"integer": 2}, "a row was lost or left as text")
        self.assertEqual(
            conn.execute("SELECT ts FROM alerts WHERE signature = 'row 0'").fetchone()["ts"],
            int(datetime.fromisoformat("2026-08-23T10:15:00.123456+0200").timestamp()))
        # Everything else on the row came across, not just the timestamp.
        self.assertEqual(
            conn.execute("SELECT src_ip FROM alerts WHERE signature = 'row 1'"
                         ).fetchone()["src_ip"], "203.0.113.7")
        # And the declared type is the new one, or the next write puts a string
        # back into it.
        self.assertEqual(
            [r["type"] for r in conn.execute("PRAGMA table_info(alerts)")
             if r["name"] == "ts"], ["INTEGER"])
        self.assertEqual(
            conn.execute("SELECT COUNT(*) AS c FROM sqlite_master"
                         " WHERE name = 'alerts_iso_ts'").fetchone()["c"], 0)

    def test_the_indexes_come_back_after_the_rebuild(self):
        # Renaming the table takes its indexes with it under their own names, so
        # recreating them is not automatic - and an alert list with no index on
        # ts is the one query this device runs constantly.
        conn = self._old_shaped_table(["2026-08-23T10:15:00+0200"])
        with db._write_lock:
            db._migrate(conn)
            conn.commit()
        names = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'alerts'")}
        self.assertIn("idx_alerts_ts", names)
        self.assertIn("idx_alerts_et_sev", names)

    def test_the_migration_is_a_no_op_the_second_time(self):
        conn = self._old_shaped_table(["2026-08-23T10:15:00+0200"])
        with db._write_lock:
            db._migrate(conn)
            db._migrate(conn)
            conn.commit()
        self.assertEqual(conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"], 1)

    def test_the_window_is_arithmetic_now_and_survives_a_clock_change(self):
        """Both sides are seconds, so a summer time change is not an event.

        This replaces two tests that policed the shape of a timestamp string:
        that the cutoff carried the local offset, and that it was written with
        %z rather than a colon. Both existed because the comparison was
        lexicographic, and both stopped meaning anything when the column became
        an integer. Neither had anything to say about the case that actually
        went wrong - the hour that repeats at the end of summer time.
        """
        self.assertEqual(db._since(24), db._now() - 86400)

        # 02:30 twice on the same night: once at +0200, once at +0100 an hour
        # later. As strings the later one sorted first, so a window that should
        # hold both held one, and the hourly chart put them in one bucket.
        earlier, later = "2026-10-25T02:30:00+0200", "2026-10-25T02:30:00+0100"
        self.assertLess(int(datetime.fromisoformat(earlier).timestamp()),
                        int(datetime.fromisoformat(later).timestamp()))
        # And as text, the later one sorts first. That is the whole defect.
        self.assertLess(later, earlier)

    def test_window_edge_is_where_it_says(self):
        db.insert_alerts([
            alert(ts=_ago(minutes=90)),
        ])
        self.assertEqual(db.query_alerts(since_hours=1)["total"], 3)
        self.assertEqual(db.query_alerts(since_hours=2)["total"], 4)


class SummaryTest(BackendTestCase):
    def test_counts_and_tops(self):
        db.insert_alerts([
            alert(severity=1, src_ip="203.0.113.7"),
            alert(severity=1, src_ip="203.0.113.7"),
            alert(severity=3, et_severity="Informational", src_ip="198.51.100.4",
                  signature="ET INFO Two", signature_id=1002,
                  category="Not Suspicious Traffic"),
        ])
        summary = db.alert_summary(hours=24)
        self.assertEqual(summary["total_all_time"], 3)
        self.assertEqual(summary["total_window"], 3)
        self.assertEqual(summary["unacknowledged"], 3)
        self.assertEqual(summary["top_sources"][0], {"src_ip": "203.0.113.7", "count": 2})
        # Grouped by ET's rating, which is what the panel colours and filters by.
        self.assertEqual({r["severity"]: r["count"] for r in summary["by_severity"]},
                         {"Major": 2, "Informational": 1})
        self.assertEqual(summary["top_categories"][0]["count"], 2)

    def test_every_figure_counts_the_same_rows(self):
        # A summary where the tile and the chart under it disagree is worse
        # than one that shows too much. Nothing is left out here, so the check
        # is that each figure sees the whole window.
        db.insert_alerts([
            alert(severity=1, et_severity="Critical", signature="Bad", signature_id=1),
            alert(severity=3, et_severity="Informational", signature="ET INFO Noise",
                  signature_id=2),
            alert(severity=3, et_severity="Informational", signature="ET INFO Noise",
                  signature_id=2),
        ])
        s = db.alert_summary(24)
        self.assertEqual(s["total_window"], 3)
        self.assertEqual({r["severity"] for r in s["by_severity"]},
                         {"Critical", "Informational"})
        self.assertEqual(sum(b["count"] for b in s["timeline"]), 3)
        self.assertEqual(sum(r["count"] for r in s["top_signatures"]), 3)

    def test_unacknowledged_is_windowed_not_all_time(self):
        # It counted the whole table on a tile wired to [alarm], so a month of
        # noise left a red badge that could never go back to green.
        db.insert_alerts([alert(ts=_ago(days=40), signature_id=77), alert(signature_id=78)])
        self.assertEqual(db.alert_summary(24)["unacknowledged"], 1)

    def test_timeline_fills_empty_hours_with_zeros(self):
        # Without the zero fill two spikes a day apart draw as constant activity.
        db.insert_alerts([alert()])
        timeline = db.alert_summary(hours=6)["timeline"]
        self.assertEqual(len(timeline), 6)
        self.assertEqual(sum(point["count"] for point in timeline), 1)
        self.assertEqual(timeline[0]["count"], 0)

    # --- long windows are drawn a day at a time ----------------------------
    #
    # The dashboard offers 7 and 30 days as well as 24 hours. Thirty days of
    # hourly buckets is 720 stacked points and 720 labels, so past two days the
    # bucket becomes a day.

    def test_a_long_window_is_bucketed_by_day(self):
        db.insert_alerts([alert(ts=_ago(days=3)), alert(), alert()])
        summary = db.alert_summary(hours=168)
        self.assertEqual(summary["timeline_step_hours"], 24)
        buckets = [point["bucket"] for point in summary["timeline"]]
        # Consecutive calendar days from the one the window opens on to today.
        # Derived from the window rather than counted, because a rolling seven
        # days touches eight dates, and seven or nine across a clock change.
        first = (datetime.now().astimezone() - timedelta(hours=168)).date()
        today = datetime.now().astimezone().date()
        self.assertEqual(buckets, [(first + timedelta(days=n)).isoformat()
                                   for n in range((today - first).days + 1)])
        self.assertEqual(sum(point["count"] for point in summary["timeline"]), 3)
        # Today is the last point, and both of today's alerts are in it.
        self.assertEqual(summary["timeline"][-1]["count"], 2)

    def test_a_short_window_stays_hourly(self):
        summary = db.alert_summary(hours=24)
        self.assertEqual(summary["timeline_step_hours"], 1)
        self.assertEqual(len(summary["timeline"]), 24)

    def test_the_threshold_is_where_it_says(self):
        # 48 hours keeps the hourly shape, which is the one that shows when a
        # burst happened. One hour more and the shape is worth less than the
        # length of the chart.
        self.assertEqual(db.alert_summary(hours=48)["timeline_step_hours"], 1)
        self.assertEqual(db.alert_summary(hours=49)["timeline_step_hours"], 24)

    def test_a_day_bucket_is_a_calendar_day_not_86400_seconds(self):
        # Dividing epoch seconds by 86400 buckets by UTC day, so on any offset
        # east of Greenwich the late evening lands in tomorrow. The label says
        # a date, so it has to be the date a person reading it would write.
        db.insert_alerts([alert(ts=_ago(hours=1))])
        timeline = db.alert_summary(hours=168)["timeline"]
        today = datetime.now().astimezone().date().isoformat()
        self.assertEqual(timeline[-1]["bucket"], today)
        self.assertEqual(timeline[-1]["count"], 1)

    def test_the_bars_add_up_to_the_number_on_the_tile(self):
        # The oldest bar is a part-day because the window is rolling. Rounding
        # it back to midnight would draw alerts the tile does not count, and a
        # tile and a chart that disagree are worse than a short first bar.
        db.insert_alerts([alert(ts=_ago(days=6, hours=23)), alert(ts=_ago(days=40)), alert()])
        summary = db.alert_summary(hours=168)
        self.assertEqual(sum(point["count"] for point in summary["timeline"]),
                         summary["total_window"])

    def test_geo_summary_takes_the_worst_rating(self):
        # A country is coloured by the worst thing seen from it, and "worst" is
        # ET's ordering, not the engine's number.
        db.insert_alerts([
            alert(src_cc="DE", et_severity="Minor", src_ip="198.51.100.4"),
            alert(src_cc="DE", et_severity="Critical", src_ip="198.51.100.5"),
        ])
        row = db.geo_summary(hours=24)[0]
        self.assertEqual((row["code"], row["count"], row["sources"], row["severity"]),
                         ("DE", 2, 2, "Critical"))

    def test_a_country_with_nothing_rated_gets_no_colour(self):
        # Not a severity, so it must not borrow one: GPL and the engine's own
        # stream events would otherwise paint a country as if ET had graded it.
        db.insert_alerts([alert(src_cc="FR", et_severity=None, severity=1,
                                src_ip="203.0.113.9")])
        row = next(r for r in db.geo_summary(hours=24) if r["code"] == "FR")
        self.assertIsNone(row["severity"])

    def test_backfill_only_touches_rows_without_a_country(self):
        db.insert_alerts([alert(src_cc=None, src_ip="203.0.113.7"), alert(src_cc="US")])
        self.assertEqual(db.backfill_countries(lambda ip: "PL"), 1)
        self.assertEqual({r["src_cc"] for r in db.query_alerts()["items"]}, {"PL", "US"})


class DayFilterTest(BackendTestCase):
    """The list takes the same calendar day the dashboard tiles count.

    The point of the whole thing: a tile that says 417 has to open a list that
    says 417. Every earlier version of this screen put two numbers in front of
    the operator and called them the same thing.
    """

    def _fill(self):
        yesterday_start, today_start = db._day_starts(db._now())
        db.insert_alerts([
            alert(ts=today_start + 60, et_severity="Critical", signature_id=1),
            alert(ts=today_start + 61, et_severity="Informational", signature_id=2),
            alert(ts=yesterday_start + 60, et_severity="Major", signature_id=3),
            alert(ts=yesterday_start - 60, et_severity="Major", signature_id=4),
            # An engine note inside today. Without one in the fixture, every
            # assertion below passes whether or not the two sides agree about
            # which rows count, which is the only thing they are here to check.
            alert(ts=today_start + 62, signature_id=2200003,
                  signature="SURICATA STREAM excessive retransmissions"),
        ])

    def test_today_is_the_calendar_day(self):
        self._fill()
        self.assertEqual(db.query_alerts(day="today", kind="alert")["total"], 2)

    def test_yesterday_stops_at_both_ends(self):
        self._fill()
        self.assertEqual(db.query_alerts(day="yesterday", kind="alert")["total"], 1)

    def test_the_day_carries_no_opinion_about_the_kind(self):
        # The day is a period and nothing else. What counts as an alert is the
        # caller's question, and the screen asks it separately.
        self._fill()
        self.assertEqual(db.query_alerts(day="today")["total"], 3)

    def test_the_list_and_the_tile_count_the_same_rows(self):
        self._fill()
        summary = db.alert_summary(24)
        self.assertEqual(db.query_alerts(day="today", kind="alert")["total"],
                         summary["today"])
        self.assertEqual(db.query_alerts(day="yesterday", kind="alert")["total"],
                         summary["yesterday"])

    def test_a_rating_tile_opens_exactly_its_own_rows(self):
        self._fill()
        rated = {r["severity"]: r["count"]
                 for r in db.alert_summary(24)["today_by_severity"]}
        self.assertTrue(rated)
        for severity, count in rated.items():
            with self.subTest(severity=severity):
                self.assertEqual(
                    db.query_alerts(day="today", kind="alert",
                                    severity=severity)["total"], count)

    def test_a_day_nobody_named_is_refused_rather_than_guessed(self):
        with self.assertRaises(ValueError):
            db.day_range("tomorrow")


class ReviewQueueTest(BackendTestCase):
    """The one count on the dashboard that is allowed to be the headline.

    A windowed count falls on its own, because its far edge moves with the
    clock. Measured on the device: 22 alerts an hour left a 24 hour window, so
    the tile counted down through the night with nobody touching it. The queue
    is the answer to a different question and must only move when a person or a
    new alert moves it.
    """

    def test_the_queue_is_not_windowed(self):
        # Forty days old and still unread is still waiting for somebody.
        db.insert_alerts([alert(ts=_ago(days=40), signature_id=77), alert(signature_id=78)])
        self.assertEqual(db.alert_summary(24)["pending"], 2)

    def test_the_queue_counts_threats_only(self):
        # The engine's own notes are not work anybody owes.
        db.insert_alerts([alert(signature_id=78),
                          alert(signature_id=2200003, signature="SURICATA STREAM")])
        self.assertEqual(db.alert_summary(24)["pending"], 1)

    def test_acknowledging_is_what_lowers_it(self):
        db.insert_alerts([alert(signature_id=78), alert(signature_id=79)])
        rows = db.query_alerts(limit=10)["items"]
        db.set_acknowledged(rows[0]["id"], True)
        self.assertEqual(db.alert_summary(24)["pending"], 1)

    def test_acknowledge_all_empties_it(self):
        # Without a bulk action the queue starts at whatever the backlog is and
        # never reaches zero: this device had 12,362 unread rows out of 12,375.
        db.insert_alerts([alert(signature_id=n) for n in (78, 79, 80)])
        self.assertEqual(db.acknowledge_all(db._now()), 3)
        self.assertEqual(db.alert_summary(24)["pending"], 0)

    def test_acknowledge_all_spares_what_arrives_after_the_cutoff(self):
        # The alert that lands while the statement runs is exactly the one
        # nobody would ever see again.
        db.insert_alerts([alert(ts=_ago(hours=1), signature_id=78)])
        cutoff = db._now()
        db.insert_alerts([alert(ts=cutoff + 5, signature_id=79)])
        self.assertEqual(db.acknowledge_all(cutoff), 1)
        self.assertEqual(db.alert_summary(24)["pending"], 1)

    def test_acknowledge_all_clears_the_engine_notes_too(self):
        # The queue on screen counts threats, but the list's "unacknowledged
        # only" filter does not, and leaving notes marked unread would put rows
        # in it right after the operator was told the queue was empty.
        db.insert_alerts([alert(signature_id=2200003, signature="SURICATA STREAM")])
        db.acknowledge_all(db._now())
        self.assertEqual(
            db.query_alerts(limit=10, acknowledged=False, kind=None)["total"], 0)


class CalendarDayTest(BackendTestCase):
    """Today and yesterday, as the calendar has them and not as arithmetic."""

    def test_today_starts_at_local_midnight_not_24_hours_back(self):
        _, today_start = db._day_starts(db._now())
        db.insert_alerts([alert(ts=today_start - 3600, signature_id=1),
                          alert(ts=today_start + 60, signature_id=2)])
        summary = db.alert_summary(24)
        self.assertEqual(summary["today"], 1)
        self.assertEqual(summary["yesterday"], 1)

    def test_yesterday_stops_where_the_day_before_starts(self):
        yesterday_start, _ = db._day_starts(db._now())
        db.insert_alerts([alert(ts=yesterday_start - 60, signature_id=3)])
        self.assertEqual(db.alert_summary(24)["yesterday"], 0)

    def test_the_day_counts_leave_the_engine_notes_out(self):
        _, today_start = db._day_starts(db._now())
        db.insert_alerts([alert(ts=today_start + 60, signature_id=2200003,
                                signature="SURICATA STREAM")])
        summary = db.alert_summary(24)
        self.assertEqual(summary["today"], 0)
        self.assertEqual(summary["diagnostics_today"], 1)

    def test_the_day_is_also_split_by_rating(self):
        # The top of the dashboard answers "how bad", not only "how many", and
        # it answers it per calendar day like the totals beside it.
        _, today_start = db._day_starts(db._now())
        db.insert_alerts([
            alert(ts=today_start + 60, et_severity="Critical", signature_id=1),
            alert(ts=today_start + 61, et_severity="Informational", signature_id=2),
            alert(ts=today_start - 60, et_severity="Critical", signature_id=3),
        ])
        summary = db.alert_summary(24)
        self.assertEqual(summary["today_by_severity"],
                         [{"severity": "Critical", "count": 1},
                          {"severity": "Informational", "count": 1}])
        self.assertEqual(summary["yesterday_by_severity"],
                         [{"severity": "Critical", "count": 1}])

    def test_yesterdays_ratings_stop_at_the_day_before(self):
        yesterday_start, _ = db._day_starts(db._now())
        db.insert_alerts([alert(ts=yesterday_start - 60, et_severity="Critical",
                                signature_id=4)])
        self.assertEqual(db.alert_summary(24)["yesterday_by_severity"], [])

    def test_the_ratings_come_back_worst_first(self):
        # The tiles are a scale. Ordered by count, one loud Informational day
        # would put the tier nobody acts on at the head of the row.
        _, today_start = db._day_starts(db._now())
        db.insert_alerts(
            [alert(ts=today_start + 60, et_severity="Informational", signature_id=n)
             for n in range(10, 20)]
            + [alert(ts=today_start + 61, et_severity="Critical", signature_id=21)])
        self.assertEqual(
            [r["severity"] for r in db.alert_summary(24)["today_by_severity"]],
            ["Critical", "Informational"])

    def test_a_day_is_a_calendar_day_across_a_clock_change(self):
        # The day the clocks go forward is 23 hours long. Built by subtracting
        # a day's worth of seconds from today's midnight, "yesterday at
        # midnight" lands at 01:00, and an hour of alerts is counted on the
        # wrong day.
        import os
        import time as time_mod
        was = os.environ.get("TZ")
        os.environ["TZ"] = "Europe/Warsaw"
        time_mod.tzset()
        try:
            # The EU clocks move forward on Sunday 2026-03-29, so that
            # Sunday is the short day. Read it from the Monday after.
            noon = int(datetime(2026, 3, 30, 12, 0).timestamp())
            yesterday_start, today_start = db._day_starts(noon)
            self.assertEqual(today_start - yesterday_start, 23 * 3600)
            self.assertEqual(datetime.fromtimestamp(today_start).hour, 0)
            self.assertEqual(datetime.fromtimestamp(yesterday_start).hour, 0)
        finally:
            if was is None:
                del os.environ["TZ"]
            else:
                os.environ["TZ"] = was
            time_mod.tzset()


class LoadHistoryTest(BackendTestCase):
    """Two tables on purpose: a week of minutes, and hours kept for good."""

    HOUR = 3600

    def _rows(self, start: int, count: int, step: int = 60, cpu: float = 10.0):
        return [(start + i * step, cpu, cpu, 45.0, 30.0) for i in range(count)]

    def test_samples_round_trip(self):
        db.insert_load_samples(self._rows(1_000_000, 3))
        rows = db.load_samples_since(0)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["ts"], 1_000_000)

    def test_a_batch_written_twice_does_not_double_the_history(self):
        db.insert_load_samples(self._rows(1_000_000, 3))
        db.insert_load_samples(self._rows(1_000_000, 3))
        self.assertEqual(len(db.load_samples_since(0)), 3)

    def test_an_empty_batch_is_not_a_write(self):
        db.insert_load_samples([])
        self.assertEqual(db.load_samples_since(0), [])

    def test_rollup_averages_the_minutes_and_keeps_the_peak(self):
        hour = 1_000_000 // self.HOUR * self.HOUR
        db.insert_load_samples([
            (hour + 60, 10.0, 10.0, 40.0, 20.0),
            (hour + 120, 30.0, 90.0, 50.0, 40.0),
        ])
        db.rollup_load_hours(0, hour + self.HOUR)
        row = db.load_hours_since(0)[0]
        self.assertEqual(row["hour"], hour)
        self.assertEqual((row["cpu"], row["cpu_peak"]), (20.0, 90.0))
        self.assertEqual((row["temp"], row["temp_peak"]), (45.0, 50.0))
        self.assertEqual(row["samples"], 2)

    def test_rollup_is_idempotent(self):
        # It has to be: it runs again over the same hour after a crash.
        hour = 1_000_000 // self.HOUR * self.HOUR
        db.insert_load_samples(self._rows(hour + 60, 5))
        db.rollup_load_hours(0, hour + self.HOUR)
        db.rollup_load_hours(0, hour + self.HOUR)
        rows = db.load_hours_since(0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["samples"], 5)

    def test_rollup_leaves_the_hour_in_progress_alone(self):
        hour = 1_000_000 // self.HOUR * self.HOUR
        db.insert_load_samples(self._rows(hour + 60, 2) + self._rows(hour + self.HOUR + 60, 2))
        db.rollup_load_hours(0, hour + self.HOUR)
        self.assertEqual([r["hour"] for r in db.load_hours_since(0)], [hour])

    def test_rollup_of_nothing_is_not_an_error(self):
        self.assertEqual(db.rollup_load_hours(1000, 1000), 0)

    def test_retention_drops_minutes_and_keeps_the_hours(self):
        now = int(datetime.now(timezone.utc).timestamp())
        old = now - 30 * 86400
        recent = now - 2 * self.HOUR   # a finished hour, so it gets rolled up too
        db.insert_load_samples([(old, 10.0, 10.0, 45.0, 30.0), (recent, 10.0, 10.0, 45.0, 30.0)])
        db.rollup_load_hours(0, now // self.HOUR * self.HOUR)
        db.purge_load_samples(7)
        self.assertEqual(len(db.load_samples_since(0)), 1)
        self.assertEqual(len(db.load_hours_since(0)), 2)

    def test_the_history_starts_at_the_oldest_row_of_either_table(self):
        self.assertIsNone(db.load_history_start())
        hour = 1_000_000 // self.HOUR * self.HOUR
        db.insert_load_samples(self._rows(hour + 60, 2))
        self.assertEqual(db.load_history_start(), hour + 60)
        db.rollup_load_hours(0, hour + self.HOUR)
        db.purge_load_samples(0)
        self.assertEqual(db.load_history_start(), hour)


class ReaderStateTest(BackendTestCase):
    def test_offset_round_trip_is_per_path(self):
        self.assertIsNone(db.load_reader_state("/mnt/ssd/eve.json"))
        db.save_reader_state("/mnt/ssd/eve.json", 42, 1000)
        db.save_reader_state("/var/log/suricata/eve.json", 7, 5)
        self.assertEqual(db.load_reader_state("/mnt/ssd/eve.json"), (42, 1000))
        db.save_reader_state("/mnt/ssd/eve.json", 42, 2000)
        self.assertEqual(db.load_reader_state("/mnt/ssd/eve.json"), (42, 2000))


class AccountTest(BackendTestCase):
    def test_user_round_trip(self):
        self.assertEqual(db.user_count(), 0)
        user_id = db.create_first_user("admin", "hash")
        self.assertEqual(db.user_count(), 1)
        self.assertEqual(db.find_user("admin")["id"], user_id)

    def test_username_is_case_insensitive(self):
        db.create_first_user("Admin", "hash")
        self.assertIsNotNone(db.find_user("admin"))

    def test_only_one_account_can_ever_be_claimed(self):
        """The check and the insert are one statement, so a second call loses.

        Two sign-up requests arriving together used to both succeed as long as
        they picked different usernames: the emptiness check was a separate
        statement and the UNIQUE constraint only covers the name. A device would
        end up with an owner and a stranger, and neither screen would say so.
        """
        self.assertIsNotNone(db.create_first_user("owner", "hash"))
        self.assertIsNone(db.create_first_user("stranger", "hash"))
        self.assertEqual(db.user_count(), 1)
        self.assertIsNone(db.find_user("stranger"))

    def test_password_change_can_end_every_session(self):
        user_id = db.create_first_user("admin", "hash")
        db.create_session("a", user_id, _future(), "browser")
        db.create_session("b", user_id, _future(), "browser")
        db.set_user_password(user_id, "new-hash")
        self.assertEqual(db.delete_sessions_for_user(user_id), 2)
        self.assertIsNone(db.find_session("a"))

    def test_expired_sessions_are_purged(self):
        user_id = db.create_first_user("admin", "hash")
        db.create_session("stale", user_id, _past(), "browser")
        db.create_session("fresh", user_id, _future(), "browser")
        self.assertEqual(db.purge_expired_sessions(), 1)
        self.assertIsNotNone(db.find_session("fresh"))

    def test_session_carries_the_username(self):
        user_id = db.create_first_user("admin", "hash")
        db.create_session("token", user_id, _future(), "browser")
        self.assertEqual(db.find_session("token")["username"], "admin")


class LabellingMigrationTest(BackendTestCase):
    """Rows stored before non-alert events had a name get one on startup.

    They are the ones that show up in the panel as "(unnamed)", which reads as a
    fault in the panel rather than as the engine reporting on itself.
    """

    def _stored(self, signature=None):
        db.insert_alerts([{
            "ts": "2026-08-24T11:12:33+0200", "event_type": "anomaly",
            "signature": signature,
            "raw": {"event_type": "anomaly",
                    "anomaly": {"type": "applayer", "app_proto": "http",
                                "event": "INVALID_GAP"}},
        }])
        return db.query_alerts(limit=1)["items"][0]

    def test_an_unnamed_row_is_named_after_what_it_reports(self):
        self._stored(signature=None)
        db.init()  # runs the migration the way a restart does
        self.assertEqual(self._current()["signature"], "anomaly: http INVALID_GAP")

    def test_a_row_that_already_has_a_name_is_left_alone(self):
        self._stored(signature="ET SCAN Potential SSH Scan")
        db.init()
        self.assertEqual(self._current()["signature"], "ET SCAN Potential SSH Scan")

    def _current(self):
        return db.query_alerts(limit=1)["items"][0]


def _future() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()


def _past() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()


# --- one detection, two records ---

# Taken from the pair that showed up as a 27 minute video call on 2026-09-01:
# the engine's own event rule and the anomaly log describing the same packet.
TWIN_STAMP = "2026-09-01T20:00:03.264376+0200"
TWIN_FLOW = 1125591893090379
TWIN_TS = 1788285603


def _engine_row(event_type: str, *, stamp: str = TWIN_STAMP, flow: int | None = TWIN_FLOW,
                signature_id: int | None = None, signature: str = "",
                event: str = "error_on_data", ts: int = TWIN_TS) -> dict:
    """One EVE record as the tailer hands it over, alert or anomaly."""
    raw: dict = {"event_type": event_type, "timestamp": stamp}
    if flow is not None:
        raw["flow_id"] = flow
    if event_type == "alert":
        raw["alert"] = {"signature": signature, "signature_id": signature_id}
    else:
        raw["anomaly"] = {"app_proto": "quic", "type": "applayer",
                          "event": event, "layer": "proto_parser"}
        signature = signature or f"anomaly: quic {event}"
    return {
        "ts": ts, "event_type": event_type, "src_ip": "203.0.113.229",
        "src_port": 443, "dest_ip": "192.168.1.10", "dest_port": 60172,
        "proto": "UDP", "app_proto": "quic", "signature": signature,
        "signature_id": signature_id, "category": None, "severity": 3,
        "et_severity": None, "iface": "eth1", "src_cc": "IE", "raw": raw,
    }


def _quic_alert(**kw) -> dict:
    kw.setdefault("signature_id", 2231001)
    kw.setdefault("signature", "SURICATA QUIC error on data")
    return _engine_row("alert", **kw)


def _quic_anomaly(**kw) -> dict:
    return _engine_row("anomaly", **kw)


class DuplicateAnomalyTest(BackendTestCase):
    """The engine reports one condition twice; the panel used to count it twice.

    Catches the fault behind the 2026-09-01 20:00 hour: 1034 stored rows for 685
    detections, because every QUIC parser complaint arrived once as an anomaly
    and once as an alert from SURICATA's own event rule. Every figure the
    dashboard draws counts rows, so the hour read half again as bad as it was.
    """

    def test_one_detection_reported_twice_is_stored_once(self):
        kept = db.without_duplicate_anomalies([_quic_alert(), _quic_anomaly()])
        self.assertEqual([row["event_type"] for row in kept], ["alert"])

    def test_the_row_kept_is_the_one_carrying_more(self):
        # The alert has app_proto, direction and the flow counters; the anomaly
        # record is little more than a header. Keeping the wrong one of the two
        # would fix the count and lose the detail view.
        kept = db.without_duplicate_anomalies([_quic_alert(), _quic_anomaly()])
        self.assertEqual(kept[0]["signature"], "SURICATA QUIC error on data")

    def test_an_anomaly_no_rule_reports_is_kept(self):
        # http INVALID_GAP has no event rule behind it, and an anomaly is often
        # the reason an alert that should have fired did not. Dropping every
        # anomaly would pass the test above and lose these.
        rows = [_quic_anomaly(event="INVALID_GAP")]
        self.assertEqual(len(db.without_duplicate_anomalies(rows)), 1)

    def test_an_unrelated_alert_on_the_same_packet_does_not_hide_the_anomaly(self):
        # The killer for a naive key. An ET rule firing on the same packet
        # shares the timestamp and the flow, but reports something else
        # entirely, so it is not the anomaly's twin. Only Suricata's own event
        # rules are.
        rows = [_quic_alert(signature_id=2013028, signature="ET INFO Something"),
                _quic_anomaly()]
        self.assertEqual(len(db.without_duplicate_anomalies(rows)), 2)

    def test_two_flows_in_the_same_microsecond_do_not_cancel_each_other(self):
        rows = [_quic_alert(flow=111), _quic_anomaly(flow=222)]
        self.assertEqual(len(db.without_duplicate_anomalies(rows)), 2)

    def test_the_same_flow_at_a_different_moment_is_a_different_detection(self):
        rows = [_quic_alert(), _quic_anomaly(stamp="2026-09-01T20:00:03.264377+0200")]
        self.assertEqual(len(db.without_duplicate_anomalies(rows)), 2)

    def test_an_anomaly_with_no_flow_is_left_alone(self):
        # A decode anomaly on a packet that never became a flow, next to an
        # engine alert that has no flow either. Timestamp alone is far too weak
        # a key - unrelated records share a microsecond - so an event with no
        # flow of its own is never matched against anything.
        rows = [_quic_alert(flow=None), _quic_anomaly(flow=None)]
        self.assertEqual(len(db.without_duplicate_anomalies(rows)), 2)

    def test_the_pair_is_caught_when_a_batch_boundary_splits_it(self):
        # The engine writes the alert first and the anomaly second, so a flush
        # between the two leaves the alert stored and the anomaly arriving on
        # its own. An in-batch check alone would let this one through.
        db.insert_alerts([_quic_alert()])
        self.assertEqual(db.without_duplicate_anomalies([_quic_anomaly()]), [])

    def test_a_split_batch_still_keeps_an_anomaly_nothing_reported(self):
        db.insert_alerts([_quic_alert(flow=999)])
        kept = db.without_duplicate_anomalies([_quic_anomaly()])
        self.assertEqual(len(kept), 1)

    def test_the_dashboard_counts_the_detection_once(self):
        # The fault as it was seen: a number on the dashboard. Two detections
        # arrive as four records, and the figure used to say four. QUIC parser
        # complaints are the engine's own event rule, so the figure they feed
        # is the diagnostics count beside the tile rather than the tile.
        now = int(datetime.now(timezone.utc).timestamp())
        rows = db.without_duplicate_anomalies([
            _quic_alert(ts=now), _quic_anomaly(ts=now),
            _quic_alert(ts=now, stamp="2026-09-01T20:00:09.111111+0200"),
            _quic_anomaly(ts=now, stamp="2026-09-01T20:00:09.111111+0200"),
        ])
        db.insert_alerts(rows)
        self.assertEqual(db.alert_summary(hours=24)["diagnostics"], 2)


class StoredDuplicateAnomalyTest(BackendTestCase):
    """The same pairing applied once to the rows already on disk."""

    def _seed(self, rows: list[dict]) -> None:
        """Store rows the way the panel did before the check existed."""
        db.insert_alerts(rows)

    def test_stored_duplicates_are_removed_when_the_panel_starts(self):
        self._seed([_quic_alert(), _quic_anomaly()])
        self.assertEqual(db.query_alerts()["total"], 2)
        db._migrate(db.connect())
        items = db.query_alerts()["items"]
        self.assertEqual([row["event_type"] for row in items], ["alert"])

    def test_the_cleanup_leaves_an_anomaly_that_stands_alone(self):
        self._seed([_quic_anomaly(event="INVALID_GAP")])
        db._migrate(db.connect())
        self.assertEqual(db.query_alerts()["total"], 1)

    def test_the_cleanup_does_not_touch_a_packet_an_et_rule_reported(self):
        self._seed([_quic_alert(signature_id=2013028, signature="ET INFO Something"),
                    _quic_anomaly()])
        db._migrate(db.connect())
        self.assertEqual(db.query_alerts()["total"], 2)

    def test_the_cleanup_is_a_no_op_the_second_time(self):
        self._seed([_quic_alert(), _quic_anomaly()])
        db._migrate(db.connect())
        db._migrate(db.connect())
        self.assertEqual(db.query_alerts()["total"], 1)

    def test_the_cleanup_matches_the_microsecond_not_only_the_second(self):
        # ts holds seconds, and this flow produced twelve complaints inside one
        # of them. Same flow, same second, different packet: a cleanup keyed on
        # the ts column would delete an anomaly no alert ever reported.
        self._seed([_quic_alert(),
                    _quic_anomaly(stamp="2026-09-01T20:00:03.900000+0200")])
        db._migrate(db.connect())
        self.assertEqual(db.query_alerts()["total"], 2)

    def test_the_cleanup_matches_the_flow_not_only_the_moment(self):
        self._seed([_quic_alert(), _quic_anomaly(flow=777)])
        db._migrate(db.connect())
        self.assertEqual(db.query_alerts()["total"], 2)

    def test_the_cleanup_leaves_alone_an_anomaly_with_no_flow(self):
        self._seed([_quic_alert(flow=None), _quic_anomaly(flow=None)])
        db._migrate(db.connect())
        self.assertEqual(db.query_alerts()["total"], 2)


class BlockedVerdictTest(BackendTestCase):
    """Which alerts stopped a packet, as opposed to which matched a rule.

    Every EVE alert carries alert.action - 'blocked' or 'allowed' - and nothing
    read it. In blocking mode the list showed what matched and never what was
    stopped, which is the one question somebody running an IPS opens the screen
    to answer.
    """

    def setUp(self):
        super().setUp()
        db.insert_alerts([
            alert(signature="ET MALWARE Stopped", signature_id=2000001,
                  action="blocked"),
            alert(signature="ET MALWARE Seen", signature_id=2000002,
                  action="allowed"),
            alert(signature="ET INFO Old", signature_id=2000003),   # no verdict
        ])

    def test_the_list_can_be_narrowed_to_what_was_stopped(self):
        page = db.query_alerts(blocked=True)
        self.assertEqual(page["total"], 1)
        self.assertEqual(page["items"][0]["signature"], "ET MALWARE Stopped")

    def test_without_the_filter_everything_that_matched_is_listed(self):
        # Most devices read a copy and block nothing, so this must not become a
        # filter that quietly empties the list.
        self.assertEqual(db.query_alerts()["total"], 3)
        self.assertEqual(db.query_alerts(blocked=False)["total"], 3)
        self.assertEqual(db.query_alerts(blocked=None)["total"], 3)

    def test_the_verdict_reaches_the_screen(self):
        by_sig = {a["signature"]: a for a in db.query_alerts()["items"]}
        self.assertEqual(by_sig["ET MALWARE Stopped"]["action"], "blocked")
        self.assertEqual(by_sig["ET MALWARE Seen"]["action"], "allowed")
        self.assertIsNone(by_sig["ET INFO Old"]["action"])

    def test_the_verdict_is_taken_from_the_event_when_the_caller_did_not(self):
        # Same rule as the ET rating: a row can never end up with a raw event
        # saying one thing and a column saying another.
        db.insert_alerts([{**alert(signature="ET MALWARE Raw", signature_id=2000004),
                           "raw": {"event_type": "alert",
                                   "alert": {"signature_id": 2000004,
                                             "action": "blocked"}}}])
        self.assertEqual(db.query_alerts(blocked=True)["total"], 2)

    def _stored_with_verdict(self, verdict: str, sid: int):
        """A row as the engine really wrote it: the verdict inside the event."""
        return {**alert(signature=f"ET MALWARE {verdict} {sid}", signature_id=sid),
                "action": None,
                "raw": {"event_type": "alert",
                        "alert": {"signature_id": sid, "action": verdict}}}

    def test_a_database_from_before_the_column_is_backfilled(self):
        """The answer was in every stored event already.

        Left NULL, "what did this device block" would have been a question about
        when the panel was upgraded rather than about the device.
        """
        db.insert_alerts([self._stored_with_verdict("blocked", 2100001),
                          self._stored_with_verdict("allowed", 2100002)])
        conn = db.connect()
        conn.execute("UPDATE alerts SET action = NULL")
        conn.commit()
        self.assertEqual(db.query_alerts(blocked=True)["total"], 0)

        self.assertEqual(db.backfill_actions(), 2)   # only the two that carry one
        self.assertEqual(db.query_alerts(blocked=True)["total"], 1)

    def test_the_backfill_stops_instead_of_looping_on_rows_with_no_verdict(self):
        # Rows whose event carries no verdict must never be picked up again, or
        # the loop spins on an update that changes nothing.
        db.insert_alerts([self._stored_with_verdict("blocked", 2100003)])
        conn = db.connect()
        conn.execute("UPDATE alerts SET action = NULL")
        conn.commit()
        self.assertEqual(db.backfill_actions(batch=1), 1)
        self.assertEqual(db.backfill_actions(), 0)


class DiagnosticScopeTest(BackendTestCase):
    """Two kinds of row in one table, and every figure used to add them up.

    On the live sensor that was 1176 engine events against 3177 findings: a
    quarter of the dashboard, the whole of one hour's chart, and 1171 entries in
    a queue of things waiting to be reviewed that nobody can review.
    """

    def setUp(self):
        super().setUp()
        db.insert_alerts([
            alert(signature_id=2000001, signature="ET MALWARE One",
                  et_severity="Major", src_ip="203.0.113.7", src_cc="US"),
            alert(signature_id=2013028, signature="ET INFO Two",
                  et_severity="Informational", src_ip="203.0.113.8", src_cc="US"),
            alert(signature_id=2210054, signature="SURICATA STREAM excessive retransmissions",
                  et_severity=None, src_ip="203.0.113.9", src_cc="DE"),
            alert(signature_id=2231001, signature="SURICATA QUIC error on data",
                  et_severity=None, src_ip="203.0.113.9", src_cc="DE"),
            alert(signature_id=None, event_type="anomaly", et_severity=None,
                  signature="anomaly: http INVALID_GAP", src_ip="203.0.113.9",
                  src_cc="DE"),
        ])

    def test_the_list_can_be_asked_for_either_kind_or_both(self):
        self.assertEqual(db.query_alerts(kind="alert")["total"], 2)
        self.assertEqual(db.query_alerts(kind="diagnostic")["total"], 3)
        self.assertEqual(db.query_alerts()["total"], 5)

    def test_the_tile_counts_findings_only(self):
        summary = db.alert_summary(hours=24)
        self.assertEqual(summary["total_window"], 2)
        self.assertEqual(summary["total_all_time"], 2)

    def test_the_summary_counts_what_was_stopped_not_only_what_matched(self):
        """The question an IPS is run for, and the panel could not answer it.

        Every alert already carried the engine's verdict and the list already
        badged it, but nothing counted them - so the way to find out whether
        blocking had ever stopped anything was to scroll.
        """
        db.insert_alerts([
            alert(signature_id=2000002, signature="ET MALWARE Stopped",
                  et_severity="Major", action="blocked"),
            alert(signature_id=2000003, signature="ET MALWARE Seen",
                  et_severity="Major", action="allowed"),
        ])
        self.assertEqual(db.alert_summary(hours=24)["blocked"], 1)

    def test_a_stopped_engine_note_is_not_counted_as_a_block(self):
        # Same scope as every other figure on the dashboard: the engine's own
        # notes are not findings, stopped or otherwise.
        db.insert_alerts([alert(signature_id=2210054, et_severity=None,
                                signature="SURICATA STREAM excessive retransmissions",
                                action="blocked")])
        self.assertEqual(db.alert_summary(hours=24)["blocked"], 0)

    def test_reading_a_copy_means_nothing_is_ever_counted_as_blocked(self):
        # Which is why the tile only appears when the number is above zero.
        self.assertEqual(db.alert_summary(hours=24)["blocked"], 0)

    def test_the_diagnostics_are_counted_but_kept_apart(self):
        # Excluded from every figure, never hidden: the number is reported so
        # the screen and the stored rows still add up for anybody who checks.
        self.assertEqual(db.alert_summary(hours=24)["diagnostics"], 3)

    def test_the_review_queue_holds_only_things_that_can_be_reviewed(self):
        # The fault as it was lived with: 1171 retransmission notices sitting in
        # "unacknowledged only". A retransmission is not a piece of work.
        self.assertEqual(db.alert_summary(hours=24)["unacknowledged"], 2)

    def test_the_top_lists_are_not_led_by_the_engine_talking_to_itself(self):
        summary = db.alert_summary(hours=24)
        listed = [row["signature"] for row in summary["top_signatures"]]
        self.assertEqual(sorted(listed), ["ET INFO Two", "ET MALWARE One"])
        self.assertNotIn("203.0.113.9", [r["src_ip"] for r in summary["top_sources"]])

    def test_the_chart_bars_are_findings_only(self):
        bars = db.alert_summary(hours=24)["timeline"]
        self.assertEqual(sum(b["count"] for b in bars), 2)

    def test_the_long_window_chart_too(self):
        # A separate query with its own WHERE clause, so it needs its own test:
        # the daily path is the one a 30 day window uses.
        bars = db.alert_summary(hours=720)["timeline"]
        self.assertEqual(sum(b["count"] for b in bars), 2)

    def test_the_map_does_not_colour_a_country_for_a_retransmission(self):
        codes = [row["code"] for row in db.geo_summary(hours=24)]
        self.assertEqual(codes, ["US"])

    def test_the_diagnostic_list_holds_nothing_from_the_rule_set(self):
        # The list the "engine notes" link opens. There used to be a second
        # query grouping these by rule for a screen of their own; the list they
        # are in already searches, windows and pages, so this is that list.
        rows = db.query_alerts(kind="diagnostic")["items"]
        sids = {r["signature_id"] for r in rows}
        self.assertNotIn(2000001, sids)
        self.assertNotIn(2013028, sids)
        self.assertEqual(sids, {2210054, 2231001, None})

    def test_the_diagnostic_list_takes_the_same_filters_as_the_alert_list(self):
        # Being one list rather than a widget is the point: a window and a
        # search have to keep working when the kind changes.
        db.insert_alerts([alert(signature_id=2210054, et_severity=None,
                                signature="SURICATA STREAM excessive retransmissions",
                                ts=_ago(days=40))])
        self.assertEqual(db.query_alerts(kind="diagnostic", since_hours=24)["total"], 3)
        self.assertEqual(db.query_alerts(kind="diagnostic", since_hours=8000)["total"], 4)
        self.assertEqual(
            db.query_alerts(kind="diagnostic", search="QUIC")["total"], 1)

    def test_the_range_covers_the_engine_rules_at_both_ends(self):
        """The agreement test cannot see this one: both predicates share the
        constant, so narrowing it keeps them agreeing with each other and wrong
        about the engine. Pinned with SIDs Suricata really ships, one near each
        end of the block it reserves for its own event rules.
        """
        for sid, name in ((2200121, "SURICATA Ethertype unknown"),
                          (2260003, "SURICATA Applayer Protocol detection skipped")):
            with self.subTest(signature=name):
                self.assertTrue(db.is_diagnostic(
                    {"event_type": "alert", "signature_id": sid}), name)
        # And the rule set's own findings stay outside it at both ends.
        for sid in (2000001, 2013504, 2400001):
            with self.subTest(signature_id=sid):
                self.assertFalse(db.is_diagnostic(
                    {"event_type": "alert", "signature_id": sid}))

    def test_the_python_split_agrees_with_the_sql_split(self):
        """Two predicates for one rule is how a rule ends up meaning two things.

        DIAGNOSTIC_SQL decides what the screens count; db.is_diagnostic decides
        what goes out live and into the mail queue. Run over the same rows they
        have to give the same answer, or the panel hides a thing on one path and
        emails it on another.
        """
        conn = db.connect()
        stored = conn.execute(
            f"SELECT id, event_type, signature_id, {db.DIAGNOSTIC_SQL} AS sql_says "
            "FROM alerts").fetchall()
        self.assertTrue(stored)
        for row in stored:
            with self.subTest(id=row["id"], signature_id=row["signature_id"]):
                self.assertEqual(
                    db.is_diagnostic({"event_type": row["event_type"],
                                      "signature_id": row["signature_id"]}),
                    bool(row["sql_says"]))

    def test_the_split_reads_a_signature_id_the_row_carries_only_in_its_raw(self):
        # The tailer hands over rows before they are stored, and a row whose
        # column is not filled in yet still has the id in the EVE record.
        self.assertTrue(db.is_diagnostic(
            {"event_type": "alert", "signature_id": None,
             "raw": {"alert": {"signature_id": 2210054}}}))
        self.assertFalse(db.is_diagnostic(
            {"event_type": "alert", "signature_id": None,
             "raw": {"alert": {"signature_id": 2000001}}}))

    def test_the_two_kinds_add_up_to_everything_stored(self):
        # The invariant that makes the split safe: nothing falls between them,
        # including the anomaly row, which has no signature_id at all.
        both = (db.query_alerts(kind="alert")["total"]
                + db.query_alerts(kind="diagnostic")["total"])
        self.assertEqual(both, db.query_alerts()["total"])
