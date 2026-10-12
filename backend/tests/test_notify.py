"""Alert notifications by e-mail.

The thing worth testing here is not SMTP - it is the restraint around it. A
sensor on a mirror port can raise hundreds of alerts an hour, and every rule in
this module exists to keep the mailbox readable.
"""
from __future__ import annotations

import queue
import re
import time
from email.message import EmailMessage
from unittest.mock import MagicMock, patch

from app import settings
from app import db
from app.modules.suricata import notify

from .helpers import PROJECT_ROOT, BackendTestCase


def alert(**overrides):
    row = {
        "id": 1,
        "ts": "2026-08-23T10:15:00+0200",
        "signature": "ET MALWARE Test",
        "signature_id": 2000001,
        "severity": 1,
        # ET's own rating, which is what decides what goes out. See db.rating_rank.
        "et_severity": "Critical",
        "src_ip": "203.0.113.7",
        "src_port": 44321,
        "dest_ip": "192.168.1.10",
        "dest_port": 443,
        "proto": "TCP",
    }
    row.update(overrides)
    return row


WORKING = {
    "enabled": True,
    "host": "smtp.example.net",
    "port": 587,
    "security": "starttls",
    "username": "ids@example.net",
    "password": "secret",
    "sender": "ids@example.net",
    "recipients": ["someone@example.net"],
    "min_severity": 2,
    "digest_seconds": 300,
    "max_per_hour": 6,
}


class ConfigTest(BackendTestCase):
    def test_defaults_are_off(self):
        current = notify.config()
        self.assertFalse(current["enabled"])
        self.assertEqual(current["recipients"], [])

    def test_saving_keeps_the_password_when_the_field_is_blank(self):
        # The form cannot show what is stored, so it cannot send it back.
        settings.set(notify.SETTINGS_KEY, dict(WORKING))
        notify.save({"host": "smtp2.example.net"})
        self.assertEqual(notify.config()["password"], "secret")

    def test_a_password_can_still_be_removed_on_purpose(self):
        settings.set(notify.SETTINGS_KEY, dict(WORKING))
        notify.save({"clear_password": True})
        self.assertEqual(notify.config()["password"], "")

    def test_the_password_never_leaves_the_device(self):
        settings.set(notify.SETTINGS_KEY, dict(WORKING))
        public = notify.public_config()
        self.assertNotIn("password", public)
        self.assertTrue(public["password_set"])

    def test_addresses_are_checked_before_the_server_sees_them(self):
        with self.assertRaises(notify.ConfigError) as raised:
            notify.save({**WORKING, "recipients": ["someone at example.net"]})
        self.assertIn("someone at example.net", str(raised.exception))

    def test_addresses_can_be_typed_one_per_line(self):
        notify.save({**WORKING, "recipients": "a@example.net\nb@example.net, a@example.net"})
        self.assertEqual(notify.config()["recipients"], ["a@example.net", "b@example.net"])

    def test_turning_it_on_without_somewhere_to_send_is_refused(self):
        for missing, message in (("host", "mail server"), ("recipients", "send to"),
                                 ("sender", "come from")):
            with self.subTest(missing=missing):
                broken = {**WORKING, missing: "" if missing != "recipients" else []}
                with self.assertRaises(notify.ConfigError) as raised:
                    notify.save(broken)
                self.assertIn(message, str(raised.exception))

    def test_half_filled_settings_can_be_saved_while_it_is_off(self):
        # Otherwise the form cannot be filled in over two visits.
        notify.save({"enabled": False, "host": "smtp.example.net"})
        self.assertEqual(notify.config()["host"], "smtp.example.net")

    def test_an_unknown_security_mode_is_refused(self):
        with self.assertRaises(notify.ConfigError):
            notify.save({**WORKING, "security": "tls-ish"})

    def test_numbers_are_bounded_rather_than_rejected(self):
        notify.save({**WORKING, "max_per_hour": 9999, "min_severity": 0,
                     "digest_seconds": 999999})
        current = notify.config()
        self.assertEqual(current["max_per_hour"], 120)
        self.assertEqual(current["min_severity"], 1)
        self.assertEqual(current["digest_seconds"], 3600)

    def test_a_port_that_is_not_a_number(self):
        with self.assertRaises(notify.ConfigError):
            notify.save({**WORKING, "port": "smtp"})


class RatingTest(BackendTestCase):
    """Which scale decides what reaches a mailbox."""

    def test_the_engine_number_does_not_set_the_word_in_the_message(self):
        # This went out as "major" before: the label was keyed by Suricata's
        # priority, so an alert ET rates Informational arrived looking urgent.
        body = notify.compose([alert(severity=2, et_severity="Informational")]).get_content()
        self.assertIn("informational: 1", body)
        self.assertNotIn("major", body)

    def test_a_rule_ET_never_rated_falls_back_on_the_engine(self):
        body = notify.compose([alert(severity=1, et_severity=None)]).get_content()
        self.assertIn("critical: 1", body)

    def test_a_priority_that_is_not_a_number_does_not_take_the_reader_down(self):
        """severity comes out of the EVE record and nothing checked it.

        A string reached `priority <= 3` as a TypeError, out of submit(), whose
        own docstring promises it never raises. It escapes into the reader loop,
        which restarts from the saved offset, reads the same line and raises
        again: a crash every two seconds, on one malformed line.
        """
        for value in ("high", [], {}, "1"):
            with self.subTest(severity=value):
                self.assertEqual(db.rating_rank(None, value), 4)

    def test_a_priority_outside_the_tiers_still_has_a_label(self):
        # A local rule written with priority 0 gave rank 0, and _describe looks
        # the label up by rank with a subscript: KeyError inside the digest
        # sender, which re-queues the batch and sends it again.
        for value in (0, -1, 99):
            with self.subTest(severity=value):
                rank = db.rating_rank(None, value)
                self.assertIn(rank, notify.SEVERITY_LABELS)

    def test_a_boolean_is_not_a_priority(self):
        # bool is a subclass of int, so `true` in a record would otherwise be
        # read as priority 1, which is the most urgent tier there is.
        self.assertEqual(db.rating_rank(None, True), 4)

    def test_the_whole_queue_survives_such_an_alert(self):
        # The promise submit() makes, end to end rather than one function deep.
        notifier = notify._Notifier()
        notifier.submit(alert(severity="high", et_severity=None))
        notifier.submit(alert(severity=0, et_severity=None))

    def test_the_threshold_ranks_by_the_rule_set_not_the_engine(self):
        # The mail threshold is the one place a rating still decides anything,
        # so it has to rank the way the list orders: ET's label first, the
        # engine priority only for a rule ET never rated.
        self.assertEqual(db.rating_rank("Informational", 1), 4)
        self.assertEqual(db.rating_rank(None, 1), 1)
        self.assertEqual(db.rating_rank(None, 3), 4)


class ComposeTest(BackendTestCase):
    def test_the_subject_carries_the_whole_summary(self):
        # Somebody glancing at a phone should not have to open the message to
        # learn whether it can wait until morning.
        message = notify.compose([alert(), alert(et_severity="Minor")], hostname="rapi-ids")
        self.assertEqual(message["Subject"], "IDS on rapi-ids: 2 alerts (critical)")

    def test_one_alert_is_not_called_alerts(self):
        self.assertIn("1 alert (", notify.compose([alert()])["Subject"])

    def test_the_body_counts_signatures_and_sources(self):
        body = notify.compose([alert(), alert(), alert(src_ip="198.51.100.4")]).get_content()
        self.assertIn("3 x ET MALWARE Test", body)
        self.assertIn("2 x 203.0.113.7", body)

    def test_the_body_names_severities_in_words(self):
        body = notify.compose([alert(et_severity="Critical"),
                               alert(et_severity="Informational")]).get_content()
        self.assertIn("critical: 1", body)
        self.assertIn("informational: 1", body)

    def test_only_a_sample_of_the_alerts_is_listed(self):
        body = notify.compose([alert(id=i) for i in range(25)]).get_content()
        self.assertIn("and 15 more in the panel", body)

    def test_what_the_limit_held_back_is_reported_not_hidden(self):
        body = notify.compose([alert()], suppressed=40).get_content()
        self.assertIn("40 further alerts were held back", body)

    def test_the_message_is_plain_text(self):
        # Read on a phone at 3 am, and by whatever the mail client is.
        self.assertEqual(notify.compose([alert()]).get_content_type(), "text/plain")


class SendTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        settings.set(notify.SETTINGS_KEY, dict(WORKING))
        self.smtp = MagicMock()
        self.smtp_ssl = MagicMock()

    def _send(self, **overrides):
        current = {**notify.config(), **overrides}
        with patch.object(notify.smtplib, "SMTP", return_value=self.smtp) as plain, \
             patch.object(notify.smtplib, "SMTP_SSL", return_value=self.smtp_ssl) as secure:
            notify.send(EmailMessage(), current)
        return plain, secure

    def test_starttls_is_negotiated_and_the_login_used(self):
        plain, secure = self._send()
        plain.assert_called_once()
        secure.assert_not_called()
        self.smtp.starttls.assert_called_once()
        self.smtp.login.assert_called_once_with("ids@example.net", "secret")
        self.smtp.send_message.assert_called_once()

    def test_implicit_tls_opens_the_other_kind_of_socket(self):
        plain, secure = self._send(security="ssl")
        secure.assert_called_once()
        plain.assert_not_called()
        self.smtp_ssl.starttls.assert_not_called()

    def test_a_server_without_a_login_is_not_handed_one(self):
        self._send(username="", security="none")
        self.smtp.login.assert_not_called()
        self.smtp.starttls.assert_not_called()

    def test_the_addresses_go_on_the_message(self):
        message = EmailMessage()
        with patch.object(notify.smtplib, "SMTP", return_value=self.smtp):
            notify.send(message, notify.config())
        self.assertEqual(message["From"], "ids@example.net")
        self.assertEqual(message["To"], "someone@example.net")

    def test_a_connection_that_will_not_close_is_not_a_failure(self):
        self.smtp.quit.side_effect = OSError("already gone")
        self._send()   # must not raise

    def test_nothing_configured(self):
        with self.assertRaises(notify.ConfigError):
            notify.send(EmailMessage(), {**notify.config(), "host": ""})


class NotifierTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        settings.set(notify.SETTINGS_KEY, dict(WORKING))
        self.notifier = notify._Notifier()
        self.sent: list[EmailMessage] = []
        self.enterContext(patch.object(
            notify, "send", side_effect=lambda message, current=None: self.sent.append(message)
        ))

    def _queue(self, *alerts):
        for entry in alerts:
            self.notifier.submit(entry)
        self.notifier._drain()

    def test_alerts_below_the_chosen_severity_are_not_queued(self):
        self._queue(alert(et_severity="Critical"), alert(et_severity="Minor"))
        self.assertEqual(len(self.notifier._pending), 1)

    def test_nothing_is_queued_while_it_is_off(self):
        notify.save({**WORKING, "enabled": False})
        self._queue(alert())
        self.assertEqual(self.notifier._pending, [])

    def test_the_reader_is_never_blocked_by_a_full_queue(self):
        # The caller is the eve.json reader: it must not raise there, and the
        # drop has to be counted rather than hidden.
        self.notifier._queue = queue.Queue(maxsize=1)
        self._queue(alert())
        self.notifier.submit(alert())
        self.notifier.submit(alert())
        self.assertEqual(self.notifier.status()["dropped"], 1)

    def test_alerts_are_collected_before_anything_is_sent(self):
        self._queue(alert())
        self.notifier._maybe_send()
        self.assertEqual(self.sent, [])

    def test_the_digest_goes_out_once_the_window_has_passed(self):
        self._queue(alert(), alert(et_severity="Major"))
        self.notifier._collecting_since = time.time() - 301
        self.notifier._maybe_send()
        self.assertEqual(len(self.sent), 1)
        self.assertIn("2 alerts", self.sent[0]["Subject"])
        self.assertEqual(self.notifier._pending, [])

    def test_immediately_means_immediately(self):
        notify.save({**WORKING, "digest_seconds": 0})
        self._queue(alert())
        self.notifier._maybe_send()
        self.assertEqual(len(self.sent), 1)

    def test_the_hourly_limit_holds_alerts_back_instead_of_dropping_them(self):
        notify.save({**WORKING, "max_per_hour": 1, "digest_seconds": 0})
        self._queue(alert())
        self.notifier._maybe_send()
        self._queue(alert(), alert())
        self.notifier._maybe_send()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.notifier.status()["held_back"], 2)

    def test_what_was_held_back_is_reported_in_the_next_message(self):
        notify.save({**WORKING, "max_per_hour": 1, "digest_seconds": 0})
        self._queue(alert())
        self.notifier._maybe_send()
        self._queue(alert())
        self.notifier._maybe_send()          # over the limit, held back
        self.notifier._sent_at = []          # an hour goes by
        self._queue(alert())
        self.notifier._maybe_send()
        self.assertIn("1 further alert", self.sent[-1].get_content())

    def test_a_mail_server_that_is_down_keeps_the_alerts(self):
        # They come back on the next attempt rather than being lost to a
        # connection error nobody saw.
        with patch.object(notify, "send", side_effect=OSError("connection refused")):
            self._queue(alert())
            self.notifier._collecting_since = time.time() - 301
            self.notifier._maybe_send()
        self.assertEqual(len(self.notifier._pending), 1)
        self.assertIn("connection refused", self.notifier.status()["last_error"])

        self.notifier._collecting_since = time.time() - 301
        self.notifier._maybe_send()
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.notifier.status()["last_error"], "")

    def test_turning_it_off_drops_what_was_waiting(self):
        self._queue(alert())
        notify.save({**WORKING, "enabled": False})
        self.notifier._collecting_since = time.time() - 301
        self.notifier._maybe_send()
        self.assertEqual(self.sent, [])
        self.assertEqual(self.notifier._pending, [])

    def test_the_test_message_says_what_it_is(self):
        self.notifier.hostname = "rapi-ids"
        self.notifier.send_test()
        self.assertIn("test message", self.sent[0]["Subject"])
        self.assertIsNotNone(self.notifier.status()["last_sent_at"])

    def test_a_failed_test_is_remembered_and_raised(self):
        with patch.object(notify, "send", side_effect=OSError("authentication failed")):
            with self.assertRaises(OSError):
                self.notifier.send_test()
        self.assertIn("authentication failed", self.notifier.status()["last_error"])

    def test_a_clean_shutdown_sends_what_it_has(self):
        self.notifier.start()
        self.addCleanup(self.notifier.stop)
        self._queue(alert())
        self.notifier.stop()
        self.assertEqual(len(self.sent), 1)


class ThresholdTest(BackendTestCase):
    """What "Everything" actually lets through.

    Every other threshold test here asks what is kept out. This one asks the
    opposite, and it exists because reading DEFAULTS and reasoning forward
    gives the wrong answer about this device. The alerts a mirror-port sensor
    really produces are the engine's own reports: no ET rating at all, engine
    priority 3, and therefore the bottom tier. On the default threshold the
    mailbox stays silent; on the lowest one every single one of them arrives.
    Both halves are behaviour somebody depends on, so both are pinned here.
    """

    # A row copied off the live sensor rather than invented: the stream engine
    # complaining about what a mirror port shows it. Nothing rates it.
    ENGINE_REPORT = {
        "signature": "SURICATA STREAM excessive retransmissions",
        "signature_id": 2210059,
        "et_severity": None,
        "severity": 3,
    }

    def setUp(self):
        super().setUp()
        self.notifier = notify._Notifier()
        self.enterContext(patch.object(
            notify, "send", side_effect=lambda message, current=None: None
        ))

    def _pending_after(self, threshold, entry):
        settings.set(notify.SETTINGS_KEY, {**WORKING, "min_severity": threshold})
        self.notifier.submit(entry)
        self.notifier._drain()
        return self.notifier._pending

    def test_an_unrated_engine_report_lands_on_the_bottom_tier(self):
        # Not an accident of the fixture: priority 3 is past
        # LOWEST_INTERESTING_PRIORITY, so it is capped rather than carried.
        self.assertEqual(db.rating_rank(None, 3), len(db.ET_SEVERITIES))

    def test_everything_includes_the_engines_own_reports(self):
        pending = self._pending_after(len(db.ET_SEVERITIES), alert(**self.ENGINE_REPORT))
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["signature"], self.ENGINE_REPORT["signature"])

    def test_the_default_threshold_keeps_them_out_entirely(self):
        self.assertEqual(self._pending_after(2, alert(**self.ENGINE_REPORT)), [])

    def test_the_lowest_choice_offered_by_the_gui_is_the_lowest_tier(self):
        # The bottom option is the only one that carries engine reports, so if
        # a tier is ever added to db.ET_SEVERITIES and the select is not
        # touched, "Everything" quietly stops meaning everything.
        source = (PROJECT_ROOT / "frontend" / "src" / "app" / "features" / "ids"
                  / "notify.ts").read_text(encoding="utf-8")
        # Only this select. The digest one sits right below it and counts
        # seconds, so a looser pattern reads 3600 as a severity.
        block = re.search(r"severityOptions = \[(.*?)\];", source, re.S)
        self.assertIsNotNone(block, "severityOptions is not where this test looks")
        offered = [int(value) for value in re.findall(r"value: (\d+)", block.group(1))]
        self.assertEqual(max(offered), len(db.ET_SEVERITIES))
        self.assertEqual(offered, list(range(1, len(db.ET_SEVERITIES) + 1)))


class QueueGrowthTest(BackendTestCase):
    """What happens while the mail server is not there.

    Found on the live sensor: the panel was pointed at 127.0.0.1:2525, a test
    SMTP server that had been shut down, and had been retrying every five
    minutes for hours. The retry is right. Keeping every alert forever while it
    retries was not: QUEUE_MAX bounds the Queue the reader writes to, but
    _drain() empties that Queue into a plain list once a second, and a failed
    send put the whole batch back into that list untrimmed.
    """

    def setUp(self):
        super().setUp()
        settings.set(notify.SETTINGS_KEY, dict(WORKING))
        self.notifier = notify._Notifier()
        # Small enough to reach in a test, exercised exactly as the real one is.
        self.enterContext(patch.object(notify, "QUEUE_MAX", 3))

    def _queue(self, count):
        for _ in range(count):
            self.notifier.submit(alert())
        self.notifier._drain()

    def test_the_collected_batch_is_bounded_too_not_just_the_queue(self):
        # The Queue is almost always empty because _drain empties it every
        # second, so its own maxsize never comes into play.
        self._queue(10)
        self.assertEqual(len(self.notifier._pending), 3)
        self.assertEqual(self.notifier.status()["dropped"], 7)

    def test_nothing_is_dropped_while_there_is_room(self):
        # A cap that trips early would throw away alerts on a healthy device.
        self._queue(3)
        self.assertEqual(len(self.notifier._pending), 3)
        self.assertEqual(self.notifier.status()["dropped"], 0)

    def test_a_server_that_refuses_does_not_grow_the_batch_without_end(self):
        # The live fault, in miniature: connection refused, over and over.
        with patch.object(notify, "send", side_effect=ConnectionRefusedError(111, "refused")):
            for _ in range(5):
                self._queue(2)
                self.notifier._collecting_since = 0
                self.notifier._maybe_send()
        self.assertEqual(len(self.notifier._pending), 3)
        self.assertIn("refused", self.notifier.status()["last_error"])

    def test_the_alerts_that_were_waiting_first_are_the_ones_kept(self):
        # The same choice a full Queue makes, so the two paths cannot disagree
        # about which end of the backlog survives.
        for i in range(6):
            self.notifier.submit(alert(signature=f"S{i}"))
        self.notifier._drain()
        self.assertEqual([a["signature"] for a in self.notifier._pending],
                         ["S0", "S1", "S2"])

    def test_the_cap_holds_on_the_way_back_in_as_well(self):
        # Today only the notifier thread writes to _pending, and it drains then
        # sends in that order, so the batch coming back cannot be over the cap
        # by itself. The trim on that path is there for the day that stops being
        # true - a second writer, or a drain moved anywhere else - and this is
        # what that day looks like: alerts waiting again by the time the send
        # comes back with an error.
        self._queue(2)
        def fail_and_refill(message, current=None):
            self.notifier._pending.extend([alert(), alert(), alert()])
            raise ConnectionRefusedError(111, "refused")
        with patch.object(notify, "send", side_effect=fail_and_refill):
            self.notifier._collecting_since = 0
            self.notifier._maybe_send()
        self.assertEqual(len(self.notifier._pending), 3)
        self.assertEqual(self.notifier.status()["dropped"], 2)

    def test_a_failed_send_still_puts_the_batch_back(self):
        # The point of the retry, which the cap must not quietly undo: a mail
        # server that comes back has to find the alerts still waiting.
        self._queue(2)
        with patch.object(notify, "send", side_effect=OSError("down")):
            self.notifier._collecting_since = 0
            self.notifier._maybe_send()
        self.assertEqual(len(self.notifier._pending), 2)
        self.assertEqual(self.notifier.status()["dropped"], 0)

    def test_what_is_waiting_counts_both_places_an_alert_can_be(self):
        self._queue(2)
        self.notifier.submit(alert())
        self.assertEqual(self.notifier.status()["waiting"], 3)
