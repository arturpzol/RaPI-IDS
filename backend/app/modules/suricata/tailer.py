"""eve.json reader.

Runs in its own thread (file IO is blocking) and hands events to the async
world through the main event loop. It handles:
  * resuming from the last offset after a panel restart,
  * log rotation (inode change) and truncation,
  * partial lines (the engine writes while we read),
  * batching of SQLite writes.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any

from ... import config, db, geoip, settings
from ...hub import hub
from .notify import notifier

log = logging.getLogger(__name__)

# How many events to collect before a batch write / how long to wait at most.
BATCH_MAX = 200
BATCH_MAX_WAIT = 0.5
IDLE_SLEEP = 0.25
STATE_SAVE_INTERVAL = 5.0


# What the sensor is allowed to lose before the screen says so. Both are the
# same threshold and it is not ours: Zeek documents capture loss as something
# that "should never exceed 1%", and Security Onion colours its per-node loss
# figures on the same scale. A capture error is different - the kernel telling
# us the ring is broken - so one is one too many.
#
# Measured against the engine's own counters rather than against its decoder
# event rules. The rules fire per packet, so five of them in a week made the
# screen red on a device dropping nothing at all out of 13.7 million packets.
MAX_DROP_PERCENT = 1.0
MAX_GAP_PERCENT = 1.0


def _as_int(value: Any) -> int | None:
    """An EVE field that has to be a number, or None.

    Every other field here is text and survives whatever the line contained.
    This one is compared against a threshold and used as a dictionary key, so a
    string reached the mail queue as a TypeError and took the reader down with
    it: the loop restarted from the saved offset, read the same line, and did it
    again every two seconds.

    bool is excluded on purpose. It is a subclass of int, so `true` in a record
    would otherwise be stored as the priority 1, which is "critical".
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _resume_at(fh: Any, partial: str) -> int:
    """Where to start reading again, given a line the engine is mid-way through.

    The file position is past those bytes, but they have not been handled: they
    are sitting in `partial`, in memory, which a restart does not survive.
    Saving the raw position means the next run seeks past the start of that
    line and reads its tail as a line of its own, which fails to parse and is
    counted as an error. One alert, silently, every time the panel restarts
    while the engine happens to be writing.

    Encoded length, not len(): the reader decodes as UTF-8, and a signature with
    one non-ASCII character would put the offset a byte or two into the line.
    """
    return max(0, fh.tell() - len(partial.encode("utf-8")))


def sensor_problem(drop_rate: float | None, capture_errors: int | None,
                   gap_rate: float) -> str | None:
    """Which of the three the operator has to be told about, worst first.

    Drops beat gaps: a dropped packet is traffic the engine never saw at all,
    while a reassembly gap is one stream it could not put back together.

    None for drop_rate or capture_errors means the engine does not publish that
    counter in the mode it is running. Absence is not zero, and answering "no
    fault" from a counter that does not exist is the failure this signature
    exists to make impossible: the caller has to pass None and the screen has to
    say it does not know.
    """
    if drop_rate is not None and drop_rate > MAX_DROP_PERCENT:
        return "drops"
    if capture_errors is not None and capture_errors > 0:
        return "errors"
    if gap_rate > MAX_GAP_PERCENT:
        return "gaps"
    return None


class SuricataState:
    """Runtime state of the module - everything we do not persist."""

    def __init__(self) -> None:
        self.event_counts: Counter[str] = Counter()
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=config.RECENT_EVENTS_BUFFER)
        self.last_stats: dict[str, Any] | None = None
        self.last_stats_at: int | None = None
        self.last_event_at: int | None = None
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.lines_read = 0
        self.parse_errors = 0
        self.reader_alive = False

    def snapshot(self) -> dict[str, Any]:
        stats = self.last_stats or {}
        capture = stats.get("capture", {})
        decoder = stats.get("decoder", {})
        tcp = stats.get("tcp", {})
        ips = stats.get("ips", {})
        # Which way the engine is taking packets, and whether it is stopping
        # anything. Two questions, because the two sections are not exclusive:
        # an inline af-packet pair publishes both, and reading "ips" as the
        # capture method reported a kernel bridge as a netfilter queue on every
        # screen that named the mechanism. Checked on this device: a stats
        # record in copy-mode ips carries "capture" with real kernel_packets
        # and "ips" beside it.
        #
        # Read here rather than from the YAML because an include replaces the
        # whole key, so the file the panel parses is not proof of what is
        # running - and because a drop-in can change the command line without
        # touching any YAML at all, which is exactly what the blocking switch
        # does.
        mode = "af-packet" if capture else ("nfqueue" if ips else None)
        # The engine has a verdict to give on each packet: either it is reading
        # from a queue, or it is forwarding an inline pair itself.
        blocking = bool(ips)
        # Capture loss exists only where there is a capture. In NFQUEUE mode
        # netfilter hands packets over one at a time and there is no ring to
        # overflow, so there is no kernel_drops to read - and reading the
        # missing section as zero is how this panel spent an evening reporting
        # a healthy sensor while it inspected nothing at all.
        measured = bool(capture)
        pkts = decoder.get("pkts", 0)
        drops = capture.get("kernel_drops", 0) if measured else None
        errors = capture.get("errors", 0) if measured else None
        total = pkts + (drops or 0)
        sessions = tcp.get("sessions", 0)
        gaps = tcp.get("reassembly_gap", 0)
        drop_rate = round(drops / total * 100, 3) if measured and total else (
            0.0 if measured else None)
        gap_rate = round(gaps / sessions * 100, 3) if sessions else 0.0
        return {
            "reader_alive": self.reader_alive,
            "eve_path": str(settings.eve_path()),
            "panel_started_at": self.started_at,
            "lines_read": self.lines_read,
            "parse_errors": self.parse_errors,
            "last_event_at": self.last_event_at,
            "last_stats_at": self.last_stats_at,
            "event_counts": dict(self.event_counts),
            "engine": {
                "uptime_seconds": (self.last_stats or {}).get("uptime"),
                "packets": pkts,
                "bytes": decoder.get("bytes", 0),
                "kernel_packets": capture.get("kernel_packets") if measured else None,
                "kernel_drops": drops,
                "capture_errors": errors,
                "drop_rate_percent": drop_rate,
                "capture_mode": mode,
                "blocking": blocking,
                # False means "this cannot be known here", which is a different
                # answer from "nothing was lost" and has to reach the screen as
                # a different answer.
                "loss_measured": measured,
                "tcp_sessions": sessions,
                "reassembly_gaps": gaps,
                "gap_rate_percent": gap_rate,
                # What the engine stopped while inline, and how much of that any
                # rule asked for. The two differ: exception policies and
                # midstream pickup drop flows on their own.
                "blocked": ips.get("blocked") if ips else None,
                "blocked_by_rules": (ips.get("drop_reason", {}).get("rules")
                                     if ips else None),
                "sensor_problem": sensor_problem(drop_rate, errors, gap_rate),
                "alerts_detected": (self.last_stats or {}).get("detect", {}).get("alert", 0),
                "flows": (self.last_stats or {}).get("flow", {}).get("total", 0),
            },
        }


state = SuricataState()


def _label_for(event: dict[str, Any]) -> str | None:
    """A name for a stored event that carries no signature of its own.

    Anomalies are the engine reporting on itself - "the parser lost part of this
    stream", "this packet made no sense" - and they are stored because they
    belong in the same timeline as the alerts: an anomaly is usually the reason
    an alert that should have fired did not. They have no signature, so without
    this the row showed up as (unnamed), which reads like a fault in the panel
    rather than a report from the engine.
    """
    etype = event.get("event_type") or ""
    if etype == "anomaly":
        anomaly = event.get("anomaly") or {}
        where = anomaly.get("app_proto") or anomaly.get("layer") or anomaly.get("type")
        what = anomaly.get("event")
        named = " ".join(part for part in (where, what) if part)
        return f"anomaly: {named}" if named else "anomaly"
    return etype or None


def _epoch(timestamp: str | None) -> int:
    """The engine's timestamp as Unix seconds, which is how everything stores it.

    EVE writes local time with an offset ("2026-08-21T20:55:55.142414+0200").
    Kept as that string it sorted and compared as text, which is chronological
    only while the offset holds still - and it does not, twice a year. Converted
    once here, on the way in, so nothing downstream has to know the engine's
    timezone or think about the shape of the string.

    An event with no timestamp, or one that will not parse, gets the moment it
    was read. Dropping it would lose an alert over a clock; putting it in the
    far past or future would hide it from every window there is.
    """
    if timestamp:
        try:
            when = datetime.fromisoformat(timestamp)
        except (TypeError, ValueError):
            log.warning("Unreadable timestamp %r, using arrival time", timestamp)
        else:
            if when.tzinfo is None:
                when = when.astimezone()
            return int(when.timestamp())
    return int(datetime.now(timezone.utc).timestamp())


def _flatten_alert(event: dict[str, Any]) -> dict[str, Any]:
    """Pull the columns we filter on out of a raw EVE event."""
    alert = event.get("alert") or {}
    return {
        "ts": _epoch(event.get("timestamp")),
        "event_type": event.get("event_type", "alert"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "app_proto": event.get("app_proto"),
        "signature": alert.get("signature") or _label_for(event),
        "signature_id": alert.get("signature_id"),
        "category": alert.get("category"),
        "severity": _as_int(alert.get("severity")),
        # ET's own rating of the rule, which is a different scale from the
        # number above and disagrees with it constantly. See db.et_severity_of.
        "et_severity": db.et_severity_of(event),
        # 'blocked' or 'allowed'. Only ever 'blocked' while the engine is inline
        # on a queue: reading a copy it can report and nothing else.
        "action": alert.get("action"),
        "iface": event.get("in_iface"),
        # Resolved here, once per alert, instead of on every dashboard refresh.
        "src_cc": geoip.classify(event.get("src_ip")),
        "raw": event,
    }


def _summarize_event(event: dict[str, Any]) -> dict[str, Any]:
    """Lightweight view of a non-alert event (live feed, without the full JSON)."""
    etype = event.get("event_type", "?")
    summary: dict[str, Any] = {
        "ts": _epoch(event.get("timestamp")),
        "event_type": etype,
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "app_proto": event.get("app_proto"),
    }
    if etype == "dns":
        dns = event.get("dns") or {}
        summary["detail"] = dns.get("rrname") or dns.get("query", [{}])[0].get("rrname")
    elif etype == "tls":
        tls = event.get("tls") or {}
        summary["detail"] = tls.get("sni") or tls.get("subject")
    elif etype == "http":
        http = event.get("http") or {}
        summary["detail"] = f"{http.get('http_method', '')} {http.get('hostname', '')}{http.get('url', '')}".strip()
    elif etype == "flow":
        flow = event.get("flow") or {}
        summary["detail"] = f"{flow.get('pkts_toserver', 0)}/{flow.get('pkts_toclient', 0)} pkt"
    return summary


class EveTailer:
    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._path = str(settings.eve_path())

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="eve-tailer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3.0)

    # --- publishing into the async world ---

    def _publish(self, topic: str, payload: Any) -> None:
        """Called from the reader thread - hence call_soon_threadsafe."""
        try:
            self._loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(hub.broadcast(topic, payload))
            )
        except RuntimeError:
            pass  # loop closed during shutdown

    # --- main loop ---

    def _run(self) -> None:
        log.info("Tailer starting: %s", self._path)
        while not self._stop.is_set():
            try:
                self._tail_once()
            except FileNotFoundError:
                state.reader_alive = False
                log.warning("No such file %s, waiting...", self._path)
                self._stop.wait(2.0)
            except Exception:
                state.reader_alive = False
                log.exception("eve.json reader failed, restarting in 2s")
                self._stop.wait(2.0)
        state.reader_alive = False
        log.info("Tailer stopped")

    def _save_offset(self, ino: int, offset: int) -> None:
        """Never fatal. A full disk makes this raise, and letting it out of the
        loop turns "the database cannot be written" into a crash-restart cycle
        that logs a traceback every two seconds - which fills the journal on the
        volume that was already full.

        What a lost offset costs is re-reading lines after a restart, and those
        alerts are inserted a second time; there is no unique key on the table.
        That is the lesser harm, and in the case that actually causes it the
        inserts are failing for the same reason, so there is nothing to double.
        """
        try:
            db.save_reader_state(self._path, ino, offset)
        except Exception:
            log.warning("Could not record the read offset", exc_info=True)

    def _tail_once(self) -> None:
        st = os.stat(self._path)
        saved = db.load_reader_state(self._path)

        with open(self._path, "r", encoding="utf-8", errors="replace") as fh:
            if saved and saved[0] == st.st_ino and saved[1] <= st.st_size:
                fh.seek(saved[1])
                log.info("Resuming from offset %d", saved[1])
            else:
                # New/rotated file: start at the end so the first run does not
                # import the whole history.
                fh.seek(0, os.SEEK_END)
                log.info("Starting at end of file (offset %d)", fh.tell())

            state.reader_alive = True
            batch: list[dict[str, Any]] = []
            batch_started = time.monotonic()
            last_state_save = time.monotonic()
            partial = ""

            while not self._stop.is_set():
                line = fh.readline()

                if line:
                    if not line.endswith("\n"):
                        # The engine is still writing this line - pick it up next round.
                        partial += line
                        continue
                    if partial:
                        line = partial + line
                        partial = ""
                    state.lines_read += 1
                    event = self._parse(line)
                    if event is not None:
                        self._handle_event(event, batch)
                    if len(batch) >= BATCH_MAX:
                        self._flush(batch)
                        batch_started = time.monotonic()
                    continue

                # EOF - flush the batch, check for rotation, then idle
                now = time.monotonic()
                if batch and now - batch_started >= BATCH_MAX_WAIT:
                    self._flush(batch)
                    batch_started = now
                if now - last_state_save >= STATE_SAVE_INTERVAL:
                    self._save_offset(st.st_ino, _resume_at(fh, partial))
                    last_state_save = now
                if self._rotated(st, fh):
                    self._flush(batch)
                    self._save_offset(st.st_ino, _resume_at(fh, partial))
                    log.info("Log rotated, reopening the file")
                    return
                self._stop.wait(IDLE_SLEEP)

            self._flush(batch)
            self._save_offset(st.st_ino, _resume_at(fh, partial))

    def _rotated(self, st: os.stat_result, fh: Any) -> bool:
        try:
            current = os.stat(self._path)
        except FileNotFoundError:
            return True
        if current.st_ino != st.st_ino:
            return True
        return current.st_size < fh.tell()  # truncate

    def _parse(self, line: str) -> dict[str, Any] | None:
        line = line.strip()
        if not line:
            return None
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            state.parse_errors += 1
            return None
        # "[1,2]" and "null" are valid JSON and not events. Without this the
        # .get() below raised AttributeError, which the outer loop treats as a
        # crash: it restarts from the last saved offset, reads the same line,
        # and does it again every two seconds for as long as the file is there.
        # One malformed record could stop the panel seeing any alert ever again.
        if not isinstance(event, dict):
            state.parse_errors += 1
            return None
        return event

    def _handle_event(self, event: dict[str, Any], batch: list[dict[str, Any]]) -> None:
        etype = event.get("event_type", "unknown")
        state.event_counts[etype] += 1
        state.last_event_at = _epoch(event.get("timestamp"))

        if etype == "stats":
            state.last_stats = event.get("stats") or {}
            state.last_stats_at = _epoch(event.get("timestamp"))
            self._publish("suricata.stats", state.snapshot())
            return

        if etype in config.PERSISTED_EVENT_TYPES:
            batch.append(_flatten_alert(event))
            return

        summary = _summarize_event(event)
        state.recent_events.append(summary)
        self._publish("suricata.event", summary)

    def _flush(self, batch: list[dict[str, Any]]) -> None:
        if not batch:
            return
        # Before the insert, not after: a row filtered out here was never
        # stored, so it is never published either, and the live feed cannot
        # show a row that a later cleanup would take away again.
        rows = db.without_duplicate_anomalies(list(batch))
        batch.clear()
        if not rows:
            return
        try:
            ids = db.insert_alerts(rows)
        except Exception:
            log.exception("Failed to store %d alerts", len(rows))
            return
        for alert_id, row in zip(ids, rows):
            # Stored, and that is all. The engine's own notes are not findings:
            # they have their own place in the alert list and their own card on
            # the engine tab, and putting them on the live stream put them in
            # the "new alerts" count, in the recent list on the dashboard and in
            # the mail queue - where "SURICATA Ethertype unknown", a note with
            # no source, destination or protocol, would be sent to somebody as
            # something to look at.
            if db.is_diagnostic(row):
                continue
            payload = {k: v for k, v in row.items() if k != "raw"}
            payload["id"] = alert_id
            payload["acknowledged"] = False
            self._publish("suricata.alert", payload)
            # Queued, never sent from here: an SMTP server that takes half a
            # minute to answer must not stall the reader feeding the panel.
            notifier.submit(payload)


_tailer: EveTailer | None = None
_loop: asyncio.AbstractEventLoop | None = None


def start_tailer(loop: asyncio.AbstractEventLoop) -> None:
    global _tailer, _loop
    _loop = loop
    _tailer = EveTailer(loop)
    _tailer.start()


def stop_tailer() -> None:
    if _tailer:
        _tailer.stop()


def restart_tailer() -> None:
    """After a log directory change the reader has to pick up the new path.

    The offset is remembered per path (reader_state table), so switching back
    to a previous directory resumes exactly where we left off.
    """
    global _tailer
    if _loop is None:
        return
    if _tailer:
        _tailer.stop()
    _tailer = EveTailer(_loop)
    _tailer.start()
    log.info("Reader switched to %s", settings.eve_path())
