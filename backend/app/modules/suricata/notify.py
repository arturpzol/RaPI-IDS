"""Alert notifications by e-mail.

A panel nobody opens reports nothing. This is the part that reaches out, and it
is built around one assumption: **the mailbox is the scarce resource**, not the
alerts. A sensor on a mirror port can raise hundreds of alerts an hour, and a
message per alert is a mailbox that gets a filter rule within a day and is never
read again.

So alerts are collected for a few minutes and sent as one digest, there is a cap
on messages per hour, and everything the cap holds back is counted and reported
in the next message rather than dropped silently.

`smtplib` and `email.message` from the standard library, so no new packages -
the same rule as the rest of the panel.

The queue is handed alerts by the eve.json reader thread, and the sending
happens in a thread of its own: an SMTP server that takes thirty seconds to
answer must not be able to stall the reader that feeds the whole panel.
"""
from __future__ import annotations

import logging
import queue
import smtplib
import ssl
import threading
import time
from collections import Counter
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

from ... import db, settings

log = logging.getLogger(__name__)

SETTINGS_KEY = "email"

# Bounded on purpose. If the queue ever fills, the sender is stuck or the
# network is gone, and holding a million alerts in memory would turn a mail
# problem into an out-of-memory problem.
#
# The cap has to be applied twice, and for a while it was applied once. Alerts
# live in two places: the Queue the reader thread writes to, and the _pending
# list the sending thread collects a digest in. _drain() empties one into the
# other every second, so the Queue is almost always empty and its maxsize never
# comes into play - and a failed send puts the whole batch straight back into
# _pending. Point the panel at an SMTP server that is not there and _pending
# grows for as long as the device is up, which is exactly the outcome this
# constant exists to prevent.
QUEUE_MAX = 5000

SMTP_TIMEOUT = 30
SECURITY_MODES = ("none", "starttls", "ssl")

# What a rating is called in a message. Keyed by db.rating_rank, which is ET's
# own scale with the engine priority as a fallback - not by Suricata's number.
# Keying it by the number was wrong in a way that reached the mailbox: an alert
# ET rates Informational but the engine gives priority 2 went out as "major".
SEVERITY_LABELS = {1: "critical", 2: "major", 3: "minor", 4: "informational"}


def _rank(alert: dict[str, Any]) -> int:
    return db.rating_rank(alert.get("et_severity"), alert.get("severity"))


class ConfigError(ValueError):
    """The settings cannot produce a message - said in words a person can act on."""


def config() -> dict[str, Any]:
    """Stored settings, with defaults filled in for keys added later."""
    stored = settings.get(SETTINGS_KEY) or {}
    return dict(settings.DEFAULTS[SETTINGS_KEY], **stored)


def _clean(raw: dict[str, Any], previous: dict[str, Any]) -> dict[str, Any]:
    """Validate what the form sent, keeping the password when it was left blank.

    A blank password field means "leave it alone" rather than "clear it",
    because the form cannot show what is stored: the API never sends it out.
    """
    out = dict(previous)
    out["enabled"] = bool(raw.get("enabled", previous["enabled"]))
    out["host"] = str(raw.get("host", previous["host"])).strip()
    out["username"] = str(raw.get("username", previous["username"])).strip()
    out["sender"] = str(raw.get("sender", previous["sender"])).strip()

    password = raw.get("password")
    if password:
        out["password"] = str(password)
    elif raw.get("clear_password"):
        out["password"] = ""

    security = str(raw.get("security", previous["security"])).strip().lower()
    if security not in SECURITY_MODES:
        raise ConfigError(f"unknown connection security: {security}")
    out["security"] = security

    try:
        out["port"] = int(raw.get("port", previous["port"]))
    except (TypeError, ValueError):
        raise ConfigError("the port has to be a number") from None
    if not 1 <= out["port"] <= 65535:
        raise ConfigError("the port has to be between 1 and 65535")

    recipients = raw.get("recipients", previous["recipients"])
    if isinstance(recipients, str):
        recipients = recipients.replace(",", "\n").split("\n")
    cleaned: list[str] = []
    for entry in recipients:
        address = str(entry).strip()
        if not address:
            continue
        # Not an RFC validator - just enough to catch a typed name or a stray
        # comma before it becomes an SMTP error nobody can read.
        if "@" not in address or address.startswith("@") or address.endswith("@"):
            raise ConfigError(f"{address!r} is not an e-mail address")
        if address not in cleaned:
            cleaned.append(address)
    out["recipients"] = cleaned

    out["min_severity"] = _bounded(raw, previous, "min_severity", 1, 4)
    out["digest_seconds"] = _bounded(raw, previous, "digest_seconds", 0, 3600)
    out["max_per_hour"] = _bounded(raw, previous, "max_per_hour", 1, 120)

    if out["enabled"]:
        if not out["host"]:
            raise ConfigError("name the mail server to send through")
        if not out["recipients"]:
            raise ConfigError("name at least one address to send to")
        if not out["sender"]:
            # Falling back to the username would be a guess; on most servers the
            # two are the same, but a wrong From is a message the server refuses.
            raise ConfigError("name the address the mail should come from")
    return out


def _bounded(raw: dict[str, Any], previous: dict[str, Any], key: str,
             low: int, high: int) -> int:
    try:
        value = int(raw.get(key, previous[key]))
    except (TypeError, ValueError):
        raise ConfigError(f"{key} has to be a number") from None
    return max(low, min(high, value))


def save(raw: dict[str, Any]) -> dict[str, Any]:
    cleaned = _clean(raw, config())
    settings.set(SETTINGS_KEY, cleaned)
    log.info("E-mail notifications %s", "on" if cleaned["enabled"] else "off")
    return cleaned


def public_config() -> dict[str, Any]:
    """What the settings screen may see. Everything except the password."""
    current = config()
    out = {k: v for k, v in current.items() if k != "password"}
    out["password_set"] = bool(current["password"])
    return out


# --- composing ---


def _describe(alert: dict[str, Any]) -> str:
    label = SEVERITY_LABELS[_rank(alert)]
    source = alert.get("src_ip") or "?"
    if alert.get("src_port"):
        source += f":{alert['src_port']}"
    target = alert.get("dest_ip") or "?"
    if alert.get("dest_port"):
        target += f":{alert['dest_port']}"
    return (f"{alert.get('ts', '')}  [{label}]  {alert.get('signature') or '(unnamed)'}\n"
            f"    {source} -> {target}  {alert.get('proto') or ''}").rstrip()


def compose(alerts: list[dict[str, Any]], suppressed: int = 0,
            hostname: str = "") -> EmailMessage:
    """One digest message. Plain text, because this is read on a phone at 3 am.

    The subject carries the whole summary: how many, how bad, and from where.
    Somebody glancing at a notification should not have to open it to learn
    whether it can wait until morning.
    """
    by_severity = Counter(_rank(a) for a in alerts)
    worst = min(by_severity, default=len(SEVERITY_LABELS))
    signatures = Counter(a.get("signature") or "(unnamed)" for a in alerts)
    sources = Counter(a.get("src_ip") for a in alerts if a.get("src_ip"))

    where = f" on {hostname}" if hostname else ""
    count = len(alerts)
    subject = (f"IDS{where}: {count} alert{'s' if count != 1 else ''}"
               f" ({SEVERITY_LABELS[worst]})")

    lines = [
        f"{count} alert{'s' if count != 1 else ''} from the intrusion detection engine"
        f"{where}.",
        "",
        "By severity: " + ", ".join(
            f"{SEVERITY_LABELS.get(sev, sev)}: {n}" for sev, n in sorted(
                by_severity.items(), key=lambda kv: (kv[0] is None, kv[0]))
        ),
        "",
        "Signatures:",
    ]
    lines += [f"  {n} x {name}" for name, n in signatures.most_common(10)]
    if len(signatures) > 10:
        lines.append(f"  ... and {len(signatures) - 10} more")

    if sources:
        lines += ["", "Busiest sources:"]
        lines += [f"  {n} x {ip}" for ip, n in sources.most_common(5)]

    # The newest first: the last thing that happened is the thing being asked
    # about. Ten of them is enough to recognise the shape of the problem; the
    # panel has the rest.
    lines += ["", "Most recent:"]
    lines += [_describe(alert) for alert in list(reversed(alerts))[:10]]
    if count > 10:
        lines.append(f"  ... and {count - 10} more in the panel")

    if suppressed:
        lines += [
            "",
            f"{suppressed} further alert{'s' if suppressed != 1 else ''} were held back "
            "by the hourly message limit. They are all in the panel.",
        ]

    message = EmailMessage()
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()
    message.set_content("\n".join(lines) + "\n")
    return message


def _test_message(hostname: str = "") -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = f"IDS{f' on {hostname}' if hostname else ''}: test message"
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()
    message.set_content(
        "This is the test message from the RaPi IDS panel.\n\n"
        "It means the mail settings work. Real messages are sent as digests: "
        "alerts are collected for a few minutes and arrive as one message.\n"
    )
    return message


# --- sending ---


def send(message: EmailMessage, current: dict[str, Any] | None = None) -> None:
    """Deliver one message. Raises with whatever the server said."""
    current = current or config()
    if not current["host"]:
        raise ConfigError("no mail server configured")
    if not current["recipients"]:
        raise ConfigError("no recipients configured")

    message["From"] = current["sender"] or current["username"]
    message["To"] = ", ".join(current["recipients"])

    context = ssl.create_default_context()
    if current["security"] == "ssl":
        server = smtplib.SMTP_SSL(current["host"], current["port"],
                                  timeout=SMTP_TIMEOUT, context=context)
    else:
        server = smtplib.SMTP(current["host"], current["port"], timeout=SMTP_TIMEOUT)
    try:
        if current["security"] == "starttls":
            server.starttls(context=context)
        if current["username"]:
            server.login(current["username"], current["password"])
        server.send_message(message)
    finally:
        try:
            server.quit()
        except Exception:      # noqa: BLE001 - a closed socket is not a failure
            pass


class _Notifier:
    """Collects alerts, sends digests, and remembers what happened last."""

    def __init__(self) -> None:
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=QUEUE_MAX)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        self._pending: list[dict[str, Any]] = []
        self._collecting_since = 0.0
        self._sent_at: list[float] = []      # timestamps inside the last hour
        self._suppressed = 0
        self._dropped = 0
        self.last_sent_at: float | None = None
        self.last_error: str = ""
        self.hostname: str = ""

    # --- from the reader thread ---

    def submit(self, alert: dict[str, Any]) -> None:
        """Never blocks and never raises: the caller is the eve.json reader."""
        current = config()
        if not current["enabled"]:
            return
        if _rank(alert) > current["min_severity"]:
            return
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            with self._lock:
                self._dropped += 1

    # --- the sending thread ---

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="notifier", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._drain()
                self._maybe_send()
            except Exception:
                log.exception("Notifier loop failed")
            self._stop.wait(1.0)
        # A clean shutdown sends what it has rather than losing it.
        try:
            self._drain()
            if self._pending:
                self._send_digest(config())
        except Exception:
            log.exception("Could not send the last digest")

    def _drain(self) -> None:
        while True:
            try:
                alert = self._queue.get_nowait()
            except queue.Empty:
                return
            with self._lock:
                if len(self._pending) >= QUEUE_MAX:
                    # Same policy as a full Queue: the ones already waiting are
                    # kept and the new arrival is counted as dropped. The screen
                    # reports the count, so a mail server that has been down for
                    # a week says so rather than quietly eating memory.
                    self._dropped += 1
                    continue
                if not self._pending:
                    self._collecting_since = time.time()
                self._pending.append(alert)

    def _maybe_send(self) -> None:
        with self._lock:
            if not self._pending:
                return
            waited = time.time() - self._collecting_since
        current = config()
        if waited < current["digest_seconds"]:
            return
        self._send_digest(current)

    def _send_digest(self, current: dict[str, Any]) -> None:
        if not current["enabled"]:
            with self._lock:
                self._pending = []
            return

        now = time.time()
        with self._lock:
            self._sent_at = [t for t in self._sent_at if now - t < 3600]
            if len(self._sent_at) >= current["max_per_hour"]:
                # Not e-mailed. The alerts stay in the panel; only their count
                # travels, in the next message, which goes out when a new alert
                # arrives. The screen says exactly this.
                self._suppressed += len(self._pending)
                self._pending = []
                return
            alerts, self._pending = self._pending, []
            suppressed, self._suppressed = self._suppressed, 0

        try:
            send(compose(alerts, suppressed, self.hostname), current)
        except Exception as err:
            log.warning("Could not send the alert digest: %s", err)
            with self._lock:
                self.last_error = str(err)
                # Back into the queue in front of whatever arrived meanwhile, so
                # a mail server that comes back finds the alerts still waiting -
                # but not without the cap. This is the path that runs every five
                # minutes while the server is refusing connections, and without
                # the trim it is the one that grows without limit.
                returning = alerts + self._pending
                self._pending = returning[:QUEUE_MAX]
                self._dropped += len(returning) - len(self._pending)
                self._suppressed += suppressed
                self._collecting_since = time.time()
            return

        with self._lock:
            self._sent_at.append(now)
            self.last_sent_at = now
            self.last_error = ""
        log.info("Sent an alert digest: %d alerts", len(alerts))

    # --- for the settings screen ---

    def send_test(self) -> None:
        current = config()
        try:
            send(_test_message(self.hostname), current)
        except Exception as err:
            with self._lock:
                self.last_error = str(err)
            raise
        with self._lock:
            self.last_sent_at = time.time()
            self.last_error = ""

    def status(self) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            return {
                "running": self._thread is not None and self._thread.is_alive(),
                "waiting": len(self._pending) + self._queue.qsize(),
                "held_back": self._suppressed,
                "dropped": self._dropped,
                "sent_last_hour": len([t for t in self._sent_at if now - t < 3600]),
                "last_sent_at": self.last_sent_at,
                "last_error": self.last_error,
            }


notifier = _Notifier()
