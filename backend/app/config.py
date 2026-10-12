"""Panel configuration. Every value can be overridden with a RAPI_* env var."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def _env_path(name: str, default: str) -> Path:
    return Path(os.environ.get(name, default)).expanduser()


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


# --- server ---
HOST = os.environ.get("RAPI_HOST", "0.0.0.0")
PORT = _env_int("RAPI_PORT", 8000)

# --- TLS ---
# Both files must exist for the panel to serve HTTPS. Missing means plain HTTP,
# so a fresh checkout still starts before scripts/setup-tls.sh has been run.
TLS_DIR = _env_path("RAPI_TLS_DIR", str(BASE_DIR / "data" / "tls"))
TLS_CERT = _env_path("RAPI_TLS_CERT", str(TLS_DIR / "server.crt"))
TLS_KEY = _env_path("RAPI_TLS_KEY", str(TLS_DIR / "server.key"))


def tls_enabled() -> bool:
    """True only when the server was actually started with TLS.

    Set by the systemd unit alongside the --ssl-* flags. Dev mode (scripts/dev.sh)
    leaves it unset and stays on plain HTTP, so the redirect listeners do not
    fight uvicorn for port 8000 there.
    """
    if os.environ.get("RAPI_SERVE_TLS", "0") != "1":
        return False
    return TLS_CERT.is_file() and TLS_KEY.is_file()


# Ports answering plain HTTP with a redirect to HTTPS. Without this an old
# bookmark on :8000 fails with a TLS parse error, which reads like the panel is
# broken rather than moved.
HTTP_REDIRECT_PORTS = [
    int(p) for p in os.environ.get("RAPI_HTTP_REDIRECT_PORTS", "80,8000").split(",")
    if p.strip().isdigit()
]

# Origins allowed to call the API in dev mode (ng serve on :4200).
CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "RAPI_CORS_ORIGINS", "http://localhost:4200,http://127.0.0.1:4200"
    ).split(",")
    if o.strip()
]

# --- authentication ---
# Two limits, because they answer different questions. The first is how long a
# session may live at all; the second is how long it may sit unused. Without the
# second one a cookie on a laptop left in a hotel stays good for a month, and
# the only remedy is changing the password, which ends every other session too.
SESSION_DAYS = _env_int("RAPI_SESSION_DAYS", 30)
SESSION_IDLE_HOURS = _env_int("RAPI_SESSION_IDLE_HOURS", 24)

# How stale the recorded "last seen" may get before it is written again. Every
# authenticated request used to update that row, and the dashboard alone polls
# every five seconds: an appliance running from an SD card should not spend its
# write cycles on a timestamp nothing reads at that resolution. The idle limit
# above is measured in hours, so minutes of drift cost nothing.
SESSION_TOUCH_SECONDS = _env_int("RAPI_SESSION_TOUCH_SECONDS", 300)

# Close code for a live WebSocket whose session has ended. 1008 (policy
# violation) is what the handshake answers with, and reusing it here would tell
# the client "your cookie was never good". This one means "it was, and it is not
# any more", which is the difference between reconnecting and going to the
# sign-in screen. 4000-4999 is the range applications may define.
WS_SESSION_ENDED = 4001

# Failed sign-ins tolerated per address inside the window before a 429.
LOGIN_MAX_ATTEMPTS = _env_int("RAPI_LOGIN_MAX_ATTEMPTS", 8)
LOGIN_WINDOW_SECONDS = _env_int("RAPI_LOGIN_WINDOW_SECONDS", 300)

# The interactive API docs list every route. They are off unless asked for -
# on an appliance the schema is a map for someone who should not have one.
ENABLE_DOCS = os.environ.get("RAPI_ENABLE_DOCS", "0") == "1"

# --- data ---
DATA_DIR = _env_path("RAPI_DATA_DIR", str(BASE_DIR / "data"))
DB_PATH = DATA_DIR / "panel.db"

# --- suricata module ---
EVE_PATH = _env_path("RAPI_EVE_PATH", "/var/log/suricata/eve.json")
SURICATA_LOG = _env_path("RAPI_SURICATA_LOG", "/var/log/suricata/suricata.log")
SURICATA_RULES_DIR = _env_path("RAPI_RULES_DIR", "/var/lib/suricata/rules")

# How many days of alerts to keep. The SD card is small, so this is bounded.
ALERT_RETENTION_DAYS = _env_int("RAPI_ALERT_RETENTION_DAYS", 30)

# How long minute-by-minute device load is kept. Above that the history lives on
# as hourly averages, which is what a question like "has this been getting worse
# since we installed it" actually needs.
LOAD_SAMPLE_DAYS = _env_int("RAPI_LOAD_SAMPLE_DAYS", 7)

# Size of the in-memory ring buffer with non-alert events (live traffic view).
RECENT_EVENTS_BUFFER = _env_int("RAPI_RECENT_EVENTS_BUFFER", 300)

# EVE event types persisted to SQLite. Everything else stays in memory only -
# flow/dns events would wear out the SD card with thousands of writes a minute.
PERSISTED_EVENT_TYPES = {"alert", "anomaly"}
