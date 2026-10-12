"""REST endpoints of the Suricata module."""
from __future__ import annotations

import logging
import subprocess
import time
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ... import config, db, geoip, settings
from . import logdir, notify, protection
from .tailer import state

log = logging.getLogger(__name__)
router = APIRouter(prefix="/suricata", tags=["suricata"])

# How far the engine's own alert counter and the panel's row count may sit
# apart before it means anything. Both move; only a gap that keeps growing
# is a reader falling behind.
ALERT_COUNT_SLACK = 10

SERVICE = "suricata"
# Only these actions may be triggered from the UI - no arbitrary commands.
# Only the rule reload is reachable from the panel. Starting, stopping and
# restarting the engine came out of the GUI, and out of this list with it: an
# endpoint that still accepted them would leave the narrowing cosmetic. The
# panel does still restart the engine of its own accord - a log directory move
# and a capture change both need it - but that goes straight to systemctl from
# the code that knows why, not through a route anyone can call.
ALLOWED_ACTIONS = {"reload"}


def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f"{' '.join(cmd)} did not finish within {timeout} s"
    except FileNotFoundError:
        return 127, f"command not found: {cmd[0]}"


@router.get("/status")
def get_status() -> dict[str, Any]:
    """Engine state plus the state of our own reader."""
    rc_active, active = _run(["systemctl", "is-active", SERVICE], timeout=10)
    _, enabled = _run(["systemctl", "is-enabled", SERVICE], timeout=10)
    snapshot = state.snapshot()
    # Rides along with the service state instead of being asked for once when a
    # screen loads: an interface can go down at any moment, and a warning that
    # only appears on a page reload is a warning nobody sees.
    snapshot["capture"] = protection.capture_link()
    # The engine counts what it raised; this counts what reached the table. The
    # pair is the only reading of that counter worth putting on a screen: equal
    # means nothing was lost between the two, and a gap is a reader falling
    # behind or an eve.json the panel is not following.
    uptime = snapshot["engine"].get("uptime_seconds")
    raised = snapshot["engine"].get("alerts_detected") or 0
    stored = db.stored_since(int(time.time()) - int(uptime)) if uptime else None
    snapshot["engine"]["alerts_stored"] = stored
    # The engine samples its counters every 8 seconds and the cutoff here has
    # one second of resolution, so the two never land on the same number and a
    # handful either way is the clock rather than a loss. Measured on this
    # device: 1131 raised against 1132 stored, from one row on the wrong side
    # of the boundary.
    snapshot["engine"]["alerts_missing"] = (
        None if stored is None else
        (0 if raised - stored <= max(ALERT_COUNT_SLACK, raised // 100)
         else raised - stored))
    snapshot["service"] = {
        "name": SERVICE,
        "active": active,
        "running": rc_active == 0,
        "enabled": enabled,
        "version": _run(["suricata", "-V"], timeout=10)[1].replace(
            "This is Suricata version ", ""
        ),
    }
    return snapshot


@router.post("/service/{action}")
def control_service(action: Literal["reload"]) -> dict[str, Any]:
    if action not in ALLOWED_ACTIONS:
        raise HTTPException(status_code=400, detail="action not allowed")
    ok, out = protection.reload_engine()
    if not ok:
        raise HTTPException(status_code=500, detail=out or f"{action} failed")
    return {"action": action, "ok": True, "output": out}


@router.get("/alerts")
def list_alerts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: str | None = Query(
        None,
        description="ET's own rating of the rule, or 'unrated' for rules that "
                    "carry none. Not Suricata's numeric alert.severity: the two "
                    "scales are independent and disagree constantly, which is "
                    "why this column exists at all. See db.ET_SEVERITIES.",
    ),
    src_ip: str | None = None,
    dest_ip: str | None = None,
    src_cc: str | None = Query(None, max_length=8, description="Country of src_ip, or home/private/unknown"),
    signature_id: int | None = None,
    search: str | None = None,
    hours: int | None = Query(
        None, ge=1, le=8760,
        description="Only the last N hours. Resolved on the server, which is where "
                    "the engine's timezone is known, and a browser elsewhere would "
                    "compute a different cutoff for the same window.",
    ),
    day: str | None = Query(
        None,
        description="One calendar day, 'today' or 'yesterday', resolved on the "
                    "server. The dashboard tiles count days; a link from one "
                    "into a rolling window would open a list that disagrees "
                    "with the number that was clicked.",
    ),
    acknowledged: bool | None = None,
    kind: str | None = Query(
        "alert",
        description="'alert' for the rule set's findings, 'diagnostic' for the "
                    "engine's own events about the traffic and about itself, "
                    "'all' for both. Defaults to 'alert': the two are different "
                    "kinds of thing and mixing them made a quarter of this list "
                    "notices nobody can act on.",
    ),
    blocked: bool | None = Query(
        None,
        description="Only alerts where the engine stopped the packet. Every "
                    "alert carries the verdict and nothing read it, so in "
                    "blocking mode the list showed which rules matched and "
                    "never which of them stopped anything.",
    ),
) -> dict[str, Any]:
    if kind not in ("alert", "diagnostic", "all"):
        raise HTTPException(status_code=422, detail=f"unknown kind: {kind}")
    if day is not None and day not in db.DAYS:
        raise HTTPException(status_code=422, detail=f"unknown day: {day}")
    # An explicit severity wins: picking one from the dropdown and getting an
    # empty list because the filter also applied would read as a broken filter.
    if severity is not None and severity not in db.ET_SEVERITIES and severity != "unrated":
        raise HTTPException(status_code=422, detail=f"unknown rating: {severity}")
    return db.query_alerts(
        limit=limit, offset=offset, severity=severity,
        src_ip=src_ip,
        dest_ip=dest_ip, src_cc=src_cc, signature_id=signature_id, search=search,
        since_hours=hours, day=day, acknowledged=acknowledged,
        kind=None if kind == "all" else kind,
        blocked=blocked,
    )


@router.get("/alerts/{alert_id}")
def get_alert_detail(alert_id: int) -> dict[str, Any]:
    alert = db.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="no such alert")
    return alert


@router.post("/alerts/ack-all")
def ack_all_alerts() -> dict[str, Any]:
    """Clear the review queue in one go.

    The queue tile on the dashboard is the only figure there that waits for a
    person rather than for the clock, which is worth nothing unless emptying it
    is one action. This device carried 12,362 unacknowledged rows out of 12,375
    when the tile was built.

    The cutoff is taken here and not from the client: a browser whose clock
    runs ahead would otherwise acknowledge alerts that have not been stored yet.
    """
    return {"acknowledged": db.acknowledge_all(int(time.time()))}


@router.post("/alerts/{alert_id}/ack")
def ack_alert(alert_id: int, value: bool = True) -> dict[str, Any]:
    if not db.set_acknowledged(alert_id, value):
        raise HTTPException(status_code=404, detail="no such alert")
    return {"id": alert_id, "acknowledged": value}


@router.get("/summary")
def get_summary(hours: int = Query(24, ge=1, le=720)) -> dict[str, Any]:
    return db.alert_summary(hours)


@router.get("/geo")
def get_geo(hours: int = Query(24, ge=1, le=720)) -> dict[str, Any]:
    """Alert sources grouped by country, for the map.

    Split into three: countries the map can place, registry buckets that have no
    location (anonymous proxies, satellite links), and traffic that never left
    the building. The last one is not a rounding error - on a sensor watching
    its own segment it is most of the volume, so it is reported as its own
    number rather than quietly dropped for lacking a country.
    """
    placed: list[dict[str, Any]] = []
    unplaced: list[dict[str, Any]] = []
    local = {"home": 0, "private": 0, "unknown": 0}

    for row in db.geo_summary(hours):
        code = row.pop("code")
        if code in local:
            local[code] = row["count"]
            continue
        entry = {**geoip.describe(code), **row}
        (placed if entry["lat"] is not None else unplaced).append(entry)

    return {
        "window_hours": hours,
        "countries": placed,
        "unplaced": unplaced,
        "local": local,
        "database": geoip.database_info(),
    }


@router.get("/events/recent")
def recent_events(
    limit: int = Query(100, ge=1, le=config.RECENT_EVENTS_BUFFER),
    event_type: str | None = None,
) -> dict[str, Any]:
    """Recent non-alert events (dns/tls/http/flow) from the in-memory buffer."""
    items = list(state.recent_events)
    if event_type:
        items = [e for e in items if e.get("event_type") == event_type]
    items.reverse()
    return {"items": items[:limit], "buffer_size": len(state.recent_events)}


@router.post("/rules/update")
def update_rules() -> dict[str, Any]:
    """suricata-update: download fresh rules (does not reload the engine).

    Always with the panel disable.conf - otherwise a fresh rule set would
    re-enable the categories the user switched off and the signatures they
    silenced from the alert view. Through the same path as every other rebuild,
    for its lock and for the pass that keeps flowbit helpers from loading as
    silent drops, which a download is the most likely thing to bring.
    """
    ok, out = protection.rebuild_from_state(offline=False)
    if not ok:
        raise HTTPException(status_code=500, detail=out or "the signature update failed")
    return {"ok": True, "output": out[-4000:]}


# --- intrusion prevention (category view) ---


class CategorySelection(BaseModel):
    categories: dict[str, bool] = Field(
        default_factory=dict, description="category id -> enabled"
    )
    informational: bool | None = Field(
        None,
        description="Whether to load the signatures the rule set rates "
                    "informational (ET's `metadata: signature_severity`). Sent "
                    "with the categories because both end in the same "
                    "disable.conf and the same rebuild. Null leaves it alone.",
    )


@router.get("/protection")
def get_protection() -> dict[str, Any]:
    """Protection state: signature counts, last update, mode, detection categories."""
    return protection.snapshot()


class ModeChoice(BaseModel):
    block: bool = Field(
        description="True puts the engine in the forwarding path, where a rule "
                    "with a drop action stops the packet. False takes it back "
                    "out, where every rule can only report.",
    )


@router.post("/protection/mode")
def set_protection_mode(choice: ModeChoice) -> dict[str, Any]:
    """Switch between reading a copy of the traffic and carrying it.

    Consequential enough to be its own endpoint rather than a field on the
    category form: it restarts the engine and, while it is restarting, every
    packet on the machine goes past a queue nothing is reading. That is safe -
    the rule says `bypass` - but it is not something to do as a side effect of
    saving something else.
    """
    try:
        ok, output = protection.set_mode(choice.block)
    except protection.ModeRefused as refused:
        # The layout cannot carry it: the request is refused, nothing failed.
        raise HTTPException(status_code=409, detail=str(refused)) from None
    if not ok:
        raise HTTPException(status_code=500, detail=output or "the mode could not be changed")
    return {"ok": True, "output": output, "mode": protection.mode_info()}


@router.post("/protection/categories")
def set_protection_categories(selection: CategorySelection) -> dict[str, Any]:
    """Store the category selection and rebuild the rule set (offline, from cache).

    The engine is not reloaded automatically - that is a separate, visible
    action, so it stays obvious from which moment the new rules apply.
    """
    unknown = set(selection.categories) - set(protection.CATEGORY_BY_ID)
    if unknown:
        raise HTTPException(status_code=400, detail=f"unknown categories: {sorted(unknown)}")
    locked = [k for k in selection.categories if protection.CATEGORY_BY_ID[k].locked]
    if locked:
        raise HTTPException(status_code=400, detail=f"these categories cannot be disabled: {locked}")

    ok, output = protection.apply_selection(
        selection.categories, informational=selection.informational,
    )
    return {"ok": ok, "output": output[-4000:], "state": protection.snapshot()}


class MuteRequest(BaseModel):
    signature_id: int = Field(gt=0, le=2**31 - 1, description="SID to silence")


@router.post("/protection/mute")
def mute_signature(request: MuteRequest) -> dict[str, Any]:
    """Silence one signature: drop it from the rule set and rebuild.

    Not a display filter - the rule stops being compiled at all, so it costs
    the engine nothing and cannot come back on the next update.
    """
    if protection.lookup_signature(request.signature_id) is None:
        raise HTTPException(
            status_code=404,
            detail=f"no signature with SID {request.signature_id} in the rule set",
        )
    ok, output = protection.mute(request.signature_id)
    return {"ok": ok, "output": output[-4000:], "state": protection.snapshot()}


@router.delete("/protection/mute/{signature_id}")
def unmute_signature(signature_id: int) -> dict[str, Any]:
    """Bring a silenced signature back."""
    try:
        ok, output = protection.unmute(signature_id)
    except KeyError:
        raise HTTPException(
            status_code=404, detail=f"SID {signature_id} is not silenced"
        ) from None
    return {"ok": ok, "output": output[-4000:], "state": protection.snapshot()}


@router.post("/protection/allow")
def allow_signature(request: MuteRequest) -> dict[str, Any]:
    """Keep alerting on one signature and never drop it, then rebuild."""
    if protection.lookup_signature(request.signature_id) is None:
        raise HTTPException(
            status_code=404,
            detail=f"no signature with SID {request.signature_id} in the rule set",
        )
    ok, output = protection.allow(request.signature_id)
    return {"ok": ok, "output": output[-4000:], "state": protection.snapshot()}


@router.delete("/protection/allow/{signature_id}")
def unallow_signature(signature_id: int) -> dict[str, Any]:
    """Let the blocking policy drop a signature again."""
    try:
        ok, output = protection.unallow(signature_id)
    except KeyError:
        raise HTTPException(
            status_code=404, detail=f"SID {signature_id} is not allowed"
        ) from None
    return {"ok": ok, "output": output[-4000:], "state": protection.snapshot()}


@router.post("/protection/rebuild")
def rebuild_protection_rules() -> dict[str, Any]:
    """Rebuild the rule set from what is stored, without changing anything.

    For a rule set that fell behind the blocking policy: after an upgrade, or
    after a rebuild that failed. Offline, from the cache, like every other
    rebuild the screen starts.
    """
    ok, output = protection.rebuild_from_state()
    return {"ok": ok, "output": output[-4000:], "state": protection.snapshot()}


# --- engine log destination ---


class LogDirRequest(BaseModel):
    path: str = Field(description="Directory the engine should write logs to")


@router.get("/logs")
def get_log_settings() -> dict[str, Any]:
    """Where engine logs go, what is in there and how much room is left."""
    return logdir.status()


@router.post("/logs/dir")
def set_log_dir(request: LogDirRequest) -> dict[str, Any]:
    """Move the engine log directory (service restart) and the panel reader."""
    try:
        result = logdir.set_dir(request.path)
    except ValueError as err:
        # Refused before anything was touched: nothing moved, nothing to undo.
        raise HTTPException(status_code=400, detail=str(err)) from err
    # A restart that did not go through is not a failed request. By this point
    # the override is written, the setting is stored and the reader has been
    # pointed at the new directory: the move happened. Answering 500 told the
    # operator it had failed and left them looking at a screen that had already
    # changed underneath them. The state travels in the body instead, and the
    # screen says which of the two happened.
    return {**result, "state": logdir.status()}


# --- alert notifications ---


class EmailSettings(BaseModel):
    """What the settings form sends.

    Everything optional: a form that only flips the switch should not have to
    resend the password, and it could not - the API never sends it out.
    """

    enabled: bool | None = None
    host: str | None = None
    port: int | None = None
    security: str | None = None
    username: str | None = None
    password: str | None = None
    clear_password: bool = False
    sender: str | None = None
    recipients: list[str] | None = None
    min_severity: int | None = None
    digest_seconds: int | None = None
    max_per_hour: int | None = None


@router.get("/notify")
def get_notifications() -> dict[str, Any]:
    """Mail settings (without the password) and what the sender has been doing."""
    return {"settings": notify.public_config(), "status": notify.notifier.status()}


@router.post("/notify")
def set_notifications(body: EmailSettings) -> dict[str, Any]:
    try:
        notify.save(body.model_dump(exclude_none=True))
    except notify.ConfigError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err
    return {"settings": notify.public_config(), "status": notify.notifier.status()}


@router.post("/notify/test")
def test_notifications() -> dict[str, Any]:
    """Send one message now, with the settings as stored.

    Saved first, then tested, deliberately: a test that passes on values the
    panel is not going to keep proves nothing.
    """
    try:
        notify.notifier.send_test()
    except notify.ConfigError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err
    except Exception as err:
        # Whatever the server said, verbatim. "Authentication failed" is an
        # answer somebody can act on; "could not send" is not.
        raise HTTPException(status_code=502, detail=str(err)) from err
    return {"ok": True, "status": notify.notifier.status()}


@router.get("/log")
def engine_log(lines: int = Query(200, ge=1, le=2000)) -> dict[str, Any]:
    """Tail of suricata.log - useful when the engine refuses to start."""
    path = settings.engine_log_path()
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"{path} is missing")
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except PermissionError:
        raise HTTPException(status_code=403, detail=f"no permission to read {path}")
    return {"path": str(path), "lines": content[-lines:]}
