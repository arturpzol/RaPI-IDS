"""RaPi IDS Panel - modular admin panel for Raspberry Pi.

The first module is a Suricata-based IDS; further ones are added in app/registry.py.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import auth, config, db, geoip, privileges, settings
from .auth_router import router as auth_router
from .hub import hub
from .redirect import start_redirect_servers, stop_redirect_servers
from .modules.network.router import router as network_router
from .modules.suricata import protection
from .modules.suricata.notify import notifier
from .modules.suricata.tailer import start_tailer, stop_tailer
from .modules.system.history import sampler as load_sampler
from .registry import enabled_modules

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("rapi-panel")

VERSION = "0.5.0"


async def _backfill_alerts() -> None:
    """Fill columns on alerts stored before those columns existed.

    Off the event loop and one batch at a time - a database holding weeks of
    history would otherwise stall the first request while it caught up. Both
    values were always present in the stored raw event, so nothing is invented
    here and no history is lost by having added the columns late.
    """
    try:
        rated = await asyncio.to_thread(db.backfill_et_severity)
        if rated:
            log.info("Read the rule rating of %d alerts from their stored events", rated)
    except Exception:
        log.exception("Severity backfill failed")

    try:
        verdicts = await asyncio.to_thread(db.backfill_actions)
        if verdicts:
            log.info("Read the engine's verdict on %d alerts from their stored events",
                     verdicts)
    except Exception:
        log.exception("Verdict backfill failed")

    if not geoip.available():
        log.warning("No geo database, so the alert map will stay empty")
        return
    try:
        filled = await asyncio.to_thread(db.backfill_countries, geoip.classify)
        if filled:
            log.info("Geolocated %d alerts from before the column existed", filled)
    except Exception:
        log.exception("Country backfill failed")


async def _retention_loop() -> None:
    """Once a day, drop alerts older than RAPI_ALERT_RETENTION_DAYS."""
    while True:
        try:
            removed = await asyncio.to_thread(
                db.purge_old_alerts, config.ALERT_RETENTION_DAYS
            )
            if removed:
                log.info("Retention: removed %d old alerts", removed)
        except Exception:
            log.exception("Retention task failed")
        try:
            gone = await asyncio.to_thread(
                db.purge_expired_sessions, config.SESSION_IDLE_HOURS
            )
            if gone:
                log.info("Retention: removed %d expired sessions", gone)
        except Exception:
            log.exception("Session cleanup failed")
        await asyncio.sleep(24 * 3600)


def _refresh_drop_conf() -> None:
    """Write drop.conf from the stored state, and disable.conf if it is missing.

    The daily refresh reads both files as they are and refuses to run without
    either. drop.conf is rewritten every start, or a panel upgraded to a new
    blocking policy would keep rebuilding with the old one until somebody
    changed a category. disable.conf is only created, never rewritten: an
    existing one was written from a state read successfully, while a fresh
    device had none at all, so its daily refresh never ran and a device
    flashed without signatures stayed without them.
    """
    try:
        if protection.ensure_disable_conf():
            log.info("disable.conf created from the stored state")
    except OSError as err:
        log.warning("disable.conf could not be written: %s", err)
    try:
        protection.refresh_drop_conf()
    except OSError as err:
        log.warning("drop.conf could not be written: %s", err)


# When the panel looks at whether the running rule set follows the blocking
# policy. Soon after starting, because a restart is how a fix to the policy
# arrives, and then every ten minutes, because the nightly refresh can bring a
# rule that needs it. A check on an unchanged file is a stat and a cached scan.
RULES_POLICY_FIRST_CHECK = 60
RULES_POLICY_INTERVAL = 600


async def _keep_rules_on_policy_once() -> None:
    try:
        done = await asyncio.to_thread(protection.keep_rules_on_policy)
    except Exception:
        log.exception("Keeping the rule set on the blocking policy failed")
        return
    if done:
        log.info("Blocking policy: %s", done)


async def _rules_policy_loop() -> None:
    await asyncio.sleep(RULES_POLICY_FIRST_CHECK)
    while True:
        await _keep_rules_on_policy_once()
        await asyncio.sleep(RULES_POLICY_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    settings.harden()
    privileges.check()
    _refresh_drop_conf()
    log.info("Database ready: %s", config.DB_PATH)
    backfill = asyncio.create_task(_backfill_alerts())
    start_tailer(asyncio.get_running_loop())
    load_sampler.start()
    # The device name goes in the subject line: one mailbox may be watching
    # several of these.
    notifier.hostname = socket.gethostname()
    notifier.start()
    retention = asyncio.create_task(_retention_loop())
    rules_policy = asyncio.create_task(_rules_policy_loop())

    redirects: list = []
    if config.tls_enabled():
        redirects = await start_redirect_servers(
            config.HOST, config.HTTP_REDIRECT_PORTS, config.PORT
        )
        log.info("Serving HTTPS on port %d (cert: %s)", config.PORT, config.TLS_CERT)
    else:
        log.warning(
            "Serving plain HTTP. Passwords and the session cookie travel in the "
            "clear. Run scripts/setup-tls.sh to fix that."
        )

    log.info(
        "Panel started, modules: %s",
        ", ".join(m.id for m in enabled_modules()),
    )
    try:
        yield
    finally:
        backfill.cancel()
        retention.cancel()
        rules_policy.cancel()
        load_sampler.stop()
        notifier.stop()
        await stop_redirect_servers(redirects)
        stop_tailer()
        log.info("Panel stopped")


app = FastAPI(
    title="RaPi IDS Panel",
    description="RaPi IDS: intrusion detection and device health",
    version=VERSION,
    lifespan=lifespan,
    docs_url="/docs" if config.ENABLE_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if config.ENABLE_DOCS else None,
)

# Angular injects component styles as <style> tags and the build inlines critical
# CSS, so style-src has to allow inline. Script does not: the one script that has
# to run before paint lives in /theme-init.js precisely so this can stay strict.
# connect-src 'self' also covers the same-origin WebSocket.
_CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
])

_SECURITY_HEADERS = {
    "Content-Security-Policy": _CSP,
    # frame-ancestors already covers this for current browsers; kept for old ones.
    "X-Frame-Options": "DENY",
    # Without this a file served with a guessed type can be run as script.
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    # Nothing here needs a camera, a microphone or a location.
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
}


@app.middleware("http")
async def security_headers(request, call_next):
    """Sent on every response, including API errors and static files.

    Deliberately no Strict-Transport-Security: it is remembered by the browser
    for months, so if the panel ever had to fall back to plain HTTP it would lock
    the operator out of their own device.
    """
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Sign-in routes are the only ones reachable without a session.
public_api = APIRouter(prefix="/api")
public_api.include_router(auth_router)

# Everything else is guarded at the router, so a new module cannot forget to
# ask for authentication - it is not something each route opts into.
api = APIRouter(prefix="/api", dependencies=[auth.CurrentUser])


@api.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "version": VERSION, "ws_clients": hub.client_count}


@api.get("/modules")
def list_modules() -> dict[str, Any]:
    """Single source of truth for the frontend navigation."""
    return {"modules": [m.to_dict() for m in enabled_modules()]}


for module in enabled_modules():
    api.include_router(module.router)

# Not in the module registry on purpose: the registry builds the navigation, and
# network topology is not a page anyone visits twice. It belongs to the setup
# wizard, which is reached after claiming the device and from the System page.
api.include_router(network_router)

app.include_router(public_api)
app.include_router(api)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    """Live stream: alerts, events and engine statistics.

    Messages have the shape {"topic": "...", "data": {...}}; the client
    filters by `topic` (suricata.alert / suricata.event / suricata.stats).
    """
    # The browser cannot put a header on a WebSocket, but it does send cookies
    # with the handshake - which is the whole reason the panel uses a cookie.
    # Closing before accept() turns the handshake itself down.
    token = ws.cookies.get(auth.COOKIE_NAME)
    if auth.session_user(token) is None:
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # The fingerprint travels with the socket so the hub can ask again later.
    # Checking once at the handshake is not enough: nothing after it ever looked
    # at the session, so a socket outlived the sign-out, the expiry and the
    # password change that were supposed to end it.
    await hub.connect(ws, auth.token_fingerprint(token or ""))
    try:
        while True:
            # We expect no commands from the client; we only await disconnect.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        log.debug("WS closed with an error", exc_info=True)
    finally:
        await hub.disconnect(ws)


# --- serving the built frontend (production) ---
# In dev we use `ng serve` on :4200, so this directory may not exist.
_FRONTEND_DIST = (
    Path(__file__).resolve().parent.parent.parent / "frontend" / "dist" / "rapi-panel" / "browser"
).resolve()

# Angular stamps a content hash into the file name, so a given name can only ever
# mean one build and is safe to cache forever. Anything else gets revalidated.
_HASHED_NAME = re.compile(r"-[A-Z0-9]{8,}\.[a-z0-9]+$")


def _cache_header(path: Path) -> dict[str, str]:
    if _HASHED_NAME.search(path.name):
        return {"Cache-Control": "public, max-age=31536000, immutable"}
    if path.suffix in {".woff2", ".woff", ".ico", ".png", ".svg"}:
        return {"Cache-Control": "public, max-age=86400"}
    return {"Cache-Control": "no-cache"}


if _FRONTEND_DIST.is_dir():
    # Mounted only when it exists. check_dir=False silences the check at startup
    # but not the one StaticFiles runs per request, so a build without an assets
    # directory - which is every build this project has produced - turned any
    # GET /assets/... into a 500 with a full traceback. Unauthenticated, since
    # the mount sits outside the guarded router, and 128 journal lines each:
    # a loop over it was a way to wear out the SD card from off the device.
    # Without the mount those paths fall through to the SPA route, which
    # answers a request for a missing file with 404.
    _ASSETS = _FRONTEND_DIST / "assets"
    if _ASSETS.is_dir():
        app.mount("/assets", StaticFiles(directory=_ASSETS), name="assets")

    @app.get("/{full_path:path}")
    def spa_fallback(full_path: str) -> Any:
        """SPA routing: unknown paths are handed over to Angular.

        Three things this has to get right, each of which was wrong before:

        1. **Stay inside the build directory.** The path comes from the client and
           was being joined onto the directory unchecked, so "../../../../data/
           panel.db" served the account database and "../../../../data/tls/
           server.key" served the TLS private key, both without a session. The
           resolved path is now required to sit under the build directory.
        2. **A missing file is 404, not index.html.** Handing HTML back for a
           missing .js meant a browser holding a stale index.html loaded the page
           with no styles and no error status: the layout looked broken with
           nothing to point at.
        3. **index.html must revalidate.** Served with no Cache-Control, browsers
           cache it heuristically. Since the cache is per origin, the panel could
           be correct under one hostname and stale under another, which is exactly
           how this surfaced.
        4. **An API path is never an Angular route.** Anything under /api that no
           endpoint claims was answered with index.html and a 200. A call to an
           endpoint that had been removed, or whose path had a typo, came back as
           a page of HTML reported as success, and the caller failed later and
           somewhere else.
        """
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

        candidate = (_FRONTEND_DIST / full_path).resolve()
        if not candidate.is_relative_to(_FRONTEND_DIST):
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

        if full_path and candidate.is_file():
            return FileResponse(candidate, headers=_cache_header(candidate))

        # A path with a suffix is asking for a file, not for an Angular route.
        if Path(full_path).suffix:
            raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

        index = _FRONTEND_DIST / "index.html"
        return FileResponse(index, headers={"Cache-Control": "no-cache"})
else:
    @app.get("/")
    def dev_root() -> dict[str, str]:
        return {
            "message": "Backend is running. The frontend is not built. Use `ng serve` "
                       "(:4200) or build it: cd frontend && npm run build",
            "docs": "/docs",
        }
