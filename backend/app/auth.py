"""Authentication for the panel.

Deliberately small and dependency-free. Two decisions worth knowing about:

**Session cookie, not a bearer token.** The panel's live stream is a browser
WebSocket, and the browser WebSocket API cannot set an `Authorization` header -
a token would have to travel in the query string, which is exactly the place
that ends up in server logs and browser history. A cookie rides along with the
handshake on its own. It is also `HttpOnly`, so script injected into the panel
cannot read it, and killing a session is a row delete rather than a wait for a
token to expire.

**scrypt from the standard library.** Password hashing needs a slow KDF, and
`hashlib.scrypt` is one, in every Python we ship on. No new packages, so the
"install only from Debian repositories" rule stays intact.

Only the hash of the session token is stored. Someone who reads the database
still cannot present a valid cookie - the same reason passwords are not stored
in the clear.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Cookie, Depends, HTTPException, Request, Response, status

from . import config, db

log = logging.getLogger("rapi-panel.auth")

COOKIE_NAME = "rapi_session"

# scrypt cost. n=2**15 keeps a single hash near a tenth of a second on a Pi 5 -
# slow enough to make guessing expensive, fast enough that logging in feels
# immediate. Stored alongside every hash so raising it later does not lock
# existing users out.
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LEN = 32


# --- passwords ---

def hash_password(password: str) -> str:
    """Returns "scrypt$n$r$p$salt$hash", all binary parts hex-encoded."""
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_LEN,
        maxmem=128 * SCRYPT_R * SCRYPT_N * 2,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${derived.hex()}"


# A real hash to check against when the account does not exist, so that path
# costs exactly one scrypt like every other. Computed once at import: deriving it
# per request made a missing user take *two* scrypts and answer twice as slowly
# as an existing one, which leaked membership just as plainly as returning early
# would have.
_ABSENT_USER_HASH: str | None = None


def absent_user_hash() -> str:
    global _ABSENT_USER_HASH
    if _ABSENT_USER_HASH is None:
        _ABSENT_USER_HASH = hash_password(secrets.token_urlsafe(32))
    return _ABSENT_USER_HASH


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, hash_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        n, r, p = int(n), int(r), int(p)
        salt, expected = bytes.fromhex(salt_hex), bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        log.warning("Malformed password hash in the database")
        return False

    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=n, r=r, p=p, dklen=len(expected),
        maxmem=128 * r * n * 2,
    )
    # Constant time: a plain == leaks how much of the hash matched.
    return hmac.compare_digest(derived, expected)


# --- sessions ---

def token_fingerprint(token: str) -> str:
    """What is stored for a session: the cookie itself is never written down."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()



def create_session(user_id: int, user_agent: str | None) -> tuple[str, datetime]:
    """Returns (token, expiry). The token is shown once - only its hash is kept."""
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(days=config.SESSION_DAYS)
    db.create_session(token_fingerprint(token), user_id, expires.isoformat(),
                      (user_agent or "")[:200])
    return token, expires


def destroy_session(token: str) -> None:
    db.delete_session(token_fingerprint(token))


def session_user(token: str | None) -> dict[str, Any] | None:
    """Resolves a cookie to a user, or None. Dead sessions are deleted here.

    Two limits, and a session has to be inside both. The absolute one caps how
    long a sign-in can last; the idle one is what makes a cookie on a machine
    somebody no longer has stop working in a day rather than in a month. Both
    delete the row on the way out, so a cookie that has died once cannot be
    presented again even if the clock moves backwards.
    """
    if not token:
        return None
    row = db.find_session(token_fingerprint(token))
    if row is None:
        return None

    now = datetime.now(timezone.utc)
    if datetime.fromisoformat(row["expires_at"]) <= now:
        db.delete_session(row["token_hash"])
        return None

    last_seen = datetime.fromisoformat(row["last_seen"])
    if now - last_seen > timedelta(hours=config.SESSION_IDLE_HOURS):
        log.info("Session ended after %s of inactivity", now - last_seen)
        db.delete_session(row["token_hash"])
        return None

    # Not on every request: see SESSION_TOUCH_SECONDS. The panel polls itself
    # every few seconds and this row lives on an SD card.
    if now - last_seen > timedelta(seconds=config.SESSION_TOUCH_SECONDS):
        db.touch_session(row["token_hash"], now.isoformat())
    return {"id": row["user_id"], "username": row["username"]}


def set_session_cookie(response: Response, request: Request, token: str, expires: datetime) -> None:
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=int(config.SESSION_DAYS * 24 * 3600),
        httponly=True,          # unreadable from JavaScript
        samesite="strict",      # the panel is same-origin, so this costs nothing
        # Secure would make the cookie undeliverable over plain HTTP, which is
        # how the panel is reached on a LAN today. Set it only when the request
        # actually arrived over TLS, so turning HTTPS on later needs no change.
        secure=request.url.scheme == "https",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, samesite="strict")


# --- brute force ---

_attempts: dict[str, list[float]] = {}


def check_rate_limit(client_ip: str) -> None:
    """Raises 429 once an address has burned through its attempts.

    In memory on purpose: the window is minutes, a restart clearing it is
    acceptable, and writing a row per failed guess would hand an attacker a way
    to wear out the SD card.
    """
    now = time.monotonic()
    window = config.LOGIN_WINDOW_SECONDS
    tries = [t for t in _attempts.get(client_ip, []) if now - t < window]
    _attempts[client_ip] = tries
    if len(tries) >= config.LOGIN_MAX_ATTEMPTS:
        retry_after = int(window - (now - tries[0])) + 1
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {retry_after} s.",
            headers={"Retry-After": str(retry_after)},
        )


def record_failure(client_ip: str) -> None:
    _attempts.setdefault(client_ip, []).append(time.monotonic())


def clear_failures(client_ip: str) -> None:
    _attempts.pop(client_ip, None)


def client_ip(request: Request) -> str:
    # No reverse proxy in front of the panel, so the socket address is the truth;
    # trusting X-Forwarded-For here would let anyone reset their own rate limit.
    return request.client.host if request.client else "unknown"


def local_ip(request: Request) -> str | None:
    """Which of this machine's addresses the browser reached the panel on.

    The peer address says where the browser is, which is not the same question.
    With a Pi whose LAN port and Wi-Fi sit in one subnet - the normal case when
    the wireless link is the management path - the peer address matches both
    interfaces and the panel picked the wrong one, refusing to hand the LAN port
    to capture because it believed the browser was on it. The local end of the
    accepted socket is unambiguous: it is the address that was dialled.
    """
    server = request.scope.get("server")
    host = server[0] if server else None
    # The wildcard shows up when the socket was not bound to one address.
    return host if host and host not in ("0.0.0.0", "::") else None


# --- dependency ---

def require_user(rapi_session: str | None = Cookie(default=None)) -> dict[str, Any]:
    """Guards every API route except /api/auth/*."""
    user = session_user(rapi_session)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not signed in")
    return user


CurrentUser = Depends(require_user)
