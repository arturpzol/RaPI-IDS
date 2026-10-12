"""Sign-in endpoints. The only routes reachable without a session."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Cookie, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, field_validator

from . import auth, db
from .modules.system import ssh

log = logging.getLogger("rapi-panel.auth")

router = APIRouter(prefix="/auth", tags=["auth"])


class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    # 12 is the shortest length worth calling a password on a device that can be
    # reached by everyone on the network.
    password: str = Field(min_length=12, max_length=256)


def _no_control_characters(value: str) -> str:
    """A new password also becomes the SSH one, which travels as one line.

    The form cannot produce a line break, the API can. The helper reads the
    first line only, so SSH would take a prefix of the password while the
    System screen said it takes the panel's. Refused where a password is
    chosen; signing in with an existing one is not affected.
    """
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("The password cannot contain control characters such as a line break")
    return value


class NewCredentials(Credentials):
    """The first account. Same shape as a sign-in, stricter on the password."""

    _password = field_validator("password")(_no_control_characters)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)

    _new_password = field_validator("new_password")(_no_control_characters)


@router.get("/state")
def auth_state(rapi_session: str | None = Cookie(default=None)) -> dict:
    """What the frontend needs before it can decide which screen to show.

    Public on purpose: it reveals only whether the panel has been claimed yet,
    which the setup screen has to know before anyone can sign in.
    """
    user = auth.session_user(rapi_session)
    return {
        "configured": db.user_count() > 0,
        "user": {"username": user["username"]} if user else None,
    }


@router.post("/setup", status_code=status.HTTP_201_CREATED)
def setup(body: NewCredentials, request: Request, response: Response) -> dict:
    """Creates the first account. Refuses once one exists.

    The early check is only there to answer quickly and without hashing. The
    guarantee that exactly one account can ever be created this way lives in
    db.create_first_user, which does the check and the insert in one statement.
    """
    if db.user_count() > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="The panel already has an account")

    user_id = db.create_first_user(body.username, auth.hash_password(body.password))
    if user_id is None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="The panel already has an account")
    token, expires = auth.create_session(user_id, request.headers.get("user-agent"))
    auth.set_session_cookie(response, request, token, expires)
    log.info("Panel claimed by %r from %s", body.username, auth.client_ip(request))
    ssh.follow_panel_password(body.password)
    return {"user": {"username": body.username}}


@router.post("/login")
def login(body: Credentials, request: Request, response: Response) -> dict:
    ip = auth.client_ip(request)
    auth.check_rate_limit(ip)

    row = db.find_user(body.username)
    # Verify against a fixed dummy hash when the account is missing, so both
    # paths cost exactly one scrypt. Measured before this: a missing user took
    # 200 ms against 102 ms for an existing one, which is a membership oracle.
    stored = row["password_hash"] if row else auth.absent_user_hash()
    if not auth.verify_password(body.password, stored) or row is None:
        auth.record_failure(ip)
        log.warning("Failed sign-in for %r from %s", body.username, ip)
        # One message for both cases - naming which half was wrong tells an
        # attacker which usernames exist.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Wrong username or password")

    auth.clear_failures(ip)
    token, expires = auth.create_session(int(row["id"]), request.headers.get("user-agent"))
    auth.set_session_cookie(response, request, token, expires)
    log.info("Signed in: %r from %s", row["username"], ip)
    return {"user": {"username": row["username"]}}


@router.post("/logout")
def logout(response: Response, rapi_session: str | None = Cookie(default=None)) -> dict:
    if rapi_session:
        auth.destroy_session(rapi_session)
    auth.clear_session_cookie(response)
    return {"status": "signed out"}


@router.post("/password")
def change_password(
    body: PasswordChange,
    request: Request,
    response: Response,
    rapi_session: str | None = Cookie(default=None),
) -> dict:
    user = auth.session_user(rapi_session)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not signed in")

    row = db.find_user(user["username"])
    if row is None or not auth.verify_password(body.current_password, row["password_hash"]):
        auth.record_failure(auth.client_ip(request))
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Current password does not match")

    db.set_user_password(int(row["id"]), auth.hash_password(body.new_password))
    # Changing a password is how someone reacts to a device they no longer
    # control, so every other session has to die - including this one, which is
    # then replaced so the person doing it is not thrown out.
    db.delete_sessions_for_user(int(row["id"]))
    token, expires = auth.create_session(int(row["id"]), request.headers.get("user-agent"))
    auth.set_session_cookie(response, request, token, expires)
    log.info("Password changed for %r; all other sessions ended", row["username"])
    ssh.follow_panel_password(body.new_password)
    return {"status": "password changed"}
