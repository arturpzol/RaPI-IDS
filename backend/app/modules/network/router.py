"""Endpoints for the topology wizard."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from ... import auth
from ...modules.suricata import protection
from . import capture, interfaces, topology

log = logging.getLogger(__name__)

router = APIRouter(prefix="/network", tags=["network"])


class Assignment(BaseModel):
    profile: str = Field(min_length=1, max_length=32)
    # role -> interface name. Validated against the hardware, not by pattern:
    # interface names are whatever the kernel decided to call them.
    roles: dict[str, str] = Field(default_factory=dict)
    # Dry run: validate and report, write nothing.
    preview: bool = False


class ApplyRequest(BaseModel):
    # Home networks in CIDR form. Asked for rather than detected because a
    # mirror port carries VLANs this machine has no address on.
    home_net: list[str] = Field(default_factory=list, max_length=32)


@router.get("/interfaces")
def list_interfaces(request: Request) -> dict[str, Any]:
    """Network hardware as it is right now."""
    return interfaces.detect(auth.client_ip(request), auth.local_ip(request))


@router.get("/topology")
def get_topology(request: Request) -> dict[str, Any]:
    """Hardware, the available layouts and the choice recorded so far."""
    state = topology.state(auth.client_ip(request), auth.local_ip(request))
    # What the engine is actually listening on, which is not necessarily what
    # the wizard was told. The difference is the whole point of showing it.
    state["engine"] = {"interfaces": protection.mode_info()["interfaces"]}
    return state


@router.post("/topology")
def set_topology(body: Assignment, request: Request) -> dict[str, Any]:
    try:
        return topology.assign(
            body.profile, body.roles, auth.client_ip(request), persist=not body.preview,
            local_ip=auth.local_ip(request),
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/home-net")
def home_net_suggestion(request: Request) -> dict[str, Any]:
    """Subnets this machine is on, as a starting point for HOME_NET."""
    return {"suggested": capture.suggest_home_net(auth.client_ip(request),
                                                 auth.local_ip(request))}


@router.post("/apply")
def apply_capture(body: ApplyRequest, request: Request) -> dict[str, Any]:
    """Point the engine at the chosen interface and restart it."""
    try:
        return capture.apply(body.home_net, auth.client_ip(request), auth.local_ip(request))
    except capture.ApplyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
