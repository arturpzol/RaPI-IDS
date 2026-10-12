"""Fan-out of events to connected WebSocket clients."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from fastapi import WebSocket

from . import config, db

log = logging.getLogger(__name__)

# How often a live socket has its session checked again. The handshake is not
# enough on its own: a socket opened with a valid cookie used to keep streaming
# alerts for as long as the tab stayed open, through the session expiring,
# through a sign-out in another tab, and through a password change - which is
# the one somebody reaches for when they have lost control of a device and want
# every other session gone. Checking on every broadcast would mean a database
# read per alert per client, so it is throttled the same way session_user
# throttles its own writes.
RECHECK_SECONDS = 30


class Hub:
    """Plain broadcast: every connected client receives every message.

    Clients filter on the `topic` field. A slow client is dropped rather than
    buffered indefinitely, and so is one whose session has ended.
    """

    def __init__(self) -> None:
        # ws -> (session fingerprint, when it was last checked)
        self._clients: dict[WebSocket, tuple[str, float]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket, token_hash: str) -> None:
        await ws.accept()
        async with self._lock:
            self._clients[ws] = (token_hash, time.monotonic())
        log.info("WS client connected (total: %d)", len(self._clients))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.pop(ws, None)
        log.info("WS client disconnected (total: %d)", len(self._clients))

    @property
    def client_count(self) -> int:
        return len(self._clients)

    def _expired(self, now: float) -> list[WebSocket]:
        """Sockets whose session row is gone, checked at most every 30 s.

        Only the row's existence is asked about. session_user already deletes
        the row when either limit runs out, and a password change deletes every
        row for that user, so "is it still there" answers all three questions.
        """
        stale = []
        for ws, (token_hash, checked) in list(self._clients.items()):
            if now - checked < RECHECK_SECONDS:
                continue
            if db.find_session(token_hash) is None:
                stale.append(ws)
            else:
                self._clients[ws] = (token_hash, now)
        return stale

    async def _drop(self, sockets: list[WebSocket], reason: str) -> None:
        for ws in sockets:
            async with self._lock:
                self._clients.pop(ws, None)
            try:
                await ws.close(code=config.WS_SESSION_ENDED)
            except Exception:
                pass
        if sockets:
            log.info("Closed %d WS client(s): %s", len(sockets), reason)

    async def broadcast(self, topic: str, payload: Any) -> None:
        if not self._clients:
            return
        async with self._lock:
            stale = self._expired(time.monotonic())
        await self._drop(stale, "the session ended")
        if not self._clients:
            return

        message = json.dumps({"topic": topic, "data": payload}, default=str)
        async with self._lock:
            targets = list(self._clients)
        dead: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.pop(ws, None)


hub = Hub()
