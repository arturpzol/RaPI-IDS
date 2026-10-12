"""Plain-HTTP listeners that send callers to HTTPS.

The panel moved from http://host:8000 to https://host, and a browser pointed at
the old address over plain HTTP would otherwise get a TLS parse error: it looks
like the device is broken, not like it moved. These listeners answer 301 with
the same path so an old bookmark still lands in the right place.

Deliberately not a second uvicorn instance: this needs to parse one request
line and one header, and a redirect that cannot itself become an attack surface
is worth more than reusing a framework.
"""
from __future__ import annotations

import asyncio
import logging

log = logging.getLogger("rapi-panel.redirect")

# A request line plus headers for a redirect is tiny. Anything larger is either
# a mistake or someone probing, and is dropped rather than buffered.
MAX_HEADER_BYTES = 8192
READ_TIMEOUT = 5.0


def _response(location: str) -> bytes:
    body = b"Moved to HTTPS\n"
    return (
        "HTTP/1.1 301 Moved Permanently\r\n"
        f"Location: {location}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii", "replace") + body


def _bad_request() -> bytes:
    return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


def _sanitise_host(raw: str, https_port: int) -> str | None:
    """Host header, stripped of its port and checked before it is echoed back.

    The Host header is attacker-controlled. Putting it into Location unchecked
    is how open redirects happen, so anything outside a hostname or address is
    refused instead of forwarded.
    """
    host = raw.strip()
    if host.startswith("["):                      # IPv6 literal
        end = host.find("]")
        if end == -1:
            return None
        name, rest = host[: end + 1], host[end + 1 :]
        if rest and not rest.startswith(":"):
            return None
    else:
        name = host.split(":", 1)[0]
        if not name or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-" for c in name):
            return None
    if len(name) > 253:
        return None
    return name if https_port == 443 else f"{name}:{https_port}"


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                  https_port: int) -> None:
    try:
        try:
            head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=READ_TIMEOUT
            )
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                asyncio.TimeoutError, ConnectionError):
            return
        if len(head) > MAX_HEADER_BYTES:
            writer.write(_bad_request())
            return

        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        target = parts[1] if len(parts) >= 2 and parts[1].startswith("/") else "/"

        host = None
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = _sanitise_host(line.split(":", 1)[1], https_port)
                break
        if host is None:
            writer.write(_bad_request())
            return

        writer.write(_response(f"https://{host}{target}"))
    except Exception:
        log.debug("Redirect listener failed", exc_info=True)
    finally:
        try:
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


async def start_redirect_servers(host: str, ports: list[int],
                                 https_port: int) -> list[asyncio.AbstractServer]:
    """Best effort: a port already taken must not stop the panel from starting."""
    servers: list[asyncio.AbstractServer] = []
    for port in ports:
        if port == https_port:
            continue
        try:
            server = await asyncio.start_server(
                lambda r, w: _handle(r, w, https_port), host, port,
                limit=MAX_HEADER_BYTES,
            )
        except OSError as exc:
            log.warning("No HTTP redirect on port %d: %s", port, exc)
            continue
        servers.append(server)
        log.info("HTTP on port %d redirects to HTTPS", port)
    return servers


async def stop_redirect_servers(servers: list[asyncio.AbstractServer]) -> None:
    for server in servers:
        server.close()
        try:
            await server.wait_closed()
        except Exception:
            pass
