#!/usr/bin/env python3
"""Do everything the panel's screens can do, against a live panel, and check it.

    RAPI_PASS=... python3 scripts/gui-walkthrough.py --url https://127.0.0.1:18443

Every step is the request the page itself sends when the button is pressed, in
the order an operator meets them: create the account, sign in and out, change
the password, run the network wizard, wait for alerts, review them, change the
protection categories, silence and allow a signature, rebuild, switch blocking
on and see a request blocked, switch it off, refresh the rules, reload the
engine, read the logs, save the e-mail settings and try the test message.

Written for scripts/test-image-vm.sh --gui, which runs it against a freshly
flashed machine that generates harmless test traffic of its own. Unit tests run
each of these against mocks; nothing ran them in a row on a real system, and
that is where the bugs of the last weeks were (a re-saved layout refused
blocking, a mode switch whose answer landed off screen).

Prints one line per check, "ok ...", "FAIL ..." or "skip ...", and exits 1 if
anything failed. Only the standard library, so it runs with any python3.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

FAILED = 0


def say(state: str, text: str, detail: str = "") -> None:
    global FAILED
    if state == "FAIL":
        FAILED += 1
    print(f"{state} {text}", flush=True)
    if detail:
        print(f"    {detail[:400]}", flush=True)


class Panel:
    """The browser's side of the conversation: a cookie, JSON, the device's CA."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.cookie = ""
        self.context = ssl._create_unverified_context()   # the device's own CA

    def call(self, method: str, path: str, body=None, timeout: int = 60):
        """(status, parsed JSON or text). Never raises for an HTTP status."""
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if self.cookie:
            request.add_header("Cookie", self.cookie)
        try:
            with urllib.request.urlopen(request, timeout=timeout, context=self.context) as answer:
                status, raw, headers = answer.status, answer.read(), answer.headers
        except urllib.error.HTTPError as error:
            status, raw, headers = error.code, error.read(), error.headers
        except (OSError, urllib.error.URLError, http.client.HTTPException) as error:
            # No answer at all: status 0, so every check after it fails
            # instead of the script dying with a traceback halfway through.
            return 0, {"error": f"{type(error).__name__}: {error}"}
        for value in headers.get_all("Set-Cookie") or []:
            if value.startswith("rapi_session="):
                self.cookie = value.split(";", 1)[0]
        text = raw.decode("utf-8", "replace")
        try:
            return status, json.loads(text)
        except ValueError:
            return status, {"text": text[:300]}


def expect(text: str, ok: bool, detail: object = "") -> bool:
    say("ok" if ok else "FAIL", text, "" if ok else str(detail))
    return ok


def wait_for(panel: Panel, what: str, test, seconds: int, step: int = 10):
    """Poll until test() returns something truthy; None on timeout."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        result = test()
        if result:
            return result
        time.sleep(step)
    say("FAIL", f"{what} (waited {seconds} s)")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", required=True)
    parser.add_argument("--user", default="walkthrough")
    args = parser.parse_args()
    password = os.environ.get("RAPI_PASS", "")
    if len(password) < 12:
        print("RAPI_PASS must hold a password of at least 12 characters", file=sys.stderr)
        return 2
    panel = Panel(args.url)

    # --- the first screen: an account, then signing in and out ---------------
    status, state = panel.call("GET", "/api/auth/state")
    expect("a fresh panel asks for an account", status == 200 and not state.get("configured"), state)
    status, body = panel.call("POST", "/api/auth/setup", {"username": args.user, "password": "short"})
    expect("a password under 12 characters is refused", status == 422, body)
    status, body = panel.call("POST", "/api/auth/setup", {"username": args.user, "password": password})
    if not expect("the account is created", status == 201, body):
        return 1
    status, _ = panel.call("GET", "/api/health")
    expect("the new session opens the panel", status == 200)
    panel.call("POST", "/api/auth/logout")
    status, _ = panel.call("GET", "/api/health")
    expect("signing out closes it", status == 401)
    status, body = panel.call("POST", "/api/auth/login", {"username": args.user, "password": "wrong password here"})
    expect("a wrong password is refused", status == 401, body)
    status, body = panel.call("POST", "/api/auth/login", {"username": args.user, "password": password})
    expect("the right one signs in", status == 200, body)
    other = password + "-changed"
    status, body = panel.call("POST", "/api/auth/password",
                              {"current_password": "not the password", "new_password": other})
    expect("a password change needs the current password", status == 403, body)
    status, body = panel.call("POST", "/api/auth/password",
                              {"current_password": password, "new_password": other})
    expect("the password can be changed", status == 200, body)
    status, body = panel.call("POST", "/api/auth/password",
                              {"current_password": other, "new_password": password})
    expect("and changed back", status == 200, body)

    # --- System ---------------------------------------------------------------
    for path in ("/api/system/info", "/api/system/metrics", "/api/system/history",
                 "/api/system/network", "/api/modules"):
        status, body = panel.call("GET", path)
        expect(f"System reads {path}", status == 200, body)
    status, ssh = panel.call("GET", "/api/system/ssh")
    expect("SSH is on and takes the panel password as rapi",
           status == 200 and ssh.get("active") and ssh.get("source") == "panel"
           and ssh.get("login") == "rapi", ssh)

    # --- How this Pi is connected ----------------------------------------------
    status, links = panel.call("GET", "/api/network/interfaces")
    expect("the interface list is read", status == 200 and links, links)
    status, topo = panel.call("GET", "/api/network/topology")
    expect("the wizard reads the hardware", status == 200 and topo.get("hardware", {}).get("links"), topo)
    status, hint = panel.call("GET", "/api/network/home-net")
    nets = hint.get("suggested") if isinstance(hint, dict) else None
    expect("the wizard suggests home networks", status == 200 and nets, hint)
    capture = (topo.get("hardware") or {}).get("management") or "eth0"
    status, body = panel.call("POST", "/api/network/topology",
                              {"profile": "self", "roles": {"capture": capture}})
    expect("\"This device only\" is saved", status == 200 and body.get("saved"), body)
    status, body = panel.call("POST", "/api/network/apply", {"home_net": nets or []}, timeout=300)
    expect("the layout is applied and the engine restarted", status == 200 and body.get("ok"), body)
    status, body = panel.call("POST", "/api/network/topology",
                              {"profile": "self", "roles": {"capture": capture}})
    expect("the same layout is saved again", status == 200 and body.get("saved"), body)
    status, topo = panel.call("GET", "/api/network/topology")
    current = topo.get("current") or {}
    expect("saving the same layout again keeps it applied",
           status == 200 and current.get("applied") is True, current)

    # --- Dashboard and alerts -----------------------------------------------------
    def engine_up():
        status, body = panel.call("GET", "/api/suricata/status")
        return status == 200 and (body.get("service") or {}).get("running")
    wait_for(panel, "the engine is running", engine_up, 180, 5)

    def some_alerts():
        status, page = panel.call("GET", "/api/suricata/alerts?limit=50")
        return page if status == 200 and page.get("total") else None
    page = wait_for(panel, "alerts from the test traffic reach the panel", some_alerts, 420)
    if page:
        say("ok", f"alerts from the test traffic reach the panel ({page['total']})")
    for path in ("/api/suricata/summary", "/api/suricata/geo", "/api/suricata/events/recent",
                 "/api/suricata/log?kind=alert"):
        status, body = panel.call("GET", path)
        expect(f"the dashboard reads {path.split('?')[0]}", status == 200, body)
    sid = None
    if page:
        alert = page["items"][0]
        sid = next((a["signature_id"] for a in page["items"] if a.get("signature_id") == 2007961),
                   alert.get("signature_id"))
        status, body = panel.call("GET", f"/api/suricata/alerts/{alert['id']}")
        expect("an alert opens in detail", status == 200 and body.get("id") == alert["id"], body)
        status, body = panel.call("POST", f"/api/suricata/alerts/{alert['id']}/ack")
        expect("one alert is marked reviewed", status == 200, body)
        status, body = panel.call("POST", "/api/suricata/alerts/ack-all")
        expect("all alerts are marked reviewed", status == 200, body)

    # --- Protection --------------------------------------------------------------
    status, prot = panel.call("GET", "/api/suricata/protection")
    expect("the protection screen reads its state", status == 200 and prot.get("categories"), prot)
    toggle = next((c for c in prot.get("categories", [])
                   if not c.get("locked") and c.get("enabled") and c.get("id") != "malware"
                   and c.get("signatures")), None)
    if toggle:
        status, body = panel.call("POST", "/api/suricata/protection/categories",
                                  {"categories": {toggle["id"]: False}}, timeout=600)
        _, after = panel.call("GET", "/api/suricata/protection")
        off = next((c for c in after.get("categories", []) if c["id"] == toggle["id"]), {})
        expect(f"a category is switched off ({toggle['id']})",
               status == 200 and off.get("enabled") is False, body)
        status, body = panel.call("POST", "/api/suricata/protection/categories",
                                  {"categories": {toggle["id"]: True}}, timeout=600)
        _, after = panel.call("GET", "/api/suricata/protection")
        on = next((c for c in after.get("categories", []) if c["id"] == toggle["id"]), {})
        expect("and back on", status == 200 and on.get("enabled") is True, body)
    else:
        say("skip", "no category to switch off and on")

    if sid:
        status, body = panel.call("POST", "/api/suricata/protection/mute",
                                  {"signature_id": sid}, timeout=600)
        expect(f"a signature is silenced ({sid})", status == 200, body)
        status, body = panel.call("DELETE", f"/api/suricata/protection/mute/{sid}", timeout=600)
        expect("and alerts again", status == 200, body)
        status, body = panel.call("POST", "/api/suricata/protection/allow",
                                  {"signature_id": sid}, timeout=600)
        expect("a signature is allowed (alert, never block)", status == 200, body)
        status, body = panel.call("DELETE", f"/api/suricata/protection/allow/{sid}", timeout=600)
        expect("and blocks again", status == 200, body)
    status, body = panel.call("POST", "/api/suricata/protection/rebuild", timeout=600)
    expect("the rule set is rebuilt on request", status == 200, body)

    status, body = panel.call("POST", "/api/suricata/protection/mode", {"block": True}, timeout=600)
    expect("blocking is switched on",
           status == 200 and (body.get("mode") or {}).get("id") == "ips", body)

    def blocked():
        # The filter the alert screen's "blocked only" uses, so a burst of
        # other alerts cannot push the blocked one off the page.
        status, page = panel.call("GET", "/api/suricata/alerts?blocked=true&limit=5")
        if status != 200:
            return None
        return next((a for a in page.get("items", []) if a.get("action") == "blocked"), None)
    hit = wait_for(panel, "the test request is blocked while blocking is on", blocked, 300)
    if hit:
        say("ok", f"the test request is blocked while blocking is on ({hit.get('signature')})")
    status, body = panel.call("POST", "/api/suricata/protection/mode", {"block": False}, timeout=600)
    expect("blocking is switched off again",
           status == 200 and (body.get("mode") or {}).get("id") == "ids", body)

    # --- Engine -------------------------------------------------------------------
    status, body = panel.call("POST", "/api/suricata/service/reload", timeout=180)
    expect("the engine reloads its rules", status == 200, body)
    status, body = panel.call("POST", "/api/suricata/rules/update", timeout=900)
    expect("the rules are refreshed from the internet", status == 200, body)
    wait_for(panel, "the engine is running after all of that", engine_up, 240, 5)

    # --- Logs ---------------------------------------------------------------------
    status, logs = panel.call("GET", "/api/suricata/logs")
    expect("the log screen reads its settings", status == 200 and logs.get("log_dir"), logs)
    status, body = panel.call("POST", "/api/suricata/logs/dir", {"path": "/etc/rapi"})
    expect("a log directory under /etc is refused", status == 400, body)
    original = logs.get("log_dir") if isinstance(logs, dict) else None
    if original:
        moved = "/var/log/rapi-walkthrough"
        status, body = panel.call("POST", "/api/suricata/logs/dir", {"path": moved}, timeout=300)
        expect("the logs move to another directory",
               status == 200 and (body.get("state") or {}).get("log_dir") == moved, body)
        status, body = panel.call("POST", "/api/suricata/logs/dir", {"path": original}, timeout=300)
        expect("and back",
               status == 200 and (body.get("state") or {}).get("log_dir") == original, body)
        wait_for(panel, "the engine is running after the move", engine_up, 240, 5)

    # --- Notifications ------------------------------------------------------------
    secret = "never-sent-back-123"
    status, body = panel.call("POST", "/api/suricata/notify", {
        "enabled": False, "host": "smtp.example.invalid", "port": 587, "security": "starttls",
        "username": "walkthrough", "password": secret, "sender": "ids@example.invalid",
        "recipients": ["admin@example.invalid"]})
    expect("the e-mail settings are saved", status == 200, body)
    status, body = panel.call("GET", "/api/suricata/notify")
    expect("the saved SMTP password never comes back", status == 200 and secret not in json.dumps(body), body)
    status, body = panel.call("POST", "/api/suricata/notify/test", timeout=120)
    # Not 200: a panel that reports a message as sent to a server that does
    # not exist gives the operator a false confirmation.
    expect("a test message to a server that does not exist is reported as failed",
           status in (400, 502) and body.get("detail"), (status, body))
    status, _ = panel.call("GET", "/api/health")
    expect("the panel is still well after all of it", status == 200)

    panel.call("POST", "/api/auth/logout")
    status, _ = panel.call("GET", "/api/suricata/alerts")
    expect("signed out, the API is closed again", status == 401)
    print("done", flush=True)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
