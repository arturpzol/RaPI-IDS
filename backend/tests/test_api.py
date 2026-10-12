"""The HTTP surface: what is reachable without signing in, and what is served.

No test client here on purpose - starlette's needs a package the image does not
carry. The endpoints are ordinary functions, so they are called as functions,
and the wiring around them is read off the application object.
"""
from __future__ import annotations

import asyncio
import inspect
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from starlette.routing import Mount

from app import auth, config, db, main, registry, settings
from app.modules.network import router as network_router
from app.modules.suricata import router as suricata_router
from app.modules.suricata import tailer

from .helpers import PROJECT_ROOT, BackendTestCase, alert


def _requires_session(route: APIRoute) -> bool:
    """Whether a session check sits somewhere in this route's dependencies."""
    pending = [route.dependant]
    while pending:
        dependant = pending.pop()
        if dependant.call is auth.require_user:
            return True
        pending.extend(dependant.dependencies)
    return False


def list_alerts(**kwargs):
    """Call the alert endpoint as a function, the way this module does.

    Every parameter declared with Query() has to be passed: left out, the
    default that arrives is the Query object itself, not the None it wraps.
    One copy of that list, because two of them meant every new filter broke
    five tests in a class that has nothing to do with the filter.
    """
    params = dict(limit=50, offset=0, severity=None, src_cc=None,
                  hours=None, day=None, kind="alert", blocked=None)
    params.update(kwargs)
    return suricata_router.list_alerts(**params)


class AuthGuardTest(BackendTestCase):
    def test_every_api_route_except_sign_in_needs_a_session(self):
        # Guarded at the router, not route by route, so a new module cannot
        # forget to ask for authentication.
        unguarded = [
            route.path for route in main.app.routes
            if isinstance(route, APIRoute)
            and route.path.startswith("/api/")
            and not route.path.startswith("/api/auth/")
            and not _requires_session(route)
        ]
        self.assertEqual(unguarded, [])

    def test_the_sign_in_routes_are_reachable_without_one(self):
        public = {route.path for route in main.app.routes
                  if isinstance(route, APIRoute) and route.path.startswith("/api/auth/")}
        self.assertIn("/api/auth/login", public)
        self.assertIn("/api/auth/state", public)

    def test_the_wizard_endpoints_are_mounted_and_guarded(self):
        paths = {route.path for route in main.app.routes if isinstance(route, APIRoute)}
        for path in ("/api/network/interfaces", "/api/network/topology",
                     "/api/network/apply"):
            self.assertIn(path, paths)
        # The wizard's traffic check was removed on purpose: 12 seconds of its
        # own listener proved less than the engine's counters already show.
        self.assertNotIn("/api/network/probe", paths)

    def test_the_websocket_is_refused_without_a_cookie(self):
        # The browser cannot put a header on a WebSocket but it does send
        # cookies with the handshake, which is why the panel uses one.
        closed = {}

        class FakeWS:
            cookies: dict[str, str] = {}

            async def close(self, code):
                closed["code"] = code

            async def accept(self):
                raise AssertionError("must not accept an unauthenticated socket")

        asyncio.run(main.websocket_endpoint(FakeWS()))
        self.assertEqual(closed["code"], 1008)

    def test_a_socket_does_not_outlive_the_session_that_opened_it(self):
        """The handshake was the only check there ever was.

        A socket opened with a good cookie kept streaming alerts for as long as
        the tab stayed open: through the session expiring, through a sign-out in
        another tab, and through a password change - which is precisely what
        somebody reaches for when they have lost control of the device and want
        every other session gone. It ended none of them.
        """
        from app.hub import Hub
        import time

        class FakeWS:
            def __init__(self):
                self.sent, self.closed = [], None

            async def accept(self):
                pass

            async def send_text(self, message):
                self.sent.append(message)

            async def close(self, code=1000):
                self.closed = code

        async def scenario():
            hub = Hub()
            ws = FakeWS()
            await hub.connect(ws, "fingerprint")
            await hub.broadcast("t", {})
            self.assertEqual(len(ws.sent), 1, "a live session should receive events")

            # The session row is gone: expiry, sign-out and password change all
            # look like this, which is why the hub asks only that one question.
            with patch.object(main.db, "find_session", return_value=None), \
                 patch.object(time, "monotonic", return_value=time.monotonic() + 3600):
                await hub.broadcast("t", {})

            self.assertEqual(ws.closed, config.WS_SESSION_ENDED)
            self.assertEqual(len(ws.sent), 1, "it kept streaming after the session ended")
            self.assertEqual(hub.client_count, 0)

        asyncio.run(scenario())

    def test_a_live_session_is_not_rechecked_on_every_event(self):
        """An alert storm must not become a database read per alert per client.

        The check is throttled the same way session_user throttles its own
        writes, because this runs on an SD card.
        """
        from app.hub import Hub

        class FakeWS:
            async def accept(self): pass
            async def send_text(self, message): pass
            async def close(self, code=1000): pass

        async def scenario():
            hub = Hub()
            await hub.connect(FakeWS(), "fingerprint")
            with patch.object(main.db, "find_session") as lookup:
                for _ in range(50):
                    await hub.broadcast("t", {})
            self.assertEqual(lookup.call_count, 0)

        asyncio.run(scenario())

    def test_the_docs_are_off_unless_asked_for(self):
        # On an appliance the schema is a map for someone who should not have one.
        self.assertIsNone(main.app.docs_url)
        self.assertIsNone(main.app.openapi_url)


class EngineAlertCountTest(BackendTestCase):
    """The engine's own counter, and the only reading of it worth a screen.

    On its own it is a number the reader lines up against the alert badge, which
    counts threats only, in the selected window, with the filters applied. Three
    differences at once, and neither figure said what it measured. Beside the
    panel's own count for the same period it says one thing: whether anything
    was lost between the reader and the table.
    """

    def _status(self, uptime: int | None, raised: int) -> dict:
        live = tailer.SuricataState()
        live.last_stats = ({"uptime": uptime, "detect": {"alert": raised},
                            "capture": {"kernel_packets": 1, "kernel_drops": 0,
                                        "errors": 0},
                            "decoder": {"pkts": 1}, "tcp": {}, "flow": {}}
                           if uptime is not None else None)
        with patch.object(suricata_router, "state", live), \
             patch.object(suricata_router, "_run", return_value=(0, "active")), \
             patch.object(suricata_router.protection, "capture_link",
                          return_value={"state": "ok", "problem": None,
                                        "interfaces": []}):
            return suricata_router.get_status()["engine"]

    def test_it_reports_what_the_panel_stored_over_the_same_period(self):
        db.insert_alerts([alert(), alert(signature_id=2210054, et_severity=None,
                                        signature="SURICATA STREAM x")])
        engine = self._status(uptime=3600, raised=2)
        self.assertEqual(engine["alerts_stored"], 2)
        self.assertEqual(engine["alerts_missing"], 0)

    def test_a_row_either_side_of_the_boundary_is_not_a_loss(self):
        """The two never land on the same number.

        The engine samples every 30 seconds and the cutoff has one second of
        resolution. Measured on the device: 1131 raised against 1132 stored.
        """
        db.insert_alerts([alert() for _ in range(12)])
        self.assertEqual(self._status(uptime=3600, raised=20)["alerts_missing"], 0)

    def test_a_reader_falling_behind_is_reported(self):
        db.insert_alerts([alert() for _ in range(10)])
        engine = self._status(uptime=3600, raised=5000)
        self.assertEqual(engine["alerts_stored"], 10)
        self.assertEqual(engine["alerts_missing"], 4990)

    def test_nothing_is_claimed_before_the_engine_has_reported(self):
        # No uptime means no period to count over, and inventing one would put
        # a comparison on the screen that compares nothing.
        engine = self._status(uptime=None, raised=0)
        self.assertIsNone(engine["alerts_stored"])
        self.assertIsNone(engine["alerts_missing"])


class DayParameterTest(BackendTestCase):
    def test_the_endpoint_passes_a_named_day_through(self):
        _, today_start = db._day_starts(db._now())
        db.insert_alerts([alert(ts=today_start + 60, signature_id=1),
                          alert(ts=today_start - 60, signature_id=2)])
        self.assertEqual(list_alerts(day="today")["total"], 1)
        self.assertEqual(list_alerts(day="yesterday")["total"], 1)

    def test_the_tile_and_the_list_agree_through_the_endpoint(self):
        # The guarantee the links are for: a tile that says 417 opens a list
        # that says 417. Measured on the device before this existed, the two
        # sides read 2,423 and 8,343, because the endpoint's default kind was
        # not part of the comparison.
        _, today_start = db._day_starts(db._now())
        db.insert_alerts([
            alert(ts=today_start + 60, et_severity="Critical", signature_id=1),
            alert(ts=today_start + 61, signature_id=2200003,
                  signature="SURICATA STREAM excessive retransmissions"),
        ])
        self.assertEqual(list_alerts(day="today")["total"],
                         db.alert_summary(24)["today"])

    def test_a_day_it_does_not_know_is_a_422_not_a_silent_everything(self):
        # Ignoring it would answer with the whole table under a heading that
        # says one day, which is the failure mode this parameter exists to end.
        with self.assertRaises(HTTPException) as caught:
            list_alerts(day="last-tuesday")
        self.assertEqual(caught.exception.status_code, 422)


class BulkAcknowledgeTest(BackendTestCase):
    """Emptying the review queue, which is what makes the queue a headline.

    Without it the dashboard tile starts at the whole backlog and can never
    reach zero, which is the same uselessness as a count that falls on its own,
    only pointing the other way.
    """

    def test_it_clears_the_queue_and_says_how_many(self):
        db.insert_alerts([alert(signature_id=78), alert(signature_id=79)])
        self.assertEqual(suricata_router.ack_all_alerts(), {"acknowledged": 2})
        self.assertEqual(db.alert_summary(24)["pending"], 0)

    def test_the_cutoff_is_this_machine_now_and_not_a_moment_later(self):
        # An alert stamped ahead of the clock is what one arriving during the
        # request looks like from here, and it is exactly the alert nobody
        # would ever see again if the button marked it reviewed.
        db.insert_alerts([alert(ts=db._now() + 300, signature_id=80)])
        self.assertEqual(suricata_router.ack_all_alerts(), {"acknowledged": 0})
        self.assertEqual(db.alert_summary(24)["pending"], 1)

    def test_it_is_a_post_and_not_hidden_behind_the_id_route(self):
        # /alerts/{alert_id} answers GET on a path of the same shape. A POST
        # here has to reach this handler and not be read as an id.
        methods = {tuple(sorted(getattr(r, "methods", set()) or ()))
                   for r in main.app.routes
                   if getattr(r, "path", "") == "/api/suricata/alerts/ack-all"}
        self.assertEqual(methods, {("POST",)})


class ReachableSurfaceTest(BackendTestCase):
    """Every endpoint should have something on the screen that calls it.

    `GET /api/suricata/rules` outlived its screen by one refactor and nobody
    noticed, because an endpoint nothing calls behaves exactly like one that
    works. It was still being scanned, still returning the same count the
    protection screen already showed, and still part of what an attacker
    reaching the panel could reach.
    """

    # Reachable from the API and from nothing else. Not permission to leave
    # them that way - each is a note about a screen that is missing.
    KNOWN_GAPS = {
        # The panel can set a password at first run and check one at login, but
        # offers no way to change it afterwards. Today that means ssh and curl,
        # which for this project is a design bug rather than a shortcut.
        "/api/auth/password",
        # Superseded by /api/system/network, which is what the wizard reads.
        "/api/network/interfaces",
    }

    def _frontend(self) -> str:
        root = PROJECT_ROOT / "frontend" / "src"
        return "\n".join(p.read_text(encoding="utf-8") for p in sorted(root.rglob("*.ts")))

    def test_every_endpoint_has_a_caller(self):
        source = self._frontend()
        unreachable = set()
        for route in main.app.routes:
            path = getattr(route, "path", "")
            if not path.startswith("/api/"):
                continue
            # Up to the first path parameter: the caller builds the rest.
            stem = path[len("/api/"):].split("{")[0].rstrip("/")
            if stem not in source:
                unreachable.add(path)
        self.assertEqual(unreachable - self.KNOWN_GAPS, set())

    def test_the_known_gaps_are_still_gaps(self):
        # A list of exceptions nobody prunes is how the next dead endpoint hides.
        source = self._frontend()
        for path in self.KNOWN_GAPS:
            with self.subTest(path=path):
                stem = path[len("/api/"):].split("{")[0].rstrip("/")
                self.assertNotIn(stem, source,
                                 f"{path} has a caller now - drop it from KNOWN_GAPS")

    def test_the_scan_reads_the_frontend_it_claims_to(self):
        source = self._frontend()
        self.assertIn("suricata/alerts", source)
        self.assertGreater(len(source), 100_000)

    def test_the_alert_list_takes_no_free_form_timestamp(self):
        """`?since=` was documented as ISO 8601 and always returned nothing.

        `ts` became an INTEGER of Unix seconds, and SQLite orders every integer
        before every string, so `ts >= '2026-09-01T00:00:00'` is false for every
        row that exists. It answered 200 with an empty list and total 0, which
        reads as a quiet network.

        Removed rather than repaired: a period on this endpoint is `hours` or a
        named `day`, both worked out on the machine the engine writes its
        timestamps on. A caller-supplied instant would be worked out on a
        browser somewhere else.
        """
        route = next(r for r in main.app.routes
                     if getattr(r, "path", "") == "/api/suricata/alerts")
        names = set(inspect.signature(route.endpoint).parameters)
        self.assertNotIn("since", names)
        self.assertIn("hours", names)
        self.assertIn("day", names)

    def test_the_rule_file_listing_is_gone(self):
        # Two screens showed the same rule count from two endpoints, and the
        # one on the engine tab was the copy without the dates.
        paths = {getattr(r, "path", "") for r in main.app.routes}
        self.assertNotIn("/api/suricata/rules", paths)
        self.assertIn("/api/suricata/rules/update", paths)


class SecurityHeaderTest(BackendTestCase):
    def test_the_policy_allows_no_script_but_its_own(self):
        csp = main._SECURITY_HEADERS["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("object-src 'none'", csp)

    def test_no_hsts(self):
        # Remembered by the browser for months: a fallback to plain HTTP would
        # lock the operator out of their own device.
        self.assertNotIn("Strict-Transport-Security", main._SECURITY_HEADERS)

    def test_the_usual_three(self):
        for header in ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"):
            self.assertIn(header, main._SECURITY_HEADERS)


# The route only exists when there is a build to serve.
@unittest.skipUnless(hasattr(main, "spa_fallback"), "frontend not built")
class StaticFileTest(BackendTestCase):
    """Serving the built frontend. Every case here was wrong once."""

    def setUp(self):
        super().setUp()
        self.dist = self.tmp / "browser"
        (self.dist / "assets").mkdir(parents=True)
        (self.dist / "index.html").write_text("<html></html>")
        (self.dist / "main-ABCD1234.js").write_text("//")
        self.enterContext(patch.object(main, "_FRONTEND_DIST", self.dist))

    def _serve(self, path):
        return main.spa_fallback(path)

    def test_no_static_mount_points_at_a_directory_that_is_not_there(self):
        """StaticFiles checks its directory on every request, not just at boot.

        check_dir=False silenced the startup check and left the per-request one,
        so with no assets directory - which is every build this project has
        produced - any GET /assets/... answered 500 with a full traceback.
        Unauthenticated, because the mount sits outside the guarded router, and
        128 journal lines each: a loop over it wore out the SD card from off
        the device.
        """
        mounts = [r for r in main.app.routes if isinstance(r, Mount)]
        for mount in mounts:
            app = mount.app
            if isinstance(app, StaticFiles):
                for directory in app.all_directories:
                    with self.subTest(mount=mount.path):
                        self.assertTrue(Path(directory).is_dir(), directory)

    def test_a_path_climbing_out_of_the_build_directory_is_refused(self):
        # This served data/panel.db and the TLS private key, without a session.
        for path in ("../../../../data/panel.db", "../../data/tls/server.key",
                     "assets/../../../etc/passwd"):
            with self.subTest(path=path), self.assertRaises(HTTPException) as raised:
                self._serve(path)
            self.assertEqual(raised.exception.status_code, 404)

    def test_a_missing_file_is_404_not_the_index(self):
        # Handing HTML back for a missing .js loads the page with no styles and
        # no error status: broken layout with nothing to point at.
        with self.assertRaises(HTTPException):
            self._serve("main-DEADBEEF.js")

    def test_an_api_path_nothing_claims_is_404_not_the_index(self):
        """Removing /api/suricata/rules did not stop it answering 200.

        Every path with no suffix that no endpoint claims fell through to
        index.html, so a call to a removed endpoint, or one with a typo in it,
        came back as a page of HTML reported as success. The caller then failed
        later and somewhere else, on data that was never JSON.
        """
        for path in ("api", "api/suricata/rules", "api/nothing/here",
                     "api/suricata/alerts/../rules"):
            with self.subTest(path=path), self.assertRaises(HTTPException) as raised:
                self._serve(path)
            self.assertEqual(raised.exception.status_code, 404)

    def test_a_route_that_only_starts_like_the_api_is_still_a_route(self):
        # /apiary is an Angular route as far as this function is concerned.
        response = self._serve("apiary/whatever")
        self.assertEqual(Path(response.path).name, "index.html")

    def test_an_angular_route_gets_the_index(self):
        response = self._serve("ids/alerts")
        self.assertEqual(Path(response.path).name, "index.html")
        self.assertEqual(response.headers["cache-control"], "no-cache")

    def test_a_real_file_is_served_with_its_own_headers(self):
        response = self._serve("main-ABCD1234.js")
        self.assertEqual(Path(response.path).name, "main-ABCD1234.js")
        self.assertIn("immutable", response.headers["cache-control"])

    def test_cache_headers(self):
        # A content hash can only ever mean one build; everything else has to
        # be revalidated, index.html above all.
        self.assertIn("immutable", main._cache_header(Path("main-ABCD1234.js"))["Cache-Control"])
        self.assertEqual(main._cache_header(Path("index.html"))["Cache-Control"], "no-cache")
        self.assertIn("86400", main._cache_header(Path("font.woff2"))["Cache-Control"])


class ModuleRegistryTest(BackendTestCase):
    def test_the_navigation_comes_from_the_registry(self):
        listed = main.list_modules()["modules"]
        self.assertEqual({m["id"] for m in listed}, {"ids", "system"})
        for module in listed:
            self.assertTrue(module["route"].startswith("/"))
            self.assertTrue(module["api_prefix"].startswith("/api/"))

    def test_the_detection_module_is_named_for_both_halves_of_what_it_does(self):
        """It was called "IDS" while shipping a working blocking switch.

        scripts/test-image-vm.sh --ips proves a rule loaded as `drop` stops a
        packet through NFQUEUE, with a control request that still gets through.
        Behind a name that says detection only, the one screen that can block
        had nothing to bring anybody to it.
        """
        ids = next(m for m in main.list_modules()["modules"] if m["id"] == "ids")
        self.assertIn("IPS", ids["name"])
        self.assertIn("IDS", ids["name"])
        self.assertIn("blocking", ids["description"].lower())

    def test_a_disabled_module_disappears_from_both_lists(self):
        with patch.object(registry, "MODULES",
                          [m for m in registry.MODULES if m.id != "system"]):
            self.assertEqual({m.id for m in registry.enabled_modules()}, {"ids"})


class ErrorMappingTest(BackendTestCase):
    """A refusal from the layer below has to reach the browser as a status."""

    def test_a_bad_log_directory_is_a_400(self):
        request = suricata_router.LogDirRequest(path="/home/rapi/logs")
        with patch.object(suricata_router.logdir, "set_dir",
                          side_effect=ValueError("ProtectHome")):
            with self.assertRaises(HTTPException) as raised:
                suricata_router.set_log_dir(request)
        self.assertEqual(raised.exception.status_code, 400)

    def test_a_restart_that_failed_is_not_a_failed_request(self):
        # By the time set_dir returns, the override is written, the setting is
        # stored and the reader has been pointed at the new directory: the move
        # happened. Answering 500 told the operator it had not, while the screen
        # behind the message had already changed underneath them.
        request = suricata_router.LogDirRequest(path="/mnt/ssd/suricata")
        with patch.object(suricata_router.logdir, "set_dir",
                          return_value={"ok": False, "restarted": False,
                                        "output": "Job failed",
                                        "log_dir": "/mnt/ssd/suricata",
                                        "previous_dir": "/var/log/suricata"}), \
             patch.object(suricata_router.logdir, "status", return_value={}):
            result = suricata_router.set_log_dir(request)
        self.assertFalse(result["restarted"])
        self.assertEqual(result["log_dir"], "/mnt/ssd/suricata")
        self.assertIn("Job failed", result["output"])

    def test_allowing_a_signature_that_is_not_in_the_rule_set_is_a_404(self):
        with patch.object(suricata_router.protection, "lookup_signature", return_value=None), \
             patch.object(suricata_router.protection, "allow") as allow:
            with self.assertRaises(HTTPException) as raised:
                suricata_router.allow_signature(suricata_router.MuteRequest(signature_id=5))
        self.assertEqual(raised.exception.status_code, 404)
        allow.assert_not_called()

    def test_blocking_again_something_that_was_not_allowed_is_a_404(self):
        with patch.object(suricata_router.protection, "unallow", side_effect=KeyError(1)):
            with self.assertRaises(HTTPException) as raised:
                suricata_router.unallow_signature(1)
        self.assertEqual(raised.exception.status_code, 404)

    def test_downloading_signatures_rebuilds_through_the_shared_path(self):
        """The lock and the flowbit pass, which a direct rebuild skipped."""
        with patch.object(suricata_router.protection, "rebuild_from_state",
                          return_value=(True, "done")) as shared, \
             patch.object(suricata_router.protection, "rebuild") as direct:
            result = suricata_router.update_rules()
        shared.assert_called_once_with(offline=False)
        direct.assert_not_called()
        self.assertTrue(result["ok"])

    def test_a_download_that_failed_is_a_500(self):
        with patch.object(suricata_router.protection, "rebuild_from_state",
                          return_value=(False, "network unreachable")):
            with self.assertRaises(HTTPException) as raised:
                suricata_router.update_rules()
        self.assertEqual(raised.exception.status_code, 500)
        self.assertIn("network unreachable", raised.exception.detail)

    def test_the_rebuild_answers_with_the_state_it_left(self):
        with patch.object(suricata_router.protection, "rebuild_from_state",
                          return_value=(True, "x" * 5000)), \
             patch.object(suricata_router.protection, "snapshot", return_value={"s": 1}):
            result = suricata_router.rebuild_protection_rules()
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["output"]), 4000)
        self.assertEqual(result["state"], {"s": 1})

    def test_unmuting_something_that_was_not_muted_is_a_404(self):
        with patch.object(suricata_router.protection, "unmute", side_effect=KeyError(1)):
            with self.assertRaises(HTTPException) as raised:
                suricata_router.unmute_signature(1)
        self.assertEqual(raised.exception.status_code, 404)

    def test_an_impossible_layout_is_a_400(self):
        body = network_router.Assignment(profile="mirror", roles={"capture": "eth9"})
        with patch.object(network_router.topology, "assign",
                          side_effect=ValueError("no such interface")):
            with self.assertRaises(HTTPException) as raised:
                network_router.set_topology(body, _FakeRequest())
        self.assertEqual(raised.exception.status_code, 400)

    def test_a_refused_apply_is_a_400_with_the_reason(self):
        body = network_router.ApplyRequest(home_net=["192.168.1.0/24"])
        with patch.object(network_router.capture, "apply",
                          side_effect=network_router.capture.ApplyError("would cut you off")):
            with self.assertRaises(HTTPException) as raised:
                network_router.apply_capture(body, _FakeRequest())
        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("would cut you off", raised.exception.detail)


class NotificationEndpointTest(BackendTestCase):
    """The mail settings travel over the API; the password must not."""

    def test_the_password_is_never_sent_out(self):
        from app import settings
        from app.modules.suricata import notify

        settings.set(notify.SETTINGS_KEY, {
            **notify.config(), "host": "smtp.example.net", "password": "secret",
            "sender": "ids@example.net", "recipients": ["a@example.net"], "enabled": True,
        })
        answer = suricata_router.get_notifications()
        self.assertNotIn("password", answer["settings"])
        self.assertTrue(answer["settings"]["password_set"])

    def test_a_refused_setting_is_a_400(self):
        body = suricata_router.EmailSettings(enabled=True, host="", recipients=[])
        with self.assertRaises(HTTPException) as raised:
            suricata_router.set_notifications(body)
        self.assertEqual(raised.exception.status_code, 400)

    def test_a_mail_server_that_refuses_is_a_502_with_what_it_said(self):
        # "Authentication failed" is something a person can act on; "could not
        # send" is not.
        with patch.object(suricata_router.notify.notifier, "send_test",
                          side_effect=OSError("authentication failed")):
            with self.assertRaises(HTTPException) as raised:
                suricata_router.test_notifications()
        self.assertEqual(raised.exception.status_code, 502)
        self.assertIn("authentication failed", raised.exception.detail)

    def test_a_form_that_only_flips_the_switch_sends_only_that(self):
        body = suricata_router.EmailSettings(enabled=False)
        self.assertEqual(body.model_dump(exclude_none=True),
                         {"enabled": False, "clear_password": False})


class EngineControlTest(BackendTestCase):
    def test_reload_is_the_only_action_on_offer(self):
        self.assertEqual(suricata_router.ALLOWED_ACTIONS, {"reload"})

    def test_anything_else_is_refused_by_the_endpoint_too(self):
        # Not only by the type hint: an endpoint that still accepted these would
        # leave the narrowing on the screen and nowhere else.
        for action in ("start", "stop", "restart"):
            with self.subTest(action=action), self.assertRaises(HTTPException) as raised:
                suricata_router.control_service(action)
            self.assertEqual(raised.exception.status_code, 400)


class AlertListingTest(BackendTestCase):
    """The severity cap, at the level where the two filters meet."""

    def setUp(self):
        super().setUp()
        db.insert_alerts([
            alert(severity=1, et_severity=et, signature_id=i, signature=f"S{i}",
                  src_ip="203.0.113.7", src_cc="home")
            for i, et in enumerate(("Major", "Informational", "Informational",
                                    "Informational"))
        ])

    _list = staticmethod(list_alerts)

    def test_every_stored_alert_is_listed(self):
        # Nothing is filtered here any more. A rule the operator does not want
        # is not loaded, so it never reaches the database at all - see
        # protection.set_informational. That is the whole change: one place
        # decides, and it is the one that can actually stop the alert.
        page = self._list()
        self.assertEqual(page["total"], 4)

    def test_a_rating_can_still_be_asked_for(self):
        self.assertEqual(self._list(severity="Informational")["total"], 3)
        self.assertEqual(self._list(severity="Major")["total"], 1)

    def test_a_rating_that_is_not_one_is_refused(self):
        with self.assertRaises(HTTPException) as raised:
            self._list(severity="Medium")
        self.assertEqual(raised.exception.status_code, 422)

    def test_the_engine_number_does_not_decide_the_rating(self):
        """Every fixture here carries engine priority 1, the most serious there
        is, and three of them are rated Informational by the rule set. The two
        scales are independent, which is why the label is stored."""
        page = self._list()
        self.assertTrue(all(a["severity"] == 1 for a in page["items"]))
        self.assertEqual(sorted(a["et_severity"] for a in page["items"]),
                         ["Informational"] * 3 + ["Major"])

    def test_the_summary_and_the_list_count_the_same_rows(self):
        self.assertEqual(suricata_router.get_summary(hours=24)["total_window"],
                         self._list()["total"])

    def test_unacknowledged_is_windowed(self):
        # It counted the whole table on a tile wired to [alarm], so a month of
        # alerts left a red badge that could never go back to green.
        old = int((datetime.now(timezone.utc) - timedelta(days=40)).timestamp())
        db.insert_alerts([alert(ts=old, et_severity="Critical", signature_id=99)])
        self.assertEqual(suricata_router.get_summary(hours=24)["unacknowledged"], 4)

    def test_the_frontend_and_the_backend_agree_on_the_scale(self):
        # Two lists, one meaning. If they drift, the panel colours a rating the
        # backend has never heard of, or filters on one the GUI cannot offer.
        models = (PROJECT_ROOT / "frontend" / "src" / "app" / "core" / "models.ts"
                  ).read_text(encoding="utf-8")
        listed = ", ".join(f"'{label}'" for label in db.ET_SEVERITIES)
        self.assertIn(f"export const ET_SEVERITIES = [{listed}]", models)


class DiagnosticEndpointTest(BackendTestCase):
    """The endpoint's own contract: what it defaults to and what it refuses."""

    def setUp(self):
        super().setUp()
        db.insert_alerts([
            alert(signature_id=2000001, signature="ET MALWARE One"),
            alert(signature_id=2210054, et_severity=None,
                  signature="SURICATA STREAM excessive retransmissions"),
            alert(signature_id=2210059, et_severity=None,
                  signature="SURICATA STREAM pkt seen on wrong thread"),
        ])

    _list = staticmethod(list_alerts)

    def test_the_list_defaults_to_findings(self):
        # The default is the point of the change: a browser that asks for
        # /alerts and says nothing else must not get the engine's own notices.
        # Read off the declaration rather than by calling, because calling the
        # endpoint as a function hands back the Query object rather than the
        # value it wraps - which is also why every test here passes kind by
        # hand, and why without this one the default is not covered at all.
        declared = inspect.signature(suricata_router.list_alerts).parameters["kind"]
        self.assertEqual(declared.default.default, "alert")

    def test_asking_for_findings_gets_findings(self):
        self.assertEqual(self._list()["total"], 1)
        self.assertEqual(self._list()["items"][0]["signature"], "ET MALWARE One")

    def test_the_list_can_still_be_asked_for_everything(self):
        self.assertEqual(self._list(kind="all")["total"], 3)
        self.assertEqual(self._list(kind="diagnostic")["total"], 2)

    def test_the_blocked_filter_is_off_unless_asked_for(self):
        """The default matters more than the filter.

        Most devices read a copy and stop nothing, so a filter left on by
        accident empties the list on almost every install. Read off the
        signature rather than by calling: a parameter left out of the call
        arrives as the Query object, which is truthy, and that is how this
        exact filter first broke eight tests.
        """
        default = inspect.signature(
            suricata_router.list_alerts).parameters["blocked"].default
        self.assertIsNone(default.default)

    def test_only_what_was_stopped_can_be_asked_for(self):
        db.insert_alerts([
            alert(signature="ET MALWARE Stopped", signature_id=2000009,
                  action="blocked"),
        ])
        self.assertEqual(self._list(blocked=True)["total"], 1)
        self.assertGreater(self._list()["total"], 1)

    def test_a_kind_that_is_not_one_is_refused(self):
        # Not silently ignored: a typo that returned the default would look like
        # a working filter that filters nothing.
        with self.assertRaises(HTTPException) as raised:
            self._list(kind="diagnostics")
        self.assertEqual(raised.exception.status_code, 422)

    def test_the_engine_notes_come_out_of_the_alert_list(self):
        # They had an endpoint and a screen of their own, which grouped them by
        # rule and wrote a sentence about each. Now they are the same list with
        # kind=diagnostic, which is where the search and the window already are.
        out = self._list(kind="diagnostic")
        self.assertEqual({r["signature_id"] for r in out["items"]}, {2210059, 2210054})

    def test_the_window_is_honoured_for_engine_notes_too(self):
        old = int((datetime.now(timezone.utc) - timedelta(days=40)).timestamp())
        db.insert_alerts([alert(ts=old, signature_id=2231001, et_severity=None,
                                signature="SURICATA QUIC error on data")])
        self.assertEqual(self._list(kind="diagnostic", hours=24)["total"], 2)
        self.assertEqual(self._list(kind="diagnostic", hours=8000)["total"], 3)


class _FakeRequest:


    client = type("Client", (), {"host": "192.168.1.55"})()
    # The address the browser dialled, which is what tells the wizard which
    # interface is carrying the session.
    scope = {"server": ("192.168.1.10", 443)}
