"""Passwords, session cookies and the brute force limiter."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi import HTTPException

from app import auth, config, db

from .helpers import BackendTestCase

# scrypt at the shipped cost takes about a tenth of a second per hash. That is
# the point in production and a waste in a test, so the tests that only care
# about the surrounding logic run it at a cost nobody would ship.
CHEAP = {"SCRYPT_N": 2 ** 8}


class PasswordTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        for name, value in CHEAP.items():
            self.enterContext(patch.object(auth, name, value))

    def test_round_trip(self):
        stored = auth.hash_password("correct horse")
        self.assertTrue(auth.verify_password("correct horse", stored))
        self.assertFalse(auth.verify_password("Correct horse", stored))

    def test_hash_carries_its_own_cost(self):
        # So the cost can be raised later without locking anyone out.
        scheme, n, r, p, salt, digest = auth.hash_password("x").split("$")
        self.assertEqual(scheme, "scrypt")
        self.assertEqual((int(n), int(r), int(p)), (auth.SCRYPT_N, auth.SCRYPT_R, auth.SCRYPT_P))
        self.assertEqual(len(bytes.fromhex(salt)), 16)
        self.assertEqual(len(bytes.fromhex(digest)), auth.SCRYPT_LEN)

    def test_salt_is_per_password(self):
        self.assertNotEqual(auth.hash_password("same"), auth.hash_password("same"))

    def test_malformed_hash_is_a_refusal_not_a_crash(self):
        for stored in ("", "not-a-hash", "scrypt$1$2", "md5$1$8$1$aa$bb"):
            with self.subTest(stored=stored):
                self.assertFalse(auth.verify_password("x", stored))

    def test_absent_user_hash_is_stable_and_verifiable(self):
        # The sign-in path checks a real hash when the account does not exist,
        # so a missing user costs exactly one scrypt like every other attempt.
        first = auth.absent_user_hash()
        self.assertIs(first, auth.absent_user_hash())
        self.assertFalse(auth.verify_password("anything", first))


class SessionTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.user_id = db.create_first_user("admin", "hash")

    def test_only_the_hash_of_the_token_is_stored(self):
        token, _ = auth.create_session(self.user_id, "curl")
        rows = db.connect().execute("SELECT token_hash FROM sessions").fetchall()
        self.assertNotIn(token, [row["token_hash"] for row in rows])
        self.assertEqual(rows[0]["token_hash"], auth.token_fingerprint(token))

    def test_session_resolves_to_its_user(self):
        token, expires = auth.create_session(self.user_id, "curl")
        self.assertEqual(auth.session_user(token), {"id": self.user_id, "username": "admin"})
        self.assertGreater(expires, datetime.now(timezone.utc))

    def test_no_cookie_and_unknown_cookie_are_both_nobody(self):
        self.assertIsNone(auth.session_user(None))
        self.assertIsNone(auth.session_user(""))
        self.assertIsNone(auth.session_user("made-up"))

    def test_expired_session_is_rejected_and_deleted(self):
        past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        db.create_session(auth.token_fingerprint("t"), self.user_id, past, "curl")
        self.assertIsNone(auth.session_user("t"))
        self.assertIsNone(db.find_session(auth.token_fingerprint("t")))

    def test_logout_kills_the_session(self):
        token, _ = auth.create_session(self.user_id, "curl")
        auth.destroy_session(token)
        self.assertIsNone(auth.session_user(token))

    def test_user_agent_is_truncated_not_rejected(self):
        auth.create_session(self.user_id, "x" * 500)
        stored = db.connect().execute("SELECT user_agent FROM sessions").fetchone()
        self.assertEqual(len(stored["user_agent"]), 200)

    def test_require_user_guards_the_api(self):
        token, _ = auth.create_session(self.user_id, "curl")
        self.assertEqual(auth.require_user(token)["username"], "admin")
        with self.assertRaises(HTTPException) as raised:
            auth.require_user(None)
        self.assertEqual(raised.exception.status_code, 401)

    def _age_last_seen(self, token: str, **delta) -> None:
        """Move a session's last use into the past, without moving the clock."""
        when = (datetime.now(timezone.utc) - timedelta(**delta)).isoformat()
        db.touch_session(auth.token_fingerprint(token), when)

    def test_a_session_nobody_used_stops_working(self):
        # The absolute limit alone left a cookie on a machine somebody no longer
        # has good for a month, and the only remedy was changing the password,
        # which ends every other session too.
        token, _ = auth.create_session(self.user_id, "curl")
        self._age_last_seen(token, hours=config.SESSION_IDLE_HOURS + 1)
        self.assertIsNone(auth.session_user(token))

    def test_the_dead_session_is_deleted_not_merely_refused(self):
        # A row left behind is a cookie that starts working again if the clock
        # moves backwards, which on a Pi with no battery-backed clock it does.
        token, _ = auth.create_session(self.user_id, "curl")
        self._age_last_seen(token, hours=config.SESSION_IDLE_HOURS + 1)
        auth.session_user(token)
        self.assertIsNone(db.find_session(auth.token_fingerprint(token)))

    def test_using_it_keeps_it_alive(self):
        token, _ = auth.create_session(self.user_id, "curl")
        self._age_last_seen(token, hours=config.SESSION_IDLE_HOURS - 1)
        self.assertIsNotNone(auth.session_user(token))
        # And the visit was recorded, so tomorrow starts counting from now.
        self._age_last_seen(token, hours=config.SESSION_IDLE_HOURS - 1)
        self.assertIsNotNone(auth.session_user(token))

    def test_the_clock_is_not_written_on_every_request(self):
        # The dashboard polls every five seconds. One row update per request is
        # a write per poll, on an SD card, for a timestamp read once a day.
        token, _ = auth.create_session(self.user_id, "curl")
        before = db.find_session(auth.token_fingerprint(token))["last_seen"]
        auth.session_user(token)
        auth.session_user(token)
        self.assertEqual(db.find_session(auth.token_fingerprint(token))["last_seen"], before)

    def test_it_is_written_once_the_record_has_gone_stale(self):
        token, _ = auth.create_session(self.user_id, "curl")
        self._age_last_seen(token, seconds=config.SESSION_TOUCH_SECONDS + 60)
        stale = db.find_session(auth.token_fingerprint(token))["last_seen"]
        auth.session_user(token)
        self.assertNotEqual(db.find_session(auth.token_fingerprint(token))["last_seen"], stale)

    def test_the_sweep_collects_what_nobody_will_present_again(self):
        # Not what enforces the rule - a stale cookie is refused on arrival.
        # This is for rows nobody ever comes back with.
        token, _ = auth.create_session(self.user_id, "curl")
        self._age_last_seen(token, hours=config.SESSION_IDLE_HOURS + 1)
        self.assertEqual(db.purge_expired_sessions(config.SESSION_IDLE_HOURS), 1)

    def test_the_sweep_leaves_sessions_that_are_still_in_use(self):
        auth.create_session(self.user_id, "curl")
        self.assertEqual(db.purge_expired_sessions(config.SESSION_IDLE_HOURS), 0)


class RateLimitTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        auth._attempts.clear()
        self.addCleanup(auth._attempts.clear)

    def test_allows_the_configured_number_of_failures(self):
        for _ in range(config.LOGIN_MAX_ATTEMPTS):
            auth.check_rate_limit("10.0.0.5")
            auth.record_failure("10.0.0.5")
        with self.assertRaises(HTTPException) as raised:
            auth.check_rate_limit("10.0.0.5")
        self.assertEqual(raised.exception.status_code, 429)
        self.assertIn("Retry-After", raised.exception.headers)

    def test_the_limit_is_per_address(self):
        for _ in range(config.LOGIN_MAX_ATTEMPTS):
            auth.record_failure("10.0.0.5")
        auth.check_rate_limit("10.0.0.6")  # must not raise

    def test_a_success_clears_the_count(self):
        for _ in range(config.LOGIN_MAX_ATTEMPTS):
            auth.record_failure("10.0.0.5")
        auth.clear_failures("10.0.0.5")
        auth.check_rate_limit("10.0.0.5")

    def test_attempts_age_out_of_the_window(self):
        with patch.object(auth.time, "monotonic", return_value=0.0):
            for _ in range(config.LOGIN_MAX_ATTEMPTS):
                auth.record_failure("10.0.0.5")
        with patch.object(auth.time, "monotonic",
                          return_value=config.LOGIN_WINDOW_SECONDS + 1):
            auth.check_rate_limit("10.0.0.5")


class CookieTest(BackendTestCase):
    def test_cookie_is_httponly_and_follows_the_scheme(self):
        # Secure on a plain HTTP LAN would make the cookie undeliverable, so it
        # is set from the scheme of the request that asked for it.
        for scheme, secure in (("https", True), ("http", False)):
            with self.subTest(scheme=scheme):
                response, request = _FakeResponse(), _FakeRequest(scheme)
                auth.set_session_cookie(response, request, "token",
                                        datetime.now(timezone.utc))
                self.assertEqual(response.kwargs["httponly"], True)
                self.assertEqual(response.kwargs["samesite"], "strict")
                self.assertEqual(response.kwargs["secure"], secure)
                self.assertEqual(response.kwargs["max_age"],
                                 config.SESSION_DAYS * 24 * 3600)


class _FakeResponse:
    def __init__(self):
        self.kwargs = {}

    def set_cookie(self, name, value, **kwargs):
        self.kwargs = kwargs


class _FakeRequest:
    def __init__(self, scheme):
        self.url = type("URL", (), {"scheme": scheme})()
