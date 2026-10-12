"""The SSH password following the panel's (app/modules/system/ssh.py).

The helper that decides whether it may is tested in test_deploy; this is the
panel's half: that the password travels on stdin, that both places a panel
password is chosen hand it on, and that nothing about SSH can stop the panel
account from being created.
"""
from __future__ import annotations

import subprocess
import typing
from unittest.mock import patch

from fastapi import Response
from pydantic import ValidationError
from starlette.requests import Request

from app import auth, auth_router
from app.modules.system import ssh

from .helpers import BackendTestCase

PASSWORD = "correct horse battery"


def _request() -> Request:
    return Request({"type": "http", "method": "POST", "path": "/", "headers": [],
                    "scheme": "https", "server": ("rapi-ids.local", 443),
                    "client": ("192.0.2.10", 50000), "query_string": b""})


class FollowPasswordTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(auth, "SCRYPT_N", 2 ** 8))
        self.enterContext(patch.object(ssh, "_installed", return_value=True))

    def test_the_password_goes_on_stdin_and_never_in_argv(self):
        with patch.object(ssh.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            ssh.follow_panel_password(PASSWORD)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["sudo", "-n", ssh.HELPER, "set"])
        self.assertNotIn(PASSWORD, " ".join(args[0]))
        self.assertEqual(kwargs["input"], PASSWORD + "\n")

    def test_a_helper_that_fails_does_not_raise(self):
        for outcome in (subprocess.CompletedProcess([], 1, "", "boom"),
                        subprocess.TimeoutExpired("sudo", 60), OSError("no sudo")):
            with self.subTest(outcome=type(outcome).__name__):
                side = {"side_effect": outcome} if isinstance(outcome, Exception) \
                    else {"return_value": outcome}
                with patch.object(ssh.subprocess, "run", **side):
                    ssh.follow_panel_password(PASSWORD)

    def test_creating_the_panel_account_hands_the_password_on(self):
        with patch.object(ssh, "follow_panel_password") as follow:
            auth_router.setup(auth_router.Credentials(username="admin", password=PASSWORD),
                              _request(), Response())
        follow.assert_called_once_with(PASSWORD)

    def test_an_ssh_failure_does_not_stop_the_account_being_created(self):
        with patch.object(ssh.subprocess, "run", side_effect=OSError("no sudo")):
            result = auth_router.setup(
                auth_router.Credentials(username="admin", password=PASSWORD),
                _request(), Response())
        self.assertEqual(result, {"user": {"username": "admin"}})

    def test_changing_the_panel_password_hands_the_new_one_on(self):
        with patch.object(ssh, "follow_panel_password"):
            auth_router.setup(auth_router.Credentials(username="admin", password=PASSWORD),
                              _request(), Response())
        token, _ = auth.create_session(1, "test")
        with patch.object(ssh, "follow_panel_password") as follow:
            auth_router.change_password(
                auth_router.PasswordChange(current_password=PASSWORD,
                                           new_password="another long password"),
                _request(), Response(), rapi_session=token)
        follow.assert_called_once_with("another long password")


class StatusTest(BackendTestCase):
    def _status(self, stdout: str, returncode: int = 0, active: str = "active\ninactive\n"):
        def run(argv, **_):
            if argv[0] == "systemctl":
                return subprocess.CompletedProcess(argv, 0, active, "")
            return subprocess.CompletedProcess(argv, returncode, stdout, "")
        with patch.object(ssh, "_installed", return_value=True), \
                patch.object(ssh.subprocess, "run", side_effect=run):
            return ssh.status()

    def test_whose_password_and_which_login(self):
        self.assertEqual(self._status("source=card\nlogin=pi\n"),
                         {"active": True, "source": "card", "login": "pi"})

    def test_either_the_service_or_the_socket_counts_as_on(self):
        self.assertFalse(self._status("source=none\nlogin=rapi\n",
                                      active="inactive\ninactive\n")["active"])
        self.assertTrue(self._status("source=none\nlogin=rapi\n",
                                     active="inactive\nactive\n")["active"])

    def test_an_unknown_answer_is_unknown_not_guessed(self):
        self.assertIsNone(self._status("source=whatever\nlogin=rapi\n")["source"])
        self.assertIsNone(self._status("", returncode=1)["source"])


class ControlCharacterTest(BackendTestCase):
    """A new password becomes the SSH one too, and the helper reads one line.

    With a line break in it, SSH took the part before the break while the
    System screen said it took the panel password.
    """

    def test_the_first_account_refuses_a_line_break(self):
        for bad in ("abcdefghijkl\nsecond line", "abcdefghijkl\rxx", "tab\tinside the password"):
            with self.subTest(password=repr(bad)), self.assertRaises(ValidationError):
                auth_router.NewCredentials(username="admin", password=bad)

    def test_a_new_password_refuses_one_too(self):
        with self.assertRaises(ValidationError):
            auth_router.PasswordChange(current_password="whatever",
                                       new_password="abcdefghijkl\nsecond line")

    def test_the_setup_route_uses_the_strict_model(self):
        hints = typing.get_type_hints(auth_router.setup)
        self.assertIs(hints["body"], auth_router.NewCredentials)

    def test_signing_in_is_not_affected(self):
        # A password is checked against its hash there; refusing one would lock
        # out whoever managed to set it before this rule existed.
        self.assertEqual(auth_router.Credentials(username="a", password="abcdefghijkl\nx").password,
                         "abcdefghijkl\nx")

    def test_ordinary_passwords_still_pass(self):
        for good in (PASSWORD, "zazolc gesla jazn 12", "p@ss:word;with'quotes\""):
            with self.subTest(password=good):
                auth_router.NewCredentials(username="admin", password=good)
