"""Whole sequences an operator walks, not one function at a time.

Every piece of the blocking switch had tests, and the sequence still broke:
apply "This device only", go back through the wizard and press "Save and
continue" on the same choice, then switch to blocking. Saving marked the layout
unapplied, the switch then refused "apply the layout first", and no test had
ever put those three steps in a row. The tests here do, with only the system
calls replaced: the wizard, the store and the switch are the real code.
"""
from __future__ import annotations

from unittest.mock import patch

from app import settings
from app.modules.network import capture, topology
from app.modules.suricata import protection

from .helpers import BackendTestCase, hardware, link


def one_port():
    # The machine the screenshots were taken on: one wired port, which is also
    # the way into the panel.
    return hardware([link("eth0", ipv4=["10.0.2.15/24"], subnets=["10.0.2.0/24"])],
                    management="eth0")


class ThisDeviceOnlyFlowTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(topology.interfaces, "detect", return_value=one_port()))
        self.enterContext(patch.object(capture.interfaces, "detect", return_value=one_port()))
        self.enterContext(patch.object(capture, "_run", return_value=(True, "ok")))
        self.enterContext(patch.object(capture, "QUEUE_DROPIN", self.tmp / "no-dropin.conf"))
        self.helper = self.enterContext(patch.object(protection.subprocess, "run"))
        self.helper.return_value.returncode = 0
        self.helper.return_value.stdout = self.helper.return_value.stderr = ""
        self.enterContext(patch.object(protection, "_catch_up_rules", return_value=(True, "")))

    def _block(self):
        return protection.set_mode(True)

    def test_apply_then_save_again_then_block(self):
        topology.assign("self", {"capture": "eth0"})
        capture.apply(["10.0.2.0/24"])
        topology.assign("self", {"capture": "eth0"})     # back, "Save and continue"
        self.assertTrue(protection.mode_info()["blocking_possible"])
        ok, _ = self._block()
        self.assertTrue(ok)
        self.assertEqual(self.helper.call_args.args[0][-1], "ips")

    def test_the_sentence_under_a_working_switch_does_not_say_it_cannot(self):
        # The VM walkthrough blocked a request on this layout while the screen
        # said "which on this layout it cannot be": the text predates the
        # queue being allowed for this device.
        helper = self.tmp / "rapi-ips-mode"
        helper.write_text("#!/bin/sh\n")
        self.enterContext(patch.object(protection, "IPS_MODE_BIN", str(helper)))
        topology.assign("self", {"capture": "eth0"})
        capture.apply(["10.0.2.0/24"])
        mode = protection.mode_info()
        self.assertTrue(mode["blocking_possible"])
        self.assertNotIn("cannot", mode["reason"])
        self.assertIn("this Pi", mode["reason"])

    def test_without_the_helper_the_sentence_does_not_offer_blocking(self):
        # No rapi-ips-mode: the screen hides the buttons, and the sentence
        # under them promised that blocking stops traffic anyway.
        self.enterContext(patch.object(protection, "IPS_MODE_BIN",
                                       str(self.tmp / "not-installed")))
        topology.assign("self", {"capture": "eth0"})
        capture.apply(["10.0.2.0/24"])
        mode = protection.mode_info()
        self.assertFalse(mode["can_switch"])
        self.assertNotIn("Blocking puts", mode["reason"])
        self.assertIn("not installed", mode["reason"])

    def test_the_wizard_does_not_say_only_the_bridge_can_block(self):
        # The card beside "blocks this Pi only" said the bridge was "the only
        # layout that can stop a packet".
        bridge = next(p for p in topology.PROFILES if p.id == "bridge")
        self.assertNotIn("stop a packet", bridge.summary)
        self.assertIn("whole network", bridge.summary)

    def test_apply_then_block_straight_away(self):
        topology.assign("self", {"capture": "eth0"})
        capture.apply(["10.0.2.0/24"])
        ok, _ = self._block()
        self.assertTrue(ok)

    def test_saved_but_never_applied_is_refused_with_the_way_out(self):
        topology.assign("self", {"capture": "eth0"})
        with self.assertRaises(protection.ModeRefused) as refused:
            self._block()
        self.assertIn("Apply the layout first", str(refused.exception))

    def test_apply_then_choose_the_mirror_then_block_is_refused(self):
        topology.assign("self", {"capture": "eth0"})
        capture.apply(["10.0.2.0/24"])
        settings.set(topology.SETTINGS_KEY, {**settings.get(topology.SETTINGS_KEY),
                                             "profile": "mirror", "applied": False})
        with self.assertRaises(protection.ModeRefused):
            self._block()
