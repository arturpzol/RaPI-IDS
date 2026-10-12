"""Putting a layout into effect, and proving afterwards that it worked."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from app import geoip, settings
from app.modules.network import capture, topology

from .helpers import PROJECT_ROOT, BackendTestCase, hardware, link


def two_ports(management="wlan0"):
    return hardware([
        link("eth0", ipv4=[], subnets=[]),
        link("wlan0", kind="wireless", ipv4=["10.10.0.5/16"], subnets=["10.10.0.0/16"]),
    ], management=management)


class HomeNetTest(BackendTestCase):
    def test_normalised_into_the_form_the_engine_expects(self):
        self.assertEqual(capture.normalise_home_net(["192.168.1.0/24", "10.0.0.0/8"]),
                         "[192.168.1.0/24,10.0.0.0/8]")

    def test_host_bits_are_tidied_and_duplicates_dropped(self):
        self.assertEqual(capture.normalise_home_net(["192.168.1.55/24", "192.168.1.0/24", ""]),
                         "[192.168.1.0/24]")

    def test_a_bare_address_is_accepted_as_a_single_host(self):
        self.assertEqual(capture.normalise_home_net(["192.168.1.5"]), "[192.168.1.5/32]")

    def test_ipv6_is_accepted(self):
        self.assertEqual(capture.normalise_home_net(["2001:db8::/32"]), "[2001:db8::/32]")

    def test_a_mistyped_network_names_itself(self):
        with self.assertRaises(capture.ApplyError) as raised:
            capture.normalise_home_net(["192.168.1.0/33"])
        self.assertIn("192.168.1.0/33", str(raised.exception))

    def test_an_empty_list_is_refused_with_the_reason(self):
        # Most rules only fire on traffic that ends inside HOME_NET, so an empty
        # one is a detector that loads every signature and matches nothing.
        with self.assertRaises(capture.ApplyError) as raised:
            capture.normalise_home_net(["  "])
        self.assertIn("HOME_NET", str(raised.exception))

    def test_suggestions_come_from_the_addresses_this_machine_has(self):
        with patch.object(capture.interfaces, "detect", return_value=two_ports()):
            self.assertEqual(capture.suggest_home_net(), ["10.10.0.0/16"])


class GuardTest(BackendTestCase):
    """The change is refused before anything is touched, not warned about.

    Recovering from a panel that took its own address away means walking to the
    device with a keyboard.
    """

    def _guard(self, profile_id, roles, detected):
        capture._guard(topology.PROFILES_BY_ID[profile_id], roles, detected)

    def test_a_layout_that_keeps_its_address_is_always_allowed(self):
        self._guard("self", {"capture": "eth0"}, two_ports(management="eth0"))

    def test_capture_and_panel_on_the_same_interface_is_refused(self):
        with self.assertRaises(capture.ApplyError) as raised:
            self._guard("mirror", {"capture": "eth0", "management": "eth0"}, two_ports())
        self.assertIn("at the same time", str(raised.exception))

    def test_capturing_on_the_interface_this_browser_uses_is_refused(self):
        with self.assertRaises(capture.ApplyError) as raised:
            self._guard("mirror", {"capture": "eth0", "management": "wlan0"},
                        two_ports(management="eth0"))
        self.assertIn("Reach the panel on wlan0 first", str(raised.exception))

    def test_a_management_path_with_no_address_is_refused(self):
        detected = hardware([
            link("eth0", ipv4=[], subnets=[]),
            link("wlan0", kind="wireless", ipv4=[], subnets=[]),
        ], management="eth0")
        with self.assertRaises(capture.ApplyError) as raised:
            self._guard("mirror", {"capture": "eth0", "management": "wlan0"}, detected)
        self.assertIn("no address", str(raised.exception))

    def test_a_working_second_path_passes(self):
        self._guard("mirror", {"capture": "eth0", "management": "wlan0"}, two_ports())


class ApplyTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.detect = self.enterContext(
            patch.object(capture.interfaces, "detect", return_value=two_ports())
        )
        self.run = self.enterContext(patch.object(capture, "_run", return_value=(True, "ok")))
        # Whatever this machine has in /etc/systemd is not what a test is about.
        self.dropin = self.tmp / "10-rapi-nfqueue.conf"
        self.enterContext(patch.object(capture, "QUEUE_DROPIN", self.dropin))

    def _choose(self, profile, roles):
        settings.set(topology.SETTINGS_KEY, {"profile": profile, "roles": roles,
                                             "chosen_at": "", "applied": False,
                                             "applied_at": "", "home_net": ""})

    def test_engine_configuration_first_then_the_interface_then_the_restart(self):
        # Order on purpose: the configuration step verifies itself and rolls
        # back, while an interface stripped of its address before that check
        # would cost the panel its way home for nothing.
        self._choose("mirror", {"capture": "eth0", "management": "wlan0"})
        result = capture.apply(["10.10.0.0/16"])
        commands = [call.args[0] for call in self.run.call_args_list]
        self.assertEqual(commands[0][:2], [capture.APPLY, "eth0"])
        self.assertEqual(commands[0][2], "[10.10.0.0/16]")
        self.assertEqual(commands[1], [capture.IFACE, "eth0", "capture"])
        self.assertEqual(commands[2], ["/usr/bin/systemctl", "restart", "suricata"])
        self.assertTrue(result["ok"])

    def test_a_mirror_takes_the_engine_off_the_queue(self):
        """The queue's drop-in outlives a change of layout.

        "This device only" with blocking on, then the mirror applied: the
        restart kept -q, the engine read this Pi's own packets from the queue
        and never the mirror port, and Apply said everything worked.
        """
        self.dropin.write_text("[Service]\nExecStart=\nExecStart=suricata -q 0\n")
        self._choose("mirror", {"capture": "eth0", "management": "wlan0"})
        result = capture.apply(["10.10.0.0/16"])
        commands = [call.args[0] for call in self.run.call_args_list]
        self.assertIn([capture.IPS_MODE, "ids"], commands)
        # Before the restart that is meant to start it on the mirror.
        self.assertLess(commands.index([capture.IPS_MODE, "ids"]),
                        commands.index(["/usr/bin/systemctl", "restart", "suricata"]))
        self.assertIn("blocking switched off", [s["step"] for s in result["steps"]])

    def test_a_mirror_that_cannot_leave_the_queue_is_not_applied(self):
        self.dropin.write_text("[Service]\n")
        self._choose("mirror", {"capture": "eth0", "management": "wlan0"})

        def run(command, timeout=120):
            return (False, "the engine would not restart") if command[0] == capture.IPS_MODE \
                else (True, "ok")
        self.run.side_effect = run
        result = capture.apply(["10.10.0.0/16"])
        self.assertFalse(result["ok"])
        self.assertFalse(settings.get(topology.SETTINGS_KEY)["applied"])

    def test_no_queue_no_extra_restart(self):
        self._choose("mirror", {"capture": "eth0", "management": "wlan0"})
        capture.apply(["10.10.0.0/16"])
        self.assertNotIn(capture.IPS_MODE, [c.args[0][0] for c in self.run.call_args_list])

    def test_this_device_only_keeps_its_queue(self):
        # There the queue is what blocking means: this Pi's own traffic.
        self.dropin.write_text("[Service]\n")
        self.detect.return_value = two_ports(management="eth0")
        self._choose("self", {"capture": "eth0"})
        capture.apply(["10.10.0.0/16"])
        self.assertNotIn(capture.IPS_MODE, [c.args[0][0] for c in self.run.call_args_list])

    def test_the_path_is_the_one_the_helper_writes(self):
        helper = (PROJECT_ROOT / "deploy" / "rapi-ips-mode").read_text()
        self.assertIn('DROPIN="$DROPIN_DIR/10-rapi-nfqueue.conf"', helper)
        self.assertIn('DROPIN_DIR="$UNIT_DIR/suricata.service.d"', helper)
        self.assertIn('UNIT_DIR="${RAPI_SYSTEMD_DIR:-/etc/systemd/system}"', helper)
        # The default the panel reads is patched above, so it is read from the
        # source, which is what ships.
        source = Path(capture.__file__).read_text()
        self.assertIn('"/etc/systemd/system/suricata.service.d/10-rapi-nfqueue.conf"', source)

    def test_a_layout_that_keeps_its_address_does_not_touch_the_interface(self):
        self.detect.return_value = two_ports(management="eth0")
        self._choose("self", {"capture": "eth0"})
        capture.apply(["10.10.0.0/16"])
        commands = [call.args[0] for call in self.run.call_args_list]
        self.assertNotIn(capture.IFACE, [c[0] for c in commands])

    def test_success_is_recorded_with_the_home_networks(self):
        self._choose("self", {"capture": "eth0"})
        self.detect.return_value = two_ports(management="eth0")
        capture.apply(["10.10.0.0/16"])
        stored = settings.get(topology.SETTINGS_KEY)
        self.assertTrue(stored["applied"])
        self.assertEqual(stored["home_net"], "[10.10.0.0/16]")
        self.assertTrue(stored["applied_at"])

    def test_a_rejected_configuration_stops_before_the_restart(self):
        self._choose("self", {"capture": "eth0"})
        self.detect.return_value = two_ports(management="eth0")
        self.run.return_value = (False, "the engine rejected this configuration")
        with self.assertRaises(capture.ApplyError):
            capture.apply(["10.10.0.0/16"])
        self.assertEqual(self.run.call_count, 1)
        self.assertFalse(settings.get(topology.SETTINGS_KEY)["applied"])

    def test_a_failed_restart_is_reported_and_not_recorded_as_applied(self):
        self._choose("self", {"capture": "eth0"})
        self.detect.return_value = two_ports(management="eth0")
        self.run.side_effect = [(True, "ok"), (False, "Job for suricata.service failed")]
        result = capture.apply(["10.10.0.0/16"])
        self.assertFalse(result["ok"])
        self.assertFalse(settings.get(topology.SETTINGS_KEY)["applied"])

    def test_nothing_chosen_yet(self):
        with self.assertRaises(capture.ApplyError):
            capture.apply(["10.10.0.0/16"])

    def test_a_layout_the_panel_cannot_finish_is_refused(self):
        """The belt for a layout that does not exist today.

        Every shipped profile can be applied - "The Pi is the router" was the
        last that could not, and it was removed rather than left in a chooser of
        things the button at the end does. The guard stays because this path
        reconfigures a live network and half of that is an outage, so it is
        exercised here against a profile made for the purpose rather than left
        as code nothing can reach.
        """
        unappliable = replace(topology.PROFILES_BY_ID["mirror"],
                              id="unappliable", can_apply=False)
        self.enterContext(patch.dict(topology.PROFILES_BY_ID,
                                     {"unappliable": unappliable}))
        self._choose("unappliable", {"capture": "eth0", "management": "wlan0"})
        with self.assertRaises(capture.ApplyError) as raised:
            capture.apply(["10.10.0.0/16"])
        self.assertIn("cannot set up", str(raised.exception))

    def test_an_interface_that_has_been_unplugged_since(self):
        self._choose("mirror", {"capture": "eth9", "management": "wlan0"})
        with self.assertRaises(capture.ApplyError) as raised:
            capture.apply(["10.10.0.0/16"])
        self.assertIn("not there any more", str(raised.exception))

    def test_a_bad_home_network_is_caught_before_anything_runs(self):
        self._choose("self", {"capture": "eth0"})
        self.detect.return_value = two_ports(management="eth0")
        with self.assertRaises(capture.ApplyError):
            capture.apply(["192.168.1.0/33"])
        self.run.assert_not_called()


def three_ports(management="wlan0"):
    """Two wired ports and a radio: the hardware an inline bridge needs."""
    return hardware([
        link("eth0"),
        link("eth1", mac="de:ad:be:ef:00:03"),
        link("wlan0", kind="wireless", ipv4=["10.10.0.5/16"], subnets=["10.10.0.0/16"]),
    ], management=management)


class InlineBlockingTest(BackendTestCase):
    """Blocking on the inline layout, which is a mode and not a second layout.

    The panel's half of it is small on purpose. Every step of the swap, the
    rollback included, lives in rapi-inline and is tested there against the
    order it runs in. What is left here is choosing the mode, refusing when
    there is no inline layout in effect, and turning the helper's three answers
    into something the operator can act on without ever raising.
    """

    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(capture.interfaces, "detect",
                                       return_value=three_ports()))
        self.run = self.enterContext(patch.object(capture, "_run",
                                                  return_value=(True, "ok pair eth0,eth1")))
        settings.set(topology.SETTINGS_KEY, {
            "profile": "bridge",
            "roles": {"bridge_a": "eth0", "bridge_b": "eth1", "management": "wlan0"},
            "home_net": "[10.10.0.0/16]", "applied": True, "applied_at": "",
            "chosen_at": "",
        })

    def commands(self):
        return [call.args[0] for call in self.run.call_args_list]

    def test_the_pair_is_the_layout_in_effect(self):
        self.assertEqual(capture.inline_members(), ["eth0", "eth1"])

    def test_a_layout_only_chosen_is_not_in_effect(self):
        """The wizard stores a layout the moment its step is saved.

        Nothing is written to the engine then and no home networks are
        recorded. Read as inline, it told the Protection screen the kernel was
        forwarding while the engine was still on the previous interface.
        """
        stored = settings.get(topology.SETTINGS_KEY)
        settings.set(topology.SETTINGS_KEY, {**stored, "applied": False})
        self.assertEqual(capture.inline_members(), [])

    def test_a_layout_without_home_networks_is_not_in_effect(self):
        stored = settings.get(topology.SETTINGS_KEY)
        settings.set(topology.SETTINGS_KEY, {**stored, "home_net": ""})
        self.assertEqual(capture.inline_members(), [])

    def test_a_passive_layout_has_no_pair(self):
        # With the roles of the previous layout still stored. The profile
        # decides, not the leftovers.
        settings.set(topology.SETTINGS_KEY, {
            "profile": "mirror", "applied": True, "home_net": "[10.10.0.0/16]",
            "roles": {"capture": "eth0", "bridge_a": "eth0", "bridge_b": "eth1"},
        })
        self.assertEqual(capture.inline_members(), [])

    def test_blocking_asks_the_helper_for_the_pair(self):
        ok, _ = capture.set_inline_blocking(True)
        self.assertTrue(ok)
        self.assertEqual(self.commands(),
                         [[capture.INLINE, "pair", "eth0", "eth1", "[10.10.0.0/16]"]])

    def test_watching_asks_the_helper_for_the_bridge(self):
        ok, _ = capture.set_inline_blocking(False)
        self.assertTrue(ok)
        self.assertEqual(self.commands(),
                         [[capture.INLINE, "bridge", "eth0", "eth1", "[10.10.0.0/16]"]])

    def test_the_swap_is_given_as_long_as_the_engine_takes_to_load(self):
        # A stop, a rebuild and a start with 68,000 rules. The default two
        # minutes of _run cut it off halfway and reported a failure the helper
        # had not had.
        capture.set_inline_blocking(True)
        self.assertEqual(self.run.call_args.args[1], capture.RESTART_TIMEOUT)

    def test_a_fallback_says_the_link_carries_traffic_and_nothing_is_blocked(self):
        # Not ok, but not an outage either. The operator has to be told which.
        self.run.return_value = (False, "fallback bridge: the ports could not be handed "
                                        "to the engine. The kernel bridge is carrying the link.")
        ok, output = capture.set_inline_blocking(True)
        self.assertFalse(ok)
        self.assertIn("traffic flows and nothing is blocked", output)
        self.assertIn("could not be handed to the engine", output)

    def test_a_fallback_is_recognised_with_the_cause_printed_after_it(self):
        # What the helper really prints: the fallback line, then the words of
        # the step that failed. Read from the last line, this came out as a raw
        # failure without the one sentence that says the link still works.
        self.run.return_value = (False, "fallback bridge: the ports could not be handed "
                                        "to the engine. The kernel bridge is carrying the link.\n"
                                        "first cause:\nError: device eth1 not available")
        ok, output = capture.set_inline_blocking(True)
        self.assertFalse(ok)
        self.assertIn("traffic flows and nothing is blocked", output)

    def test_a_failure_with_the_link_down_is_passed_on_in_the_helper_s_words(self):
        self.run.return_value = (False, "failed: the link is down: the engine would not "
                                        "start, and the kernel bridge could not be put back")
        ok, output = capture.set_inline_blocking(True)
        self.assertFalse(ok)
        self.assertIn("the link is down", output)
        self.assertNotIn("traffic flows", output)

    def test_it_never_raises(self):
        # The route that calls it turns an exception into a 500 and loses the
        # helper's own words.
        self.run.return_value = (False, "")
        ok, _ = capture.set_inline_blocking(True)
        self.assertFalse(ok)

    def test_it_refuses_on_a_layout_that_is_not_in_effect(self):
        settings.set(topology.SETTINGS_KEY, {"profile": "mirror",
                                             "roles": {"capture": "eth0"}})
        ok, output = capture.set_inline_blocking(True)
        self.assertFalse(ok)
        self.assertIn("not an inline layout in effect", output)
        self.assertEqual(self.commands(), [])


class LayoutChangeTest(BackendTestCase):
    """Moving from one layout to another, which has to undo the last one.

    A port the panel took out of NetworkManager stays out of it: the rule is on
    disk and a unit reapplies it after every reboot.
    """

    def setUp(self):
        super().setUp()
        self.detect = self.enterContext(
            patch.object(capture.interfaces, "detect", return_value=three_ports()))
        self.run = self.enterContext(patch.object(capture, "_run",
                                                  return_value=(True, "ok")))
        self.sys_net = self.tmp / "class-net"
        for name, mac in (("eth0", "de:ad:be:ef:00:00"), ("eth1", "de:ad:be:ef:00:01"),
                          ("eth2", "de:ad:be:ef:00:02"), ("wlan0", "de:ad:be:ef:00:03")):
            (self.sys_net / name).mkdir(parents=True)
            (self.sys_net / name / "address").write_text(mac + "\n")
        self.enterContext(patch.object(capture, "SYS_NET", self.sys_net))

    def commands(self):
        return [call.args[0] for call in self.run.call_args_list]

    def _stored(self, profile, roles):
        settings.set(topology.SETTINGS_KEY, {"profile": profile, "roles": roles,
                                             "chosen_at": "", "applied": True,
                                             "applied_at": "", "home_net": ""})

    def _holds(self, name, mac=None, file_name=None):
        """What rapi-capture-iface leaves for a port it took: a file matched by MAC."""
        conf = capture.NM_CONF_DIR
        mac = mac or (self.sys_net / name / "address").read_text().strip()
        (conf / f"{capture.CAPTURE_CONF_PREFIX}{file_name or name}.conf").write_text(
            f"[device-rapi-capture-{file_name or name}]\nmatch-device=mac:{mac}\nmanaged=0\n")

    def test_what_is_held_is_read_from_disk_not_from_the_settings(self):
        self._holds("eth0")
        self._holds("eth1")
        self.assertEqual(capture.held_interfaces(), {"eth0", "eth1"})

    def test_a_port_held_under_its_old_name_is_found_by_its_card(self):
        """The file says eth9. The card it matches is eth1 today.

        Releasing eth9 fails with "no such interface" and leaves eth1
        unmanaged, which is the failure releasing exists to prevent.
        """
        self._holds("eth1", file_name="eth9")
        self.assertEqual(capture.held_interfaces(), {"eth1"})

    def test_a_file_whose_card_is_gone_names_nothing(self):
        self._holds("eth7", mac="aa:aa:aa:aa:aa:aa", file_name="eth7")
        self.assertEqual(capture.held_interfaces(), set())

    def test_only_this_panel_s_own_files_count(self):
        # The directory belongs to NetworkManager. A name long enough that
        # dropping the prefix check would produce one, not an empty string.
        (capture.NM_CONF_DIR / "99-other-plugin-settings.conf").write_text("[main]\n")
        self._holds("eth0")
        self.assertEqual(capture.held_interfaces(), {"eth0"})

    def test_leaving_an_inline_layout_hands_the_other_port_back(self):
        self._holds("eth0")
        self._holds("eth1")
        self._stored("mirror", {"capture": "eth1", "management": "wlan0"})
        capture.apply(["10.10.0.0/16"])
        released = [c for c in self.commands() if c[-1] == "restore"]
        self.assertEqual(released, [[capture.IFACE, "eth0", "restore"]])

    def test_nothing_is_released_before_the_configuration_is_accepted(self):
        """A refused configuration used to cost nothing, and then it cost a port.

        Released first, a port went back to NetworkManager with DHCP and its
        offloads on, and the error that followed said nothing had changed.
        """
        self._holds("eth0")
        self._stored("mirror", {"capture": "eth1", "management": "wlan0"})
        self.run.side_effect = lambda cmd, *a, **k: (
            (False, "rejected") if cmd[0] == capture.APPLY else (True, "ok"))
        with self.assertRaises(capture.ApplyError):
            capture.apply(["10.10.0.0/16"])
        self.assertEqual(self.commands(), [[capture.APPLY, "eth1", "[10.10.0.0/16]"]])

    def test_a_release_that_failed_is_reported(self):
        # The next step fails because of it, and without this the operator
        # reads only the second error.
        self._holds("eth0")
        self._stored("mirror", {"capture": "eth1", "management": "wlan0"})
        self.run.side_effect = lambda cmd, *a, **k: (
            (False, "device busy") if cmd[-1] == "restore" else (True, "ok"))
        result = capture.apply(["10.10.0.0/16"])
        self.assertFalse(result["ok"])
        self.assertTrue(any(step["step"] == "release eth0" and not step["ok"]
                            for step in result["steps"]))

    def test_leaving_an_inline_layout_takes_its_bridge_down(self):
        (self.sys_net / "br-rapi").mkdir()
        self._stored("mirror", {"capture": "eth1", "management": "wlan0"})
        capture.apply(["10.10.0.0/16"])
        commands = self.commands()
        self.assertIn([capture.BRIDGE, capture.BRIDGE_NAME, "down"], commands)
        # After the configuration was accepted, like every other change.
        self.assertLess(commands.index([capture.APPLY, "eth1", "[10.10.0.0/16]"]),
                        commands.index([capture.BRIDGE, capture.BRIDGE_NAME, "down"]))

    def test_the_interface_the_new_layout_wants_is_not_bounced(self):
        self._holds("eth0")
        self._stored("mirror", {"capture": "eth0", "management": "wlan0"})
        capture.apply(["10.10.0.0/16"])
        self.assertNotIn([capture.IFACE, "eth0", "restore"], self.commands())

    def test_an_inline_layout_leaves_its_own_ports_to_the_helper(self):
        # Released after the bridge is up, a live member gets its offloads
        # turned back on and nothing turns them off again.
        self._holds("eth0")
        self._holds("eth2")
        self._stored("bridge", {"bridge_a": "eth0", "bridge_b": "eth1",
                                "management": "wlan0"})
        capture.apply(["10.10.0.0/16"])
        released = [c for c in self.commands() if c[-1] == "restore"]
        self.assertEqual(released, [[capture.IFACE, "eth2", "restore"]])

    def test_an_old_port_that_will_not_let_go_leaves_the_bridge_in_effect(self):
        """The bridge is up. A port of an earlier layout refused to be released.

        Counted as a layout that did not go in, inline_members() answered "not
        inline" for a live bridge, and the blocking switch turned on the queue,
        which bridged frames never reach, and reported blocking.
        """
        self._holds("eth2")
        self._stored("bridge", {"bridge_a": "eth0", "bridge_b": "eth1",
                                "management": "wlan0"})
        self.run.side_effect = lambda cmd, *a, **k: (
            (False, "device busy") if cmd[-1] == "restore" else (True, "ok bridge"))
        result = capture.apply(["10.10.0.0/16"])
        self.assertFalse(result["ok"])
        self.assertTrue(settings.get(topology.SETTINGS_KEY)["applied"])
        self.assertEqual(capture.inline_members(), ["eth0", "eth1"])

    def test_a_panel_that_holds_nothing_releases_nothing(self):
        self._stored("self", {"capture": "eth0"})
        capture.apply(["10.10.0.0/16"])
        self.assertEqual([c for c in self.commands() if c[-1] == "restore"], [])


class HomeNetCacheTest(BackendTestCase):
    """The panel's own copy of HOME_NET has to die when the helper rewrites it.

    Only the engine is restarted by the wizard, never the panel, and
    geoip.home_networks() is cached for the life of the process. Alerts
    classified in between are bucketed against the old HOME_NET, and src_cc is
    worked out once and stored on the row: the map shows this network as a
    foreign country for those alerts for good.
    """

    def setUp(self):
        super().setUp()
        self.state = self.tmp / "rapi-home-net"
        self.enterContext(patch.object(geoip, "HOME_NET_STATE", self.state))
        geoip.home_networks.cache_clear()
        self.addCleanup(geoip.home_networks.cache_clear)
        self.enterContext(
            patch.object(capture.interfaces, "detect",
                         return_value=two_ports(management="eth0")))

        def helper(cmd, *args, **kwargs):
            # Stands in for the helpers that write this file: rapi-capture-apply
            # directly, and rapi-inline through it.
            if cmd[0] == capture.APPLY:
                self.state.write_text(cmd[2], encoding="utf-8")
            if cmd[0] == capture.INLINE:
                self.state.write_text(cmd[4], encoding="utf-8")
            return (True, "ok")

        self.enterContext(patch.object(capture, "_run", side_effect=helper))
        settings.set(topology.SETTINGS_KEY,
                     {"profile": "self", "roles": {"capture": "eth0"},
                      "chosen_at": "", "applied": False, "applied_at": "",
                      "home_net": ""})

    def test_the_next_alert_is_classified_against_the_new_home_net(self):
        self.state.write_text("[10.0.0.0/24]", encoding="utf-8")
        # Reading it once is what fills the cache, exactly as the first alert
        # after boot does.
        self.assertFalse(geoip.is_home("198.51.100.40"))
        capture.apply(["198.51.100.0/24"])
        self.assertTrue(geoip.is_home("198.51.100.40"))

    def test_the_bridge_layout_drops_it_too(self):
        # The other route through this module writes HOME_NET with the same
        # helper, and had the same cache behind it.
        self.state.write_text("[10.0.0.0/24]", encoding="utf-8")
        self.assertFalse(geoip.is_home("198.51.100.40"))
        capture.interfaces.detect.return_value = three_ports()
        settings.set(topology.SETTINGS_KEY,
                     {"profile": "bridge",
                      "roles": {"bridge_a": "eth0", "bridge_b": "eth1",
                                "management": "wlan0"}})
        capture.apply(["198.51.100.0/24"])
        self.assertTrue(geoip.is_home("198.51.100.40"))

    def test_the_old_network_stops_being_home_as_well(self):
        # Both directions, because keeping the old value alongside the new one
        # would still be wrong and would still pass the check above.
        self.state.write_text("[10.0.0.0/24]", encoding="utf-8")
        self.assertTrue(geoip.is_home("10.0.0.5"))
        capture.apply(["198.51.100.0/24"])
        self.assertFalse(geoip.is_home("10.0.0.5"))


class BridgeApplyTest(BackendTestCase):
    """The one layout where the panel can take a working network down."""

    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(capture.interfaces, "detect",
                                       return_value=three_ports()))
        self.run = self.enterContext(patch.object(capture, "_run",
                                                  return_value=(True, "ok")))
        settings.set(topology.SETTINGS_KEY, {
            "profile": "bridge",
            "roles": {"bridge_a": "eth0", "bridge_b": "eth1", "management": "wlan0"},
        })

    def commands(self):
        return [call.args[0] for call in self.run.call_args_list]

    def test_the_layout_is_built_by_the_same_helper_as_the_blocking_switch(self):
        """One implementation of how the link is built, and one order.

        The wizard used to build the bridge itself and the switch used a second
        sequence for the same two ports. Every review found another state the
        two disagreed about. The order is tested once, in the helper.
        """
        result = capture.apply(["10.10.0.0/16"])
        self.assertTrue(result["ok"])
        self.assertEqual(self.commands(), [
            [capture.INLINE, "bridge", "eth0", "eth1", "[10.10.0.0/16]"]])

    def test_the_engine_is_pointed_at_the_bridge_not_at_a_cable(self):
        # Listening on one member would see one direction of the conversation.
        result = capture.apply(["10.10.0.0/16"])
        self.assertEqual(result["interface"], capture.BRIDGE_NAME)
        self.assertEqual(result["members"], ["eth0", "eth1"])

    def test_a_layout_that_did_not_go_in_is_not_recorded_as_applied(self):
        # Recorded as applied, the Protection screen would offer a switch for a
        # link that is not there and describe a kernel bridge that is not up.
        self.run.return_value = (False, "failed: the link is down: the engine would not start")
        result = capture.apply(["10.10.0.0/16"])
        self.assertFalse(result["ok"])
        self.assertFalse(settings.get(topology.SETTINGS_KEY)["applied"])
        self.assertIn("link is down", result["steps"][0]["output"])

    def test_a_layout_that_did_go_in_is_recorded_with_its_home_networks(self):
        # inline_members() reads both, and the blocking switch needs both.
        capture.apply(["10.10.0.0/16"])
        stored = settings.get(topology.SETTINGS_KEY)
        self.assertTrue(stored["applied"])
        self.assertEqual(stored["home_net"], "[10.10.0.0/16]")

    def test_the_way_into_the_panel_cannot_be_one_of_the_two_cables(self):
        settings.set(topology.SETTINGS_KEY, {
            "profile": "bridge",
            "roles": {"bridge_a": "eth0", "bridge_b": "wlan0", "management": "wlan0"},
        })
        with self.assertRaises(capture.ApplyError) as raised:
            capture.apply(["10.10.0.0/16"])
        self.assertIn("at the same time", str(raised.exception))

    def test_one_interface_cannot_be_both_sides(self):
        settings.set(topology.SETTINGS_KEY, {
            "profile": "bridge",
            "roles": {"bridge_a": "eth0", "bridge_b": "eth0", "management": "wlan0"},
        })
        with self.assertRaises(capture.ApplyError) as raised:
            capture.apply(["10.10.0.0/16"])
        self.assertIn("two parts", str(raised.exception))

    def test_the_browser_side_of_the_bridge_is_refused(self):
        # Same guard as the passive layouts, now covering both members.
        self.enterContext(patch.object(capture.interfaces, "detect",
                                       return_value=three_ports(management="eth1")))
        with self.assertRaises(capture.ApplyError) as raised:
            capture.apply(["10.10.0.0/16"])
        self.assertIn("Reach the panel on wlan0", str(raised.exception))
