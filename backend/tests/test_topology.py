"""The layouts a Pi can be wired in, and recording which one applies."""
from __future__ import annotations

from unittest.mock import patch

from app import settings
from app.modules.network import topology
from app.modules.suricata import protection

from .helpers import BackendTestCase, hardware, link


def one_port():
    """A stock Pi 5: one wired port carrying the panel, one radio, no address."""
    return hardware([
        link("eth0"),
        link("wlan0", kind="wireless", ipv4=[], subnets=[], carrier=False,
             speed_mbps=None),
    ], management="eth0")


def two_ports():
    return hardware([
        link("eth0"),
        link("eth1", usb=True, driver="cdc_ether", ipv4=[], subnets=[]),
        link("wlan0", kind="wireless", ipv4=["10.10.0.5/16"], subnets=["10.10.0.0/16"]),
    ], management="eth0")


class ProfileTest(BackendTestCase):
    def test_every_layout_asks_for_as_many_interfaces_as_it_has_roles(self):
        # The invariant behind the fix above, checked for every layout rather
        # than the two that were wrong: a role is an interface, so a layout
        # offered on fewer interfaces than it has roles cannot be completed.
        for profile in topology.PROFILES:
            with self.subTest(profile=profile.id):
                self.assertGreaterEqual(profile.usable_needed, len(profile.roles))

    def test_every_layout_says_what_it_is_blind_to(self):
        # The whole point of the screen: a layout that sees nothing looks
        # exactly like one that works.
        for profile in topology.PROFILES:
            with self.subTest(profile=profile.id):
                self.assertTrue(profile.sees.strip())
                self.assertTrue(profile.blind_to.strip())
                self.assertTrue(profile.steps)

    def test_every_role_has_a_label(self):
        for profile in topology.PROFILES:
            for role in profile.roles:
                self.assertIn(role, topology.ROLE_LABELS)

    def test_no_vendor_names_anywhere(self):
        # The same feature is called port mirroring, SPAN or monitor mode
        # depending on who built the switch.
        text = " ".join(
            " ".join([p.name, p.summary, p.sees, p.blind_to, p.hardware, *p.steps]).lower()
            for p in topology.PROFILES
        )
        # The generic feature names are fine and are listed on purpose ("port
        # mirroring, SPAN or monitor mode"). Brand names are what has to stay out.
        for vendor in ("cisco", "ubiquiti", "unifi", "netgear", "tp-link", "mikrotik",
                       "juniper", "aruba", "zyxel"):
            self.assertNotIn(vendor, text)

    def test_only_the_layouts_the_panel_can_finish_are_marked_so(self):
        # A bridge or a router is a working network, and half of one is an
        # outage, so the panel records those and does not attempt them.
        appliable = {p.id for p in topology.PROFILES if p.can_apply}
        # The router is the one left: it is addresses, DHCP and a firewall, not
        # an interface setting, and half of it is somebody's internet gone.
        self.assertEqual(appliable, {"self", "mirror", "bridge"})

    def test_blocking_needs_the_traffic_to_pass_through(self):
        for profile in topology.PROFILES:
            if profile.can_block:
                self.assertFalse(profile.passive, profile.id)


class ProfileWordingTest(BackendTestCase):
    """What the layouts promise, against what the wiring can deliver."""

    def test_the_bridge_does_not_promise_lossless_inspection(self):
        # Passing through the Pi means no copy is needed, not that the engine
        # keeps up: it can still fall behind, and its counter says when.
        bridge = next(p for p in topology.PROFILES if p.id == "bridge")
        text = f"{bridge.summary} {bridge.sees}".lower()
        self.assertNotIn("nothing is missed", text)
        self.assertNotIn("nothing lost", text)
        self.assertIn("capture loss", text)


class AvailabilityTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.detect = self.enterContext(patch.object(topology.interfaces, "detect"))

    def _profiles(self, detected):
        self.detect.return_value = detected
        return {p["id"]: p for p in topology.state()["profiles"]}

    def test_one_port_can_only_watch_itself_and_says_why(self):
        profiles = self._profiles(one_port())
        self.assertTrue(profiles["self"]["available"])
        self.assertFalse(profiles["bridge"]["available"])
        self.assertIn("USB Ethernet adapter", profiles["bridge"]["reason"])

    def test_a_radio_counts_as_the_second_interface_for_a_mirror(self):
        # Capture needs the wired port to itself; the panel can live on Wi-Fi.
        self.assertTrue(self._profiles(one_port())["mirror"]["available"])

    def test_a_mirror_needs_a_second_interface_of_some_kind(self):
        single = hardware([link("eth0")], management="eth0")
        self.assertFalse(self._profiles(single)["mirror"]["available"])

    def test_two_wired_ports_open_the_inline_layouts(self):
        profiles = self._profiles(two_ports())
        self.assertTrue(profiles["bridge"]["available"])

    def test_a_layout_is_never_offered_with_fewer_ports_than_it_has_roles(self):
        # Two wired ports and no radio: enough for the bridge itself, nothing
        # left to reach the panel by. It used to be offered anyway, and the
        # wizard then refused to save with "no interface chosen for: Panel
        # access" the moment the interfaces step opened - a dead end reached by
        # following the screen.
        no_radio = hardware([
            link("eth0"),
            link("eth1", usb=True, driver="r8152", ipv4=[], subnets=[]),
        ], management="eth0")
        profiles = self._profiles(no_radio)
        self.assertFalse(profiles["bridge"]["available"])
        # And the mirror still is: two roles, two interfaces.
        self.assertTrue(profiles["mirror"]["available"])

    def test_the_panel_offers_no_layout_it_cannot_put_into_effect(self):
        """The chooser only lists things the button at the end can do.

        "The Pi is the router" was the one exception and it was a trap: the most
        invasive layout on the list was the only one the panel could not build,
        so picking it led to a step saying so and to a stored value whose single
        effect was to make Apply refuse. The image goes to networks nobody here
        has seen; a wizard that otherwise acts must not offer "replace your
        router" among the things it acts on.
        """
        for profile in topology.PROFILES:
            with self.subTest(profile=profile.id):
                self.assertTrue(profile.can_apply, profile.id)
        self.assertNotIn("gateway", topology.PROFILES_BY_ID)

    def test_a_stored_layout_that_no_longer_exists_reads_as_no_choice(self):
        """Layouts get retired; the devices that chose them keep running.

        "Network tap" and "The Pi is the router" have both been taken out. A
        stored id with no card behind it came back as a choice the wizard could
        not find, so the first step showed nothing selected and every step after
        it rendered blank - a wizard that cannot be finished and does not say
        why. Reported as no choice, with the retired name kept so the screen can
        say what happened. The engine keeps the capture interface and HOME_NET
        it was given; nothing here touches those.
        """
        self.detect.return_value = two_ports()
        with patch.object(settings, "get", return_value={
                "profile": "tap", "roles": {"capture": "eth0"}}):
            current = topology.state()["current"]
        self.assertEqual(current["profile"], "")
        self.assertEqual(current["roles"], {})
        self.assertEqual(current["retired"], "tap")

    def test_a_stored_layout_that_still_exists_is_left_alone(self):
        self.detect.return_value = two_ports()
        with patch.object(settings, "get", return_value={
                "profile": "mirror", "roles": {"capture": "eth0"}}):
            current = topology.state()["current"]
        self.assertEqual(current["profile"], "mirror")
        self.assertEqual(current["roles"], {"capture": "eth0"})
        self.assertNotIn("retired", current)

    def test_only_a_layout_the_traffic_crosses_claims_it_can_block(self):
        """Being in the path is necessary, and it is not sufficient on its own.

        A passive layout cannot block whatever the engine is set to: a copy
        cannot be stopped, and NFQUEUE on a host's own input and output stops
        that host's traffic, not the network's. Only a layout the traffic
        crosses can make the claim, and then only because the mode switch hands
        the forwarding to the engine.
        """
        for profile in topology.PROFILES:
            with self.subTest(profile=profile.id):
                if profile.passive:
                    self.assertFalse(profile.can_block, profile.id)

    def test_the_one_passive_layout_left_covers_a_tap_as_well(self):
        """Removed rather than merged, so the fact has to live somewhere.

        The panel configured "Mirror port on a switch" and "Network tap"
        identically - same roles, same requirements, same apply path, different
        prose and picture. With the tap card gone, its owner would otherwise be
        sent to set up a switch feature they do not use, and would not be told
        that a non-aggregating tap needs two capture interfaces to this panel's
        one.
        """
        steps = " ".join(topology.PROFILES_BY_ID["mirror"].steps).lower()
        self.assertIn("tap", steps)
        self.assertIn("aggregating", steps)

    def test_the_layout_that_needs_nothing_is_never_refused_for_hardware(self):
        """A board with no Ethernet is still a sensor watching its own traffic.

        `self` inherited wired_needed=1, so on a Zero W the card reading
        "Nothing. This is how the device works out of the box." was refused with
        "A USB Ethernet adapter adds one" printed underneath it.
        """
        radio_only = hardware([link("wlan0", kind="wireless")], management="wlan0")
        self.assertTrue(self._profiles(radio_only)["self"]["available"])

    def test_a_layout_names_every_interface_it_needs(self):
        """The Needs line has to agree with the count that decides availability.

        `bridge` said "two wired interfaces" while __post_init__ raises its
        requirement to three - two for the traffic and one to reach the panel
        by. Someone buys one adapter on the strength of that line and the layout
        is still greyed out, with a reason describing a device they do not have.
        """
        for profile in topology.PROFILES:
            if profile.usable_needed < 2:
                continue
            with self.subTest(profile=profile.id):
                self.assertRegex(
                    profile.hardware.lower(),
                    r"(second|third) way into the panel|panel",
                    f"{profile.id} needs {profile.usable_needed} interfaces and "
                    "its hardware line does not mention the one for the panel")

    def test_the_refusal_counts_in_words_that_agree_with_the_number(self):
        radio_only = hardware([link("wlan0", kind="wireless")], management="wlan0")
        reason = self._profiles(radio_only)["mirror"]["reason"]
        self.assertIn("1 wired interface,", reason)
        self.assertNotIn("1 wired interfaces", reason)

    def test_unavailable_layouts_are_still_returned(self):
        # Hiding the bridge on a one-port Pi saves a line of screen and costs
        # the reader the fact that a cheap adapter is the whole difference.
        self.assertEqual(len(self._profiles(one_port())), len(topology.PROFILES))


class AssignTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.detect = self.enterContext(patch.object(topology.interfaces, "detect"))
        self.detect.return_value = two_ports()

    def test_a_choice_is_recorded_but_not_marked_as_applied(self):
        # Clicking through a wizard is not the same as the engine having been
        # told about it.
        result = topology.assign("mirror", {"capture": "eth1", "management": "wlan0"})
        self.assertTrue(result["saved"])
        stored = settings.get("topology")
        self.assertEqual(stored["profile"], "mirror")
        self.assertEqual(stored["roles"], {"capture": "eth1", "management": "wlan0"})
        self.assertFalse(stored["applied"])
        self.assertTrue(stored["chosen_at"])

    def _applied(self, profile, roles):
        settings.set("topology", {"profile": profile, "roles": roles, "chosen_at": "",
                                  "applied": True, "home_net": "[10.0.2.0/24]",
                                  "applied_at": "2026-09-25T11:46:51+00:00"})

    def test_saving_the_running_layout_again_keeps_it_applied(self):
        """Back through the wizard and "Save and continue" on the same choice.

        It used to mark the layout unapplied, and blocking then refused with
        "apply the layout first" on a device running exactly that layout.
        """
        self._applied("mirror", {"capture": "eth1", "management": "wlan0"})
        topology.assign("mirror", {"capture": "eth1", "management": "wlan0"})
        stored = settings.get("topology")
        self.assertTrue(stored["applied"])
        self.assertEqual(stored["home_net"], "[10.0.2.0/24]")
        self.assertEqual(stored["applied_at"], "2026-09-25T11:46:51+00:00")

    def test_a_different_choice_is_not_applied_until_it_is(self):
        for profile, roles in (("mirror", {"capture": "eth0", "management": "wlan0"}),
                               ("self", {"capture": "eth1"})):
            with self.subTest(profile=profile, roles=roles):
                self._applied("mirror", {"capture": "eth1", "management": "wlan0"})
                topology.assign(profile, roles)
                self.assertFalse(settings.get("topology")["applied"])

    def test_a_dry_run_warns_without_writing(self):
        result = topology.assign("mirror", {"capture": "eth0", "management": "wlan0"},
                                 persist=False)
        self.assertFalse(result["saved"])
        self.assertTrue(result["warnings"])
        self.assertEqual(settings.get("topology")["profile"], "")

    def test_an_unknown_layout_is_refused(self):
        with self.assertRaises(ValueError):
            topology.assign("mirror-port", {"capture": "eth1"})

    def test_a_missing_role_is_refused_by_its_label(self):
        with self.assertRaises(ValueError) as raised:
            topology.assign("mirror", {"capture": "eth1"})
        self.assertIn("Panel access", str(raised.exception))

    def test_an_interface_that_is_gone_is_refused(self):
        # Validated against the hardware as it is now: an adapter can be pulled
        # out between opening the page and pressing the button.
        with self.assertRaises(ValueError):
            topology.assign("mirror", {"capture": "eth9", "management": "wlan0"})

    def test_one_interface_cannot_fill_two_roles(self):
        with self.assertRaises(ValueError):
            topology.assign("bridge", {"bridge_a": "eth0", "bridge_b": "eth0",
                                       "management": "wlan0"})


class WarningTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.detect = self.enterContext(patch.object(topology.interfaces, "detect"))

    def _warnings(self, profile_id, roles, detected):
        self.detect.return_value = detected
        return topology.assign(profile_id, roles, persist=False)["warnings"]

    def test_capturing_on_the_management_interface_is_called_out(self):
        notes = self._warnings("mirror", {"capture": "eth0", "management": "wlan0"},
                               two_ports())
        self.assertTrue(any("unreachable" in note for note in notes))

    def test_the_layout_that_keeps_its_address_gets_no_such_warning(self):
        # Warning here would train people to click past the warning that matters.
        self.assertEqual(self._warnings("self", {"capture": "eth0"}, one_port()), [])

    def test_a_radio_switched_off_in_software_is_called_out(self):
        detected = hardware([
            link("eth0"),
            link("eth1", ipv4=[], subnets=[]),
            link("wlan0", kind="wireless", ipv4=[], subnets=[], blocked=True,
                 carrier=False),
        ], management="eth0")
        notes = self._warnings("mirror", {"capture": "eth1", "management": "wlan0"},
                               detected)
        self.assertTrue(any("switched off in software" in note for note in notes))

    def test_a_management_path_with_no_address_is_called_out(self):
        detected = hardware([
            link("eth0"), link("eth1", ipv4=[], subnets=[]),
            link("wlan0", kind="wireless", ipv4=[], subnets=[], carrier=True),
        ], management="eth0")
        notes = self._warnings("mirror", {"capture": "eth1", "management": "wlan0"},
                               detected)
        self.assertTrue(any("no address yet" in note for note in notes))

    def test_capturing_on_wifi_is_called_out(self):
        # A Wi-Fi client only receives its own traffic, so it cannot watch a
        # network no matter what the switch is doing.
        notes = self._warnings("mirror", {"capture": "wlan0", "management": "eth0"},
                               two_ports())
        self.assertTrue(any("cannot be used to watch a network" in note for note in notes))

    def test_a_capture_interface_with_no_cable_is_called_out(self):
        detected = hardware([
            link("eth0"), link("eth1", carrier=False, ipv4=[], subnets=[]),
            link("wlan0", kind="wireless", ipv4=["10.10.0.5/16"], subnets=["10.10.0.0/16"]),
        ], management="eth0")
        notes = self._warnings("mirror", {"capture": "eth1", "management": "wlan0"},
                               detected)
        self.assertTrue(any("no link at the moment" in note for note in notes))

    def test_warnings_do_not_block_the_choice(self):
        # Someone rewiring a device on purpose knows more about their desk than
        # the panel does.
        self.detect.return_value = two_ports()
        result = topology.assign("mirror", {"capture": "eth0", "management": "wlan0"})
        self.assertTrue(result["warnings"])
        self.assertTrue(result["saved"])


class StateTest(BackendTestCase):
    def test_nothing_chosen_is_not_the_same_as_this_device_only(self):
        with patch.object(topology.interfaces, "detect", return_value=one_port()):
            current = topology.state()["current"]
        self.assertEqual(current["profile"], "")
        self.assertFalse(current["applied"])

class BlockingClaimTest(BackendTestCase):
    """A layout may claim dropping only if the panel can actually configure it.

    The inline bridge claimed it once and could not: the panel built a Linux
    bridge and pointed af-packet at it, and a kernel bridge forwards the frame
    whatever the engine thinks of it. So the claim was taken away, and later the
    mechanism was built instead. Blocking there means the engine doing the
    forwarding, af-packet copy-mode ips with a paired copy-iface, which the
    Detection mode switch now writes.

    What must not come back is a pill that promises more than the configuration
    does, in either direction.
    """

    def test_a_passive_layout_never_claims_blocking(self):
        for profile in topology.PROFILES:
            if not profile.passive:
                continue
            with self.subTest(profile=profile.id):
                self.assertFalse(
                    profile.can_block,
                    f"{profile.id} is passive; a copy cannot be stopped")

    def test_the_layout_that_claims_it_says_what_it_costs(self):
        # Blocking here trades a link that survives a stopped engine for one
        # that does not. Claiming the first half and hiding the second is the
        # same fault as the old pill, pointing the other way.
        claimed = [p for p in topology.PROFILES if p.can_block]
        self.assertTrue(claimed, "no layout can block any more")
        for profile in claimed:
            with self.subTest(profile=profile.id):
                self.assertFalse(profile.passive, f"{profile.id} blocks but is passive")
                self.assertTrue(profile.blocking_cost,
                                f"{profile.id} claims blocking and says nothing about the cost")
                self.assertRegex(profile.blocking_cost, r"carries nothing|stopped")

    def test_a_layout_that_cannot_block_says_why_if_the_traffic_crosses_it(self):
        for profile in topology.PROFILES:
            if profile.passive or profile.can_block:
                continue
            with self.subTest(profile=profile.id):
                self.assertTrue(profile.blocking_needs,
                                f"{profile.id} is inline and says nothing about blocking")

    def test_the_note_reaches_the_wizard(self):
        by_id = {p["id"]: p for p in topology.state()["profiles"]}
        self.assertTrue(by_id["bridge"]["can_block"])
        self.assertIn("carries nothing", by_id["bridge"]["blocking_cost"])

    def test_the_engine_mode_tells_this_device_what_it_can_do(self):
        """The sentence used to name a mechanism and leave the reader to guess.

        It said blocking needs "an inline bridge or NFQUEUE", which pointed
        straight at the layout that could not block. Now the layout decides
        what it says, so what it has to avoid is describing the other one: where
        the queue is refused (a mirror) it says why; where the queue works it
        promises this device's own traffic and nothing beyond it; inline it
        must not promise that traffic keeps flowing without the engine.
        """
        mode = protection.mode_info()
        if mode["can_block"] or mode["inline"]:
            self.skipTest("this device is inline or already blocking")
        reason = mode["reason"]
        if not mode["blocking_possible"]:
            self.assertEqual(reason, mode["blocking_unavailable"])
        elif not mode["can_switch"]:
            self.assertIn("not installed", reason)
        else:
            # The queue: this device and nothing beyond it.
            self.assertIn("this Pi, and nothing beyond it", reason)
        self.assertNotIn("bridge", reason)
