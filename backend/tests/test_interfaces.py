"""Reading the network hardware out of /sys, with a fake /sys.

The image goes to other people's boards: one port, two ports, none at all, a
USB adapter, a radio switched off in software. None of that can be arranged on
the machine running the tests, so the tests build the /sys tree the kernel
would have produced and let the detector read it.
"""
from __future__ import annotations

import socket
from unittest.mock import patch

from app.modules.network import interfaces

from .helpers import BackendTestCase, if_addr, if_stats, write_sysfs


class DetectTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.sysfs = self.tmp / "class-net"
        self.sysfs.mkdir()
        self.enterContext(patch.object(interfaces, "SYS_NET", self.sysfs))
        self.enterContext(patch.object(interfaces, "RFKILL", self.tmp / "rfkill"))
        # The default route is a real file on the machine running the tests.
        self.enterContext(patch.object(interfaces, "default_route_interface",
                                       return_value="eth0"))

    def _pi5(self):
        """A Pi 5 as it comes: one wired port, one radio, plus the loopback."""
        write_sysfs(self.sysfs, "eth0")
        write_sysfs(self.sysfs, "wlan0", kind="wireless", carrier=False, speed=None,
                    mac="de:ad:be:ef:00:02")
        write_sysfs(self.sysfs, "lo", kind="loopback")
        # Read through a lambda, so a test can plug an adapter in after setup.
        self.addrs = {
            "eth0": [if_addr("192.168.1.10")],
            "wlan0": [],
            "lo": [if_addr("127.0.0.1", "255.0.0.0")],
        }
        self.stats = {"eth0": if_stats(), "wlan0": if_stats(isup=False, speed=0),
                      "lo": if_stats()}
        self.enterContext(patch.object(interfaces.psutil, "net_if_addrs",
                                       side_effect=lambda: self.addrs))
        self.enterContext(patch.object(interfaces.psutil, "net_if_stats",
                                       side_effect=lambda: self.stats))

    def test_loopback_is_not_an_interface_anyone_can_choose(self):
        self._pi5()
        names = [link["name"] for link in interfaces.detect()["links"]]
        self.assertEqual(names, ["eth0", "wlan0"])

    def test_counts_are_what_the_layouts_are_checked_against(self):
        self._pi5()
        self.assertEqual(interfaces.detect()["counts"],
                         {"usable": 2, "wired": 1, "wireless": 1})

    def test_addresses_and_subnets(self):
        self._pi5()
        eth0 = interfaces.detect()["links"][0]
        self.assertEqual(eth0["ipv4"], ["192.168.1.10/24"])
        self.assertEqual(eth0["subnets"], ["192.168.1.0/24"])

    def test_carrier_is_the_honest_answer_about_the_cable(self):
        # An interface can be administratively up with nothing plugged in.
        self._pi5()
        links = {link["name"]: link for link in interfaces.detect()["links"]}
        self.assertTrue(links["eth0"]["carrier"])
        self.assertFalse(links["wlan0"]["carrier"])

    def test_a_made_up_interface_is_not_offered_for_capture(self):
        # veth, tun, docker0: no device directory, so nothing to capture from.
        self._pi5()
        (self.sysfs / "veth0").mkdir()
        (self.sysfs / "veth0" / "type").write_text("1\n")
        (self.sysfs / "veth0" / "address").write_text("aa:bb:cc:dd:ee:ff\n")
        self.addrs["veth0"] = []
        self.stats["veth0"] = if_stats()
        links = {link["name"]: link for link in interfaces.detect()["links"]}
        self.assertEqual(links["veth0"]["kind"], "virtual")
        self.assertEqual(interfaces.detect()["counts"]["usable"], 2)

    def test_an_interface_with_no_device_has_no_driver(self):
        # Path.resolve() is not strict: on a missing symlink it hands the path
        # back unchanged, so every veth, tun, docker bridge and the panel's own
        # br-rapi was listed in the wizard as having a driver called "driver".
        # Confirmed on the device before the fix: lo answered 'driver'.
        self._pi5()
        (self.sysfs / "veth0").mkdir()
        (self.sysfs / "veth0" / "type").write_text("1\n")
        (self.sysfs / "veth0" / "address").write_text("aa:bb:cc:dd:ee:ff\n")
        self.addrs["veth0"] = []
        self.stats["veth0"] = if_stats()
        links = {link["name"]: link for link in interfaces.detect()["links"]}
        self.assertEqual(links["veth0"]["driver"], "")
        # And a real one still reports its module.
        self.assertEqual(links["eth0"]["driver"], "bcmgenet")

    def test_a_usb_adapter_is_marked_as_one(self):
        self._pi5()
        write_sysfs(self.sysfs, "eth1", usb=True, mac="de:ad:be:ef:00:03")
        self.addrs["eth1"] = []
        self.stats["eth1"] = if_stats(speed=100)
        links = {link["name"]: link for link in interfaces.detect()["links"]}
        self.assertTrue(links["eth1"]["usb"])
        self.assertEqual(links["eth1"]["driver"], "cdc_ether")
        self.assertFalse(links["eth0"]["usb"])

    def test_an_unknown_speed_is_none_not_a_negative_number(self):
        self._pi5()
        (self.sysfs / "eth0" / "speed").write_text("-1\n")
        self.assertIsNone(interfaces.detect()["links"][0]["speed_mbps"])

    def test_a_soft_blocked_radio_is_flagged(self):
        # The quiet failure: the interface exists, the driver is loaded, and
        # nothing will ever associate.
        self._pi5()
        rfkill = self.tmp / "rfkill" / "rfkill0"
        rfkill.mkdir(parents=True)
        (rfkill / "type").write_text("wlan\n")
        (rfkill / "soft").write_text("1\n")
        (rfkill / "hard").write_text("0\n")
        detected = interfaces.detect()
        self.assertTrue(detected["wireless_blocked"])
        self.assertTrue([l for l in detected["links"] if l["name"] == "wlan0"][0]["blocked"])

    def test_a_bluetooth_block_says_nothing_about_wifi(self):
        self._pi5()
        rfkill = self.tmp / "rfkill" / "rfkill1"
        rfkill.mkdir(parents=True)
        (rfkill / "type").write_text("bluetooth\n")
        (rfkill / "soft").write_text("1\n")
        self.assertFalse(interfaces.detect()["wireless_blocked"])

    def test_a_board_with_no_ethernet_at_all(self):
        write_sysfs(self.sysfs, "wlan0", kind="wireless")
        self.enterContext(patch.object(interfaces.psutil, "net_if_addrs",
                                       return_value={"wlan0": [if_addr("192.168.1.20")]}))
        self.enterContext(patch.object(interfaces.psutil, "net_if_stats",
                                       return_value={"wlan0": if_stats()}))
        self.assertEqual(interfaces.detect()["counts"], {"usable": 1, "wired": 0, "wireless": 1})


class ManagementOnOneSubnetTest(BackendTestCase):
    """The whole path, from the address that was dialled to is_management.

    This is the shape the wizard actually meets on this desk: the LAN port and
    the radio on one network, the operator browsing over Wi-Fi so that the LAN
    port can be handed to a mirror.
    """

    def setUp(self):
        super().setUp()
        self.sysfs = self.tmp / "class-net"
        self.sysfs.mkdir()
        self.enterContext(patch.object(interfaces, "SYS_NET", self.sysfs))
        self.enterContext(patch.object(interfaces, "RFKILL", self.tmp / "rfkill"))
        self.enterContext(patch.object(interfaces, "default_route_interface",
                                       return_value="eth0"))
        write_sysfs(self.sysfs, "eth0")
        write_sysfs(self.sysfs, "wlan0", kind="wireless", mac="de:ad:be:ef:00:02")
        addrs = {
            "eth0": [if_addr("198.51.100.189")],
            "wlan0": [if_addr("198.51.100.190")],
        }
        stats = {"eth0": if_stats(), "wlan0": if_stats()}
        self.enterContext(patch.object(interfaces.psutil, "net_if_addrs", return_value=addrs))
        self.enterContext(patch.object(interfaces.psutil, "net_if_stats", return_value=stats))

    def management(self, local_ip):
        return interfaces.detect("198.51.100.50", local_ip)["management"]

    def test_the_session_is_traced_to_the_interface_that_answered_it(self):
        self.assertEqual(self.management("198.51.100.190"), "wlan0")
        self.assertEqual(self.management("198.51.100.189"), "eth0")

    def test_without_the_dialled_address_the_answer_is_a_guess(self):
        # What the panel had before: the subnet matches both interfaces, so this
        # is whichever comes first. Kept as a test to record that it is a guess,
        # not an answer - the guard must not be the only thing standing between
        # a wrong guess and a device that goes silent.
        self.assertIn(self.management(None), {"eth0", "wlan0"})


class ManagementInterfaceTest(BackendTestCase):
    """Which interface the person configuring the panel is talking through.

    The one piece of detection that exists to stop someone cutting the branch
    they are sitting on.
    """

    def setUp(self):
        super().setUp()
        self.links = [
            {"name": "eth0", "ipv4": ["192.168.1.10/24"], "subnets": ["192.168.1.0/24"]},
            {"name": "wlan0", "ipv4": ["10.10.0.5/16"], "subnets": ["10.10.0.0/16"]},
        ]

    def test_matched_by_the_subnet_the_client_is_on(self):
        self.assertEqual(interfaces._management_interface("192.168.1.55", self.links), "eth0")
        self.assertEqual(interfaces._management_interface("10.10.4.4", self.links), "wlan0")

    def test_no_match_falls_back_to_the_default_route(self):
        # Reached through a router or a VPN: no subnet matches, and the default
        # route is the best guess available.
        with patch.object(interfaces, "default_route_interface", return_value="eth0"):
            self.assertEqual(interfaces._management_interface("172.16.9.9", self.links), "eth0")
            self.assertEqual(interfaces._management_interface(None, self.links), "eth0")

    def test_the_address_the_browser_dialled_wins(self):
        """Two interfaces in one subnet is the normal case, not an exotic one.

        A Pi whose LAN port and Wi-Fi both sit in 198.51.100.0/24 - which is what
        you get the moment the wireless link becomes the management path on an
        ordinary home network - matches the client address on both. The panel
        used to take the first of them and then refuse to hand the LAN port to
        capture, insisting the browser was on it, from a browser that was on
        Wi-Fi. The address that was dialled belongs to exactly one interface.
        """
        links = [
            {"name": "eth0", "ipv4": ["198.51.100.189/24"], "subnets": ["198.51.100.0/24"]},
            {"name": "wlan0", "ipv4": ["198.51.100.190/24"], "subnets": ["198.51.100.0/24"]},
        ]
        self.assertEqual(
            interfaces._management_interface("198.51.100.50", links, "198.51.100.190"), "wlan0")
        self.assertEqual(
            interfaces._management_interface("198.51.100.50", links, "198.51.100.189"), "eth0")

    def test_an_address_that_belongs_to_no_interface_falls_through(self):
        # Port forwarded from somewhere else: the dialled address is not one of
        # ours, so the subnet the client is on is the next best thing.
        self.assertEqual(
            interfaces._management_interface("10.10.4.4", self.links, "203.0.113.9"), "wlan0")

    def test_a_nonsense_client_address_does_not_raise(self):
        with patch.object(interfaces, "default_route_interface", return_value="eth0"):
            self.assertEqual(interfaces._management_interface("::garbage", self.links), "eth0")


class AddressParsingTest(BackendTestCase):
    def test_link_local_addresses_are_left_out(self):
        # Every interface has one and it says nothing about where it is plugged.
        addrs = {"eth0": [
            if_addr("169.254.3.4", "255.255.0.0"),
            if_addr("fe80::1", None, socket.AF_INET6),
            if_addr("2001:db8::1", None, socket.AF_INET6),
        ]}
        ipv4, ipv6, subnets = interfaces._addresses("eth0", addrs)
        self.assertEqual(subnets, [])          # 169.254/16 is link local
        self.assertEqual(ipv6, ["2001:db8::1"])

    def test_an_unparseable_netmask_keeps_the_address(self):
        ipv4, _, subnets = interfaces._addresses("eth0", {"eth0": [if_addr("10.0.0.1", "nonsense")]})
        self.assertEqual(ipv4, ["10.0.0.1"])
        self.assertEqual(subnets, [])


class DefaultRouteTest(BackendTestCase):
    def test_reads_the_route_table_of_this_machine(self):
        # Nothing to assert about the name, only that it does not raise and
        # answers with something an interface could be called.
        name = interfaces.default_route_interface()
        self.assertIsInstance(name, str)
