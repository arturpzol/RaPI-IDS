"""Placing an address: our network, a private one, or a country."""
from __future__ import annotations

from unittest.mock import patch

from app import geoip

from .helpers import BackendTestCase


class HomeNetworkTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.state = self.tmp / "rapi-home-net"
        self.enterContext(patch.object(geoip, "HOME_NET_STATE", self.state))
        geoip.home_networks.cache_clear()
        self.addCleanup(geoip.home_networks.cache_clear)

    def test_reads_the_engine_list(self):
        self.state.write_text("[192.168.1.0/24,10.10.0.0/16]\n")
        self.assertEqual(len(geoip.home_networks()), 2)
        self.assertTrue(geoip.is_home("192.168.1.10"))
        self.assertTrue(geoip.is_home("10.10.5.5"))
        self.assertFalse(geoip.is_home("8.8.8.8"))

    def test_negations_and_rubbish_are_skipped(self):
        self.state.write_text("[192.168.1.0/24,!192.168.1.5,nonsense,]\n")
        self.assertEqual([str(n) for n in geoip.home_networks()], ["192.168.1.0/24"])

    def test_a_routable_home_net_still_counts_as_home(self):
        # HOME_NET here is 198.51.100.0/24, a routable block the geo database
        # happily calls "US". Sort by HOME_NET first or every local alert lands
        # on the map in Kansas.
        self.state.write_text("[198.51.100.0/24]\n")
        self.assertEqual(geoip.classify("198.51.100.7"), "home")

    def test_not_an_address_is_not_home(self):
        self.state.write_text("[192.168.1.0/24]\n")
        self.assertFalse(geoip.is_home("example.net"))

    def test_a_v4_address_is_not_matched_against_a_v6_network(self):
        self.state.write_text("[2001:db8::/32]\n")
        self.assertFalse(geoip.is_home("192.168.1.10"))


class ClassifyTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.enterContext(patch.object(geoip, "HOME_NET_STATE", self.tmp / "none"))
        geoip.home_networks.cache_clear()
        self.addCleanup(geoip.home_networks.cache_clear)

    def test_no_address_is_unknown(self):
        self.assertEqual(geoip.classify(None), "unknown")
        self.assertEqual(geoip.classify(""), "unknown")

    def test_private_address_outside_home_net(self):
        with patch.object(geoip, "country", return_value=None):
            self.assertEqual(geoip.classify("192.168.5.5"), "private")

    def test_a_country_wins_over_the_private_bucket(self):
        with patch.object(geoip, "country", return_value="PL"):
            self.assertEqual(geoip.classify("203.0.113.7"), "PL")

    def test_public_address_with_no_answer_is_unknown(self):
        # Not "private": saying an address is on somebody's LAN when the
        # database simply had no answer for it is a different claim.
        with patch.object(geoip, "country", return_value=None):
            self.assertEqual(geoip.classify("8.8.8.8"), "unknown")

    def test_garbage_is_unknown(self):
        with patch.object(geoip, "country", return_value=None):
            self.assertEqual(geoip.classify("not-an-ip"), "unknown")


class CoordinateTest(BackendTestCase):
    def test_iso6709_parsing(self):
        self.assertEqual(geoip._parse_iso6709("+5215+02100"), (52.25, 21.0))
        self.assertEqual(geoip._parse_iso6709("-3352+15113"), (-33.8667, 151.2167))
        self.assertIsNone(geoip._parse_iso6709("nonsense"))

    def test_medoid_picks_a_listed_city(self):
        # Not the mean: a mean of the United States' zones lands in the Pacific.
        points = [(52.0, 21.0), (52.5, 21.5), (10.0, -160.0)]
        self.assertIn(geoip._medoid(points), points)

    def test_describe_never_invents_a_position(self):
        described = geoip.describe("ZZ")
        self.assertEqual(described["code"], "ZZ")
        self.assertIsNone(described["lat"])
        self.assertIsNone(described["lon"])
