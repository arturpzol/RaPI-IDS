"""Country lookup for alert addresses, offline and without extra dependencies.

Data comes from the Debian package `geoip-database` (take the trixie-backports
build - the one in main is frozen on a 2019 snapshot and misses most of what has
been reallocated since). Two files, country resolution only:

    /usr/share/GeoIP/GeoIP.dat     IPv4
    /usr/share/GeoIP/GeoIPv6.dat   IPv6

The format is MaxMind's legacy one and the reader below is the whole of it: a
binary trie walked one bit of the address at a time. Written out here rather
than pulled in through python3-geoip, because that is a C binding for forty
lines of arithmetic and a lookup costs microseconds either way.

City resolution is not on offer. Nothing in Debian ships a free city database -
geoipupdate sits in contrib and wants a MaxMind account key - so a marker lands
on the country's principal city, and the panel must not claim more than that.

Includes GeoLite data created by MaxMind, available from http://maxmind.com/.
"""
from __future__ import annotations

import functools
import ipaddress
import json
import logging
import math
import mmap
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

GEOIP_V4 = Path("/usr/share/GeoIP/GeoIP.dat")
GEOIP_V6 = Path("/usr/share/GeoIP/GeoIPv6.dat")

ZONE_TAB = Path("/usr/share/zoneinfo/zone.tab")
ISO_3166 = Path("/usr/share/iso-codes/json/iso_3166-1.json")

# Where scripts/setup-suricata-override.sh remembers the value it put in
# suricata.yaml. Reading the file is cheap; --dump-config is the fallback.
HOME_NET_STATE = Path("/etc/suricata/rapi-home-net")

# Leaf marker of the legacy trie: a record at or above this is a country index,
# anything below it is the offset of the next node.
COUNTRY_BEGIN = 16776960

# Index -> ISO 3166-1 alpha-2, in libGeoIP's order. The order is part of the
# file format: the database stores the index, not the code, so a row inserted in
# the wrong place would silently relabel every country after it. Verified
# against an unrelated database (tor-geoipdb, built from IPFire Location) over
# 20k random addresses: 96.6% agreement, with the remainder being genuine
# vendor disagreement on cloud ranges, and no index the table could not name.
COUNTRY_CODES = (
    "--", "AP", "EU", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "CW", "AO", "AQ",
    "AR", "AS", "AT", "AU", "AW", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH",
    "BI", "BJ", "BM", "BN", "BO", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA",
    "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU",
    "CV", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG",
    "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "SX", "GA", "GB",
    "GD", "GE", "GF", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT",
    "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IN",
    "IO", "IQ", "IR", "IS", "IT", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM",
    "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS",
    "LT", "LU", "LV", "LY", "MA", "MC", "MD", "MG", "MH", "MK", "ML", "MM", "MN",
    "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA",
    "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY",
    "QA", "RE", "RO", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI",
    "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "ST", "SV", "SY", "SZ", "TC", "TD",
    "TF", "TG", "TH", "TJ", "TK", "TM", "TN", "TO", "TL", "TR", "TT", "TV", "TW",
    "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI", "VN",
    "VU", "WF", "WS", "YE", "YT", "RS", "ZA", "ZM", "ME", "ZW", "A1", "A2", "O1",
    "AX", "GG", "IM", "JE", "BL", "MF", "BQ", "SS", "O1",
)

# Registry codes that are not places: anonymous proxies, satellite links, the
# continent-wide buckets. Counted, but never drawn on a map.
NON_GEOGRAPHIC = frozenset({"--", "A1", "A2", "O1", "AP", "EU"})

# ISO has no entry for these, so they need names of their own or the UI shows a
# bare two-letter code where every other row shows a country.
SPECIAL_NAMES = {
    "A1": "Anonymous proxy",
    "A2": "Satellite provider",
    "O1": "Other",
    "AP": "Asia/Pacific",
    "EU": "Europe",
}


class _LegacyDatabase:
    """One .dat file, mmapped.

    mmap and not read(): together the two files are 13 MB, and the panel would
    be carrying all of it resident to answer a handful of lookups a minute. This
    way the kernel keeps only the pages actually walked.
    """

    def __init__(self, path: Path, bits: int) -> None:
        self._file = path.open("rb")
        self._map = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        self._bits = bits
        self._record_length = 3

    def lookup(self, address: int) -> str | None:
        node = 0
        record = self._record_length
        for depth in range(self._bits - 1, -1, -1):
            offset = node * 2 * record
            if (address >> depth) & 1:
                offset += record
            value = int.from_bytes(self._map[offset:offset + record], "little")
            if value >= COUNTRY_BEGIN:
                index = value - COUNTRY_BEGIN
                if 0 <= index < len(COUNTRY_CODES):
                    return COUNTRY_CODES[index]
                # A record we cannot name means the file is not the format we
                # think it is - better to report nothing than a wrong country.
                log.warning("GeoIP: country index %s out of range", index)
                return None
            node = value
        return None


_databases: dict[int, _LegacyDatabase | None] = {}


def _database(version: int) -> _LegacyDatabase | None:
    """Open on first use and remember the result, failure included."""
    if version in _databases:
        return _databases[version]
    path = GEOIP_V6 if version == 6 else GEOIP_V4
    try:
        _databases[version] = _LegacyDatabase(path, 128 if version == 6 else 32)
    except OSError as err:
        log.warning("GeoIP: %s unavailable (%s). No geolocation", path, err)
        _databases[version] = None
    return _databases[version]


def available() -> bool:
    return _database(4) is not None


@functools.lru_cache(maxsize=8192)
def country(ip: str) -> str | None:
    """ISO 3166-1 alpha-2 for an address, or None when it has no country.

    None covers both halves of "we do not know": addresses with no public
    location at all (private, loopback, multicast) and public ones the database
    has no entry for.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not address.is_global:
        return None
    database = _database(address.version)
    if database is None:
        return None
    code = database.lookup(int(address))
    return None if code in (None, "--") else code


# --- country metadata ---


def _parse_iso6709(value: str) -> tuple[float, float] | None:
    """"+5215+02100" -> (52.25, 21.0). Degrees and minutes, seconds optional."""
    match = re.fullmatch(
        r"([+-])(\d{2})(\d{2})(\d{2})?([+-])(\d{3})(\d{2})(\d{2})?", value
    )
    if not match:
        return None
    lat_sign, lat_d, lat_m, lat_s, lon_sign, lon_d, lon_m, lon_s = match.groups()
    lat = int(lat_d) + int(lat_m) / 60 + int(lat_s or 0) / 3600
    lon = int(lon_d) + int(lon_m) / 60 + int(lon_s or 0) / 3600
    return (
        round(-lat if lat_sign == "-" else lat, 4),
        round(-lon if lon_sign == "-" else lon, 4),
    )


# Above this many zones, zone.tab is ordering a country geographically rather
# than by importance, and its first line stops being a sensible marker. It picks
# out exactly nine countries - AQ, AR, AU, BR, CA, KZ, MX, RU, US - and every
# one of them is a country wide enough for the distinction to matter.
MANY_ZONES = 5


def _medoid(points: list[tuple[float, float]]) -> tuple[float, float]:
    """The listed city closest to all the others.

    Not the mean: a mean of the United States' zones is dragged into the Pacific
    by Alaska and Hawaii, and Brazil's out to sea by Fernando de Noronha. The
    medoid is a real city from the list, so an outlier can pull the answer at
    most as far as the nearest other entry.
    """
    def spread(candidate: tuple[float, float]) -> float:
        total = 0.0
        for other in points:
            dy = candidate[0] - other[0]
            # Longitude degrees get narrower towards the poles.
            dx = (candidate[1] - other[1]) * math.cos(
                math.radians((candidate[0] + other[0]) / 2)
            )
            total += dy * dy + dx * dx
        return total

    return min(points, key=spread)


@functools.lru_cache(maxsize=1)
def _coordinates() -> dict[str, tuple[float, float]]:
    """Country -> a point to put the marker on, from tzdata's zone.tab.

    zone.tab exists to list time zones, and its coordinates are those of each
    zone's principal city. That is the closest thing to a country position
    Debian ships, and it is honest about what it is: the marker says "an alert
    came from this country", not "from this spot".

    Which of a country's zones to use is the whole difficulty. Taking the first
    line works for most of the world, and is badly wrong for the big ones: it
    puts Canada on Newfoundland, Australia on Lord Howe Island, Brazil on an
    Atlantic island and Russia in Kaliningrad. Past MANY_ZONES entries the list
    is geographic, so the medoid is used instead.
    """
    zones: dict[str, list[tuple[float, float]]] = {}
    try:
        text = ZONE_TAB.read_text(encoding="utf-8")
    except OSError as err:
        log.warning("GeoIP: %s unreadable (%s). No map coordinates", ZONE_TAB, err)
        return {}
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        point = _parse_iso6709(fields[1])
        if point:
            zones.setdefault(fields[0], []).append(point)

    return {
        code: (_medoid(points) if len(points) >= MANY_ZONES else points[0])
        for code, points in zones.items()
    }


@functools.lru_cache(maxsize=1)
def _names() -> dict[str, str]:
    """Country -> English name, from the iso-codes package."""
    try:
        data = json.loads(ISO_3166.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        log.warning("GeoIP: %s unreadable (%s). Falling back to codes", ISO_3166, err)
        return {}
    return {
        entry["alpha_2"]: entry.get("common_name") or entry["name"]
        for entry in data.get("3166-1", [])
        if entry.get("alpha_2")
    }


def describe(code: str) -> dict[str, Any]:
    """Everything the frontend needs about one country code.

    lat/lon come back None for anything the map cannot honestly place: the
    registry's non-geographic buckets, and the few territories tzdata has no
    line for. The frontend lists those, it does not plot them.
    """
    point = None if code in NON_GEOGRAPHIC else _coordinates().get(code)
    return {
        "code": code,
        "name": SPECIAL_NAMES.get(code) or _names().get(code, code),
        "lat": point[0] if point else None,
        "lon": point[1] if point else None,
    }


def database_info() -> dict[str, Any]:
    """Which file answered, and how old it is.

    The date is the mtime of the .dat, which dpkg preserves, so it is the day
    MaxMind built the data rather than the day it was installed.

    Kept in the API but no longer shown on the map. A geo database does go stale
    quietly - the answers drift as ranges get reallocated - but the date on
    screen read as a fault the operator should act on, and there is no action:
    Debian publishes this data every few months and `apt upgrade` is the whole
    of it. Country allocations move slowly enough that months change no answer
    here. This stays for whoever is diagnosing one wrong country.
    """
    try:
        stat = GEOIP_V4.stat()
    except OSError:
        return {"available": False, "path": str(GEOIP_V4), "updated": None}
    return {
        "available": True,
        "path": str(GEOIP_V4),
        "updated": datetime.fromtimestamp(stat.st_mtime, timezone.utc)
        .date()
        .isoformat(),
    }


# --- our own networks ---


def _parse_networks(value: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    for part in value.strip().strip("[]").split(","):
        part = part.strip()
        if not part or part.startswith("!"):
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return networks


@functools.lru_cache(maxsize=1)
def home_networks() -> tuple[Any, ...]:
    """HOME_NET as the engine sees it.

    This has to come from the engine's own configuration, not from a guess at
    which ranges look local. HOME_NET here is 198.51.100.0/24, a routable block,
    and the geo database duly answers "US" for every host on the LAN. Sort by
    HOME_NET first and the map stays truthful; sort by RFC1918 and every local
    alert lands in Kansas.
    """
    try:
        value = HOME_NET_STATE.read_text(encoding="utf-8")
    except OSError:
        value = ""
    if not value.strip():
        try:
            dump = subprocess.run(
                ["suricata", "--dump-config"],
                capture_output=True, text=True, timeout=30,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            dump = ""
        for line in dump.splitlines():
            if line.startswith("vars.address-groups.HOME_NET"):
                value = line.split("=", 1)[1]
                break
    return tuple(_parse_networks(value))


def is_home(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(
        address.version == net.version and address in net for net in home_networks()
    )


def classify(ip: str | None) -> str:
    """Bucket an address for the map: our network, a private one, or a country.

    Returns "home", "private" or the alpha-2 code; "unknown" when the database
    has nothing. Order matters - see home_networks().
    """
    if not ip:
        return "unknown"
    if is_home(ip):
        return "home"
    code = country(ip)
    if code:
        return code
    try:
        if not ipaddress.ip_address(ip).is_global:
            return "private"
    except ValueError:
        return "unknown"
    return "unknown"
