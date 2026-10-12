"""Runtime settings (data/settings.json) and the paths derived from them."""
from __future__ import annotations

import json

from app import config, settings

from .helpers import BackendTestCase


class SettingsTest(BackendTestCase):
    def test_defaults_when_no_file(self):
        self.assertEqual(settings.get("log_dir"), str(config.EVE_PATH.parent))
        self.assertEqual(settings.get("topology")["profile"], "")
        self.assertFalse(settings.get("topology")["applied"])

    def test_set_persists_and_reloads(self):
        settings.set("log_dir", "/mnt/ssd/suricata")
        settings._cache = None  # force a read from disk
        self.assertEqual(settings.get("log_dir"), "/mnt/ssd/suricata")
        stored = json.loads(settings.SETTINGS_PATH.read_text())
        self.assertEqual(stored["log_dir"], "/mnt/ssd/suricata")

    def test_unknown_key_is_refused(self):
        # A typo must not silently create a setting nothing ever reads.
        with self.assertRaises(KeyError):
            settings.set("log-dir", "/mnt/ssd")

    def test_unknown_keys_in_the_file_are_ignored(self):
        settings.SETTINGS_PATH.write_text(json.dumps({"log_dir": "/mnt/a", "junk": 1}))
        settings._cache = None
        self.assertNotIn("junk", settings.all())

    def test_unreadable_file_falls_back_to_defaults(self):
        # Half a written file after a power cut must not stop the panel booting.
        settings.SETTINGS_PATH.write_text("{not json")
        settings._cache = None
        self.assertEqual(settings.get("log_dir"), str(config.EVE_PATH.parent))

    def test_the_file_is_not_readable_by_anyone_else(self):
        # It holds the SMTP password.
        settings.set("log_dir", "/mnt/ssd/suricata")
        self.assertEqual(settings.SETTINGS_PATH.stat().st_mode & 0o777, 0o600)

    def test_an_older_file_is_tightened_at_startup(self):
        settings.SETTINGS_PATH.write_text("{}")
        settings.SETTINGS_PATH.chmod(0o644)
        settings.harden()
        self.assertEqual(settings.SETTINGS_PATH.stat().st_mode & 0o777, 0o600)

    def test_derived_paths_follow_the_directory(self):
        settings.set("log_dir", "/mnt/ssd/suricata")
        self.assertEqual(str(settings.eve_path()), "/mnt/ssd/suricata/eve.json")
        self.assertEqual(
            settings.engine_log_path().name, config.SURICATA_LOG.name,
        )
        self.assertEqual(str(settings.engine_log_path().parent), "/mnt/ssd/suricata")
