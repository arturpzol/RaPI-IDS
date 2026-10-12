"""Where the engine writes its logs, and moving that somewhere else.

Two halves. One is the path being accepted or refused for the right reason -
the engine's systemd unit cannot see home directories or write to /etc, so a
directory the panel accepts has to be one the engine can actually use.

The other is which volumes the panel offers. It used to offer none, on the
reasoning that what is mounted now says nothing about what will be mounted
after a reboot. The objection was right and the answer was wrong: /etc/fstab
knows, so the panel reads it and says which volumes will still be there,
instead of leaving somebody to type a path they have to know by heart.
"""
from __future__ import annotations

import subprocess
import os
import types
from pathlib import Path
from unittest.mock import patch

from app import settings
from app.modules.suricata import logdir

from .helpers import BackendTestCase

YAML_HEAD = "%YAML 1.1\n---\ndefault-log-dir: /var/log/suricata\n"


class ConfigStateTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.yaml = self.tmp / "suricata.yaml"
        self.override = self.tmp / "rapi-overrides.yaml"
        self.enterContext(patch.object(logdir, "SURICATA_YAML", self.yaml))
        self.enterContext(patch.object(logdir, "OVERRIDE_PATH", self.override))
        self.yaml.write_text(YAML_HEAD)

    def test_include_is_detected(self):
        self.assertFalse(logdir.include_wired())
        self.yaml.write_text(YAML_HEAD + f"include: {self.override}\n")
        self.assertTrue(logdir.include_wired())

    def test_a_commented_include_does_not_count(self):
        self.yaml.write_text(YAML_HEAD + f"# include: {self.override}\n")
        self.assertFalse(logdir.include_wired())

    def test_the_override_wins_when_it_is_included(self):
        self.override.write_text("%YAML 1.1\n---\ndefault-log-dir: /mnt/ssd/suricata\n")
        self.assertEqual(str(logdir.engine_dir()), "/var/log/suricata")  # not included yet
        self.yaml.write_text(YAML_HEAD + f"include: {self.override}\n")
        self.assertEqual(str(logdir.engine_dir()), "/mnt/ssd/suricata")

    def test_without_either_the_packaged_default_is_the_answer(self):
        self.yaml.unlink()
        self.assertEqual(logdir.engine_dir(), logdir.config.EVE_PATH.parent)

    def test_status_reports_the_directory_and_its_files(self):
        directory = self.tmp / "logs"
        directory.mkdir()
        (directory / "eve.json").write_text("{}\n")
        (directory / "subdir").mkdir()
        with patch.object(logdir, "engine_dir", return_value=directory):
            status = logdir.status()
        self.assertEqual(status["log_dir"], str(directory))
        self.assertEqual([f["name"] for f in status["files"]], ["eve.json"])
        self.assertGreater(status["disk"]["total"], 0)

    def test_status_no_longer_proposes_destinations(self):
        # Deliberate: a suggestion is read as a recommendation, and the panel
        # has no idea which volume will still be mounted tomorrow.
        with patch.object(logdir, "engine_dir", return_value=self.tmp):
            self.assertNotIn("targets", logdir.status())

    def test_status_warns_when_the_panel_reads_elsewhere(self):
        settings.set("log_dir", "/mnt/ssd/suricata")
        with patch.object(logdir, "engine_dir", return_value=Path("/var/log/suricata")):
            warnings = " ".join(logdir.status()["warnings"])
        self.assertIn("/mnt/ssd/suricata", warnings)

    def test_status_warns_when_the_panel_cannot_change_anything(self):
        with patch.object(logdir, "engine_dir", return_value=self.tmp):
            status = logdir.status()
        self.assertFalse(status["can_change"])
        self.assertIn("setup-suricata-override.sh", " ".join(status["warnings"]))


class PathRulesTest(BackendTestCase):
    def test_forbidden_directories(self):
        for path in ("/home/rapi/logs", "/root", "/etc/suricata", "/usr/share",
                     "/proc", "/var/lib/suricata"):
            with self.subTest(path=path):
                self.assertIsNotNone(logdir.forbidden_reason(Path(path)))

    def test_home_is_refused_with_the_reason_that_applies(self):
        reason = logdir.forbidden_reason(Path("/home/rapi/logs"))
        self.assertIn("ProtectHome", reason)

    def test_a_relative_path_is_refused(self):
        self.assertIsNotNone(logdir.forbidden_reason(Path("logs")))

    def test_normal_places_are_allowed(self):
        for path in ("/mnt/ssd/suricata", "/media/usb/logs", "/var/log/suricata",
                     "/srv/ids"):
            with self.subTest(path=path):
                self.assertIsNone(logdir.forbidden_reason(Path(path)))

    def test_a_prefix_match_is_not_enough(self):
        # /home is refused, /homelab is a perfectly ordinary directory.
        self.assertIsNone(logdir.forbidden_reason(Path("/homelab/logs")))

    def test_the_safe_pattern_rejects_a_trailing_newline(self):
        # fullmatch, not match: '$' also matches just before a final newline, so
        # '/mnt/x\n' used to pass and reach a shell command.
        self.assertIsNone(logdir.SAFE_PATH_RE.fullmatch("/mnt/ssd/suricata\n"))
        self.assertIsNotNone(logdir.SAFE_PATH_RE.fullmatch("/mnt/ssd/suricata"))

    def test_the_safe_pattern_rejects_shell_metacharacters(self):
        for path in ("/mnt/a b", "/mnt/a;rm -rf /", "/mnt/$(id)", "/mnt/a'b"):
            with self.subTest(path=path):
                self.assertIsNone(logdir.SAFE_PATH_RE.fullmatch(path))


class RotationTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.conf_dir = self.tmp / "logrotate.d"
        self.conf_dir.mkdir()
        self.enterContext(patch.object(logdir, "LOGROTATE_DIR", self.conf_dir))

    def test_a_matching_pattern_counts(self):
        (self.conf_dir / "rapi-suricata").write_text(
            "/mnt/ssd/suricata/*.log\n/mnt/ssd/suricata/*.json\n{\n  daily\n}\n"
        )
        self.assertTrue(logdir.rotation_covered(Path("/mnt/ssd/suricata")))

    def test_a_pattern_for_another_directory_does_not(self):
        (self.conf_dir / "suricata").write_text("/var/log/suricata/*.json\n{\n daily\n}\n")
        self.assertFalse(logdir.rotation_covered(Path("/mnt/ssd/suricata")))

    def test_a_star_does_not_cross_a_directory_separator(self):
        (self.conf_dir / "suricata").write_text("/mnt/*.json\n{\n daily\n}\n")
        self.assertFalse(logdir.rotation_covered(Path("/mnt/ssd/suricata")))

    def test_no_entry_at_all_is_a_warning_not_a_crash(self):
        self.assertFalse(logdir.rotation_covered(Path("/mnt/ssd/suricata")))


class SetDirTest(BackendTestCase):
    def setUp(self):
        super().setUp()
        self.yaml = self.tmp / "suricata.yaml"
        self.override = self.tmp / "rapi-overrides.yaml"
        self.override.write_text("%YAML 1.1\n---\n")
        self.yaml.write_text(YAML_HEAD + f"include: {self.override}\n")
        self.enterContext(patch.object(logdir, "SURICATA_YAML", self.yaml))
        self.enterContext(patch.object(logdir, "OVERRIDE_PATH", self.override))
        # The real one runs as root through sudo. The stand-in does the part
        # that matters to the rest of set_dir: the directory exists afterwards.
        def prepare(directory):
            directory.mkdir(parents=True, exist_ok=True)
            return True, f"created {directory}"

        self.prepare = self.enterContext(
            patch.object(logdir, "prepare_dir", side_effect=prepare))
        self.enterContext(patch("app.modules.suricata.tailer.restart_tailer"))
        self.run_mock = self.enterContext(patch.object(logdir.subprocess, "run"))
        self.run_mock.return_value.returncode = 0
        self.run_mock.return_value.stdout = ""
        self.run_mock.return_value.stderr = ""
        self.target = self.tmp / "newlogs"

    def test_a_restart_that_never_finishes_is_reported_not_raised(self):
        # Loading 68,000 rules on a Pi takes as long as it takes. The timeout
        # used to escape as a 500 with a traceback, after the override was
        # already written: the engine goes to the new directory, the reader is
        # never moved, and nothing reaches the screen until somebody restarts
        # the panel.
        self.run_mock.side_effect = subprocess.TimeoutExpired(cmd="systemctl", timeout=180)
        result = logdir.set_dir(str(self.target))
        self.assertFalse(result["restarted"])
        self.assertIn("180", result["output"])
        # The half that did happen still happened, and the reader went with it.
        self.assertEqual(settings.get("log_dir"), str(self.target))
        self.assertIn(f"default-log-dir: {self.target}", self.override.read_text())

    def test_it_waits_as_long_as_the_other_restart_paths_do(self):
        # Two minutes was this module's own number. Every other path that
        # restarts the engine waits three, and this one loads the same rules.
        logdir.set_dir(str(self.target))
        self.assertEqual(self.run_mock.call_args.kwargs["timeout"], 180)

    def test_writes_the_override_restarts_and_moves_the_reader(self):
        result = logdir.set_dir(str(self.target))
        self.assertTrue(result["ok"])
        self.assertIn(f"default-log-dir: {self.target}", self.override.read_text())
        self.assertTrue(self.override.read_text().startswith("%YAML 1.1"))
        self.assertEqual(settings.get("log_dir"), str(self.target))
        self.assertEqual(str(settings.eve_path()), str(self.target / "eve.json"))
        self.assertEqual(self.run_mock.call_args[0][0][-3:],
                         ["systemctl", "restart", "suricata"])

    def test_the_root_helper_makes_the_directory(self):
        """The panel does not create it, and must not try.

        A disk mounted at /mnt/ssd belongs to root, so the panel's own mkdir
        fails inside it - which is how a button meant to save somebody a shell
        ended up printing `sudo mkdir -p ...` for them to paste into one.
        """
        deeper = self.target / "deeper"
        logdir.set_dir(str(deeper))
        self.prepare.assert_called_once_with(deeper)
        self.assertTrue(deeper.is_dir())

    def test_nothing_is_written_when_the_directory_cannot_be_prepared(self):
        # Half a move is worse than none: the override would point the engine at
        # a directory that is not there, and the engine would refuse to start.
        self.prepare.side_effect = None
        self.prepare.return_value = (False, "no such directory: /mnt/nope")
        with self.assertRaises(ValueError) as raised:
            logdir.set_dir(str(self.target))
        self.assertIn("no such directory", str(raised.exception))
        self.assertNotIn("default-log-dir", self.override.read_text())
        self.run_mock.assert_not_called()

    def test_the_helper_runs_before_the_override_is_written(self):
        # Same reason: the directory has to exist before anything points at it.
        seen = {}
        self.prepare.side_effect = lambda d: (
            seen.setdefault("override", self.override.read_text()),
            d.mkdir(parents=True, exist_ok=True),
            (True, ""),
        )[-1]
        logdir.set_dir(str(self.target))
        self.assertNotIn("default-log-dir", seen["override"])

    def test_a_failed_restart_is_reported(self):
        self.run_mock.return_value.returncode = 1
        self.run_mock.return_value.stderr = "Job failed"
        result = logdir.set_dir(str(self.target))
        self.assertFalse(result["ok"])
        self.assertIn("Job failed", result["output"])

    def test_a_forbidden_directory_is_refused_before_anything_happens(self):
        with self.assertRaises(ValueError):
            logdir.set_dir("/home/rapi/logs")
        self.run_mock.assert_not_called()
        self.assertNotIn("default-log-dir", self.override.read_text())

    def test_a_path_with_metacharacters_is_refused(self):
        with self.assertRaises(ValueError):
            logdir.set_dir("/mnt/ssd/$(id)")
        self.run_mock.assert_not_called()

    def test_a_file_where_a_directory_should_be_is_refused(self):
        blocker = self.tmp / "afile"
        blocker.write_text("")
        # The real helper answers this one itself (exit 5); the stand-in has to
        # be told, or mkdir(exist_ok=True) would happily pretend it worked.
        self.prepare.side_effect = None
        self.prepare.return_value = (False, f"exists and is not a directory: {blocker}")
        with self.assertRaises(ValueError):
            logdir.set_dir(str(blocker))

    def test_without_the_include_the_panel_says_so(self):
        self.yaml.write_text(YAML_HEAD)
        with self.assertRaises(ValueError) as raised:
            logdir.set_dir(str(self.target))
        self.assertIn("setup-suricata-override.sh", str(raised.exception))

    def test_an_unwritable_override_is_refused(self):
        self.override.chmod(0o444)
        self.addCleanup(self.override.chmod, 0o644)
        if os.access(self.override, os.W_OK):
            self.skipTest("running as root - file permissions do not apply")
        with self.assertRaises(ValueError):
            logdir.set_dir(str(self.target))

    def test_the_panel_never_tells_anyone_to_open_a_shell(self):
        """What this used to do, and must not do again.

        On root-owned media the panel's own mkdir failed, and the error handed
        over `sudo mkdir -p ... && sudo chown ...` to paste into a terminal. On
        a device whose whole promise is that there is no terminal, that is not
        an error message, it is the feature failing. The helper creates the
        directory now, and a failure says what went wrong without homework.
        """
        self.prepare.side_effect = None
        self.prepare.return_value = (False, "no such directory: /mnt/root-owned")
        with self.assertRaises(ValueError) as raised:
            logdir.set_dir("/mnt/root-owned/suricata")
        message = str(raised.exception)
        self.assertNotIn("sudo", message)
        self.assertNotIn("chown", message)
        self.assertIn("no such directory", message)


class VolumeDetectionTest(BackendTestCase):
    """Which volumes the panel offers, and which it keeps quiet about.

    The screen used to be a path field and nothing else, so this is the part
    that replaced somebody typing `/mnt/ssd/suricata` from memory.
    """

    def setUp(self):
        super().setUp()
        self.fstab = self.tmp / "fstab"
        self.fstab.write_text(
            "# a comment\n"
            "proc            /proc   proc  defaults 0 0\n"
            "UUID=1234       /mnt/ssd ext4 defaults,nofail 0 2\n"
            "malformed-line\n"
        )
        self.enterContext(patch.object(logdir, "FSTAB", self.fstab))

    def _mounts(self, *specs):
        """Fake psutil partitions over real directories, with fake device ids."""
        parts, devices = [], {"/": 1}
        for mount, fstype, opts, dev in specs:
            path = self.tmp / mount.strip("/").replace("/", "-")
            path.mkdir(parents=True, exist_ok=True)
            parts.append(types.SimpleNamespace(
                device=f"/dev/{mount.strip('/').replace('/', '-') or 'root'}",
                mountpoint=mount, fstype=fstype, opts=opts,
            ))
            devices[mount] = dev
        real_stat = os.stat

        def fake_stat(path, *args, **kwargs):
            key = str(path).rstrip("/") or "/"
            if key in devices:
                return types.SimpleNamespace(st_dev=devices[key])
            return real_stat(path, *args, **kwargs)

        self.enterContext(patch.object(logdir.psutil, "disk_partitions",
                                       return_value=parts))
        self.enterContext(patch.object(logdir.os, "stat", side_effect=fake_stat))

    def test_fstab_is_read_for_mount_points_only(self):
        self.assertEqual(logdir._fstab_mounts(), {"/proc", "/mnt/ssd"})

    def test_an_unreadable_fstab_is_not_a_crash(self):
        with patch.object(logdir, "FSTAB", self.tmp / "nope"):
            self.assertEqual(logdir._fstab_mounts(), set())

    def test_the_boot_volume_is_never_offered(self):
        # It is the thing being moved away from, so offering it is nonsense.
        self._mounts(("/", "ext4", "rw", 1), ("/mnt/ssd", "ext4", "rw", 2))
        self.assertEqual([c["mount"] for c in logdir.candidates()], ["/mnt/ssd"])

    def test_the_firmware_partition_is_never_offered(self):
        # The one that actually turns up on a Pi: a small VFAT partition the
        # bootloader reads, which would fill in a day and take the boot with it.
        self._mounts(("/boot/firmware", "vfat", "rw", 3),
                     ("/mnt/ssd", "ext4", "rw", 2))
        self.assertEqual([c["mount"] for c in logdir.candidates()], ["/mnt/ssd"])

    def test_read_only_and_volatile_volumes_are_skipped(self):
        self._mounts(("/mnt/ro", "ext4", "ro,noatime", 4),
                     ("/mnt/ram", "tmpfs", "rw", 5),
                     ("/mnt/ssd", "ext4", "rw", 2))
        self.assertEqual([c["mount"] for c in logdir.candidates()], ["/mnt/ssd"])

    def test_a_volume_missing_from_fstab_is_offered_but_flagged(self):
        """Offered, not hidden, and the risk named.

        After a reboot the mount point is an ordinary directory on the card
        again and the engine keeps writing to it without a word - which is the
        failure this flag exists to put on screen.
        """
        self._mounts(("/mnt/usb", "ext4", "rw", 6), ("/mnt/ssd", "ext4", "rw", 2))
        by_mount = {c["mount"]: c for c in logdir.candidates()}
        self.assertTrue(by_mount["/mnt/ssd"]["persistent"])
        self.assertFalse(by_mount["/mnt/usb"]["persistent"])

    def test_volumes_in_fstab_come_first(self):
        self._mounts(("/mnt/usb", "ext4", "rw", 6), ("/mnt/ssd", "ext4", "rw", 2))
        self.assertEqual(logdir.candidates()[0]["mount"], "/mnt/ssd")

    def test_the_suggested_directory_sits_under_the_volume(self):
        # Not at the root of it: a mount point usually has lost+found and
        # whatever the disk held before, and eve.json among that is hard to find.
        self._mounts(("/mnt/ssd", "ext4", "rw", 2))
        self.assertEqual(logdir.candidates()[0]["path"], "/mnt/ssd/suricata")

    def test_already_here_means_the_volume_not_the_directory(self):
        # The logs can live in a directory with any name on that volume.
        # Whether the directory is called suricata or suricata3 is nobody's
        # business; whether the writes are off the card is the question.
        self._mounts(("/mnt/ssd", "ext4", "rw", 2))
        with patch.object(logdir, "engine_dir", return_value=Path("/mnt/ssd/suricata3")):
            self.assertTrue(logdir.candidates()[0]["current"])

    def test_on_root_filesystem_answers_the_question_the_screen_asks(self):
        self._mounts(("/mnt/ssd", "ext4", "rw", 2))
        self.assertTrue(logdir.on_root_filesystem(Path("/")))
        self.assertFalse(logdir.on_root_filesystem(Path("/mnt/ssd")))
