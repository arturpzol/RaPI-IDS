"""The appliance image recipe.

None of this can be checked by building an image in a test - that needs a
network and several minutes - so what is checked here is the part that goes
wrong silently: a package list that quietly grows, a partition id that stops
matching the one in cmdline.txt (an unbootable card, and nothing says why until
it is in a customer's hands), a placeholder in the unit template that nobody
substitutes.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from .helpers import PROJECT_ROOT, BackendTestCase

IMAGE = PROJECT_ROOT / "image"
BUILD = (PROJECT_ROOT / "scripts" / "build-image.sh").read_text()
CUSTOMIZE = (IMAGE / "customize.sh").read_text()
UNIT_TEMPLATE = (PROJECT_ROOT / "deploy" / "rapi-panel.service.in").read_text()
INSTALL = (PROJECT_ROOT / "scripts" / "install-service.sh").read_text()


def packages() -> list[str]:
    out = []
    for line in (IMAGE / "packages.list").read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


class PackageListTest(BackendTestCase):
    def test_the_pieces_without_which_the_device_is_not_the_device(self):
        listed = packages()
        for package in ("linux-image-rpi-2712", "raspi-firmware", "suricata",
                        "python3-fastapi", "python3-uvicorn", "python3-psutil"):
            self.assertTrue(
                any(p.split("/")[0] == package for p in listed),
                f"{package} is not in image/packages.list",
            )

    def test_the_engine_comes_from_backports(self):
        # trixie/main has 7.0.10. The panel is written against 8.x, and the
        # difference is not cosmetic: the af-packet block and the stats counters
        # both changed.
        self.assertIn("suricata/trixie-backports", packages())
        self.assertIn("geoip-database/trixie-backports", packages())

    def test_nothing_that_only_exists_for_development(self):
        # The whole point of the image. Each of these has been in a Pi image on
        # this desk at some point and none of them has any business there.
        forbidden = {"nodejs", "npm", "chromium", "git", "build-essential",
                     "gcc", "python3-pip", "cron"}
        for package in packages():
            self.assertNotIn(package.split("/")[0], forbidden)

    def test_the_radio_can_actually_be_used(self):
        """Wi-Fi is a way into this device, and the wizard asks about it.

        The build installs no Recommends, and wpasupplicant is only recommended
        by network-manager, so a card written with the flashing tool's wireless
        answer would come up with the keyfile in place and no way to associate.
        The firmware is the radio itself: without it there is no interface for
        the answer to apply to.
        """
        listed = {p.split("/")[0] for p in packages()}
        for package in ("wpasupplicant", "firmware-brcm80211", "wireless-regdb"):
            self.assertIn(package, listed, package)

    def test_what_the_panel_calls_at_runtime_is_installed(self):
        # Each of these is called by name from the panel or its helpers, and a
        # missing one fails at the moment the operator uses the feature.
        listed = {p.split("/")[0] for p in packages()}
        for package, caller in (
            ("raspi-utils-core", "vcgencmd, for throttling and under-voltage"),
            ("ethtool", "the capture helper, to switch offloads off"),
            ("network-manager", "the capture helper, to take an interface off DHCP"),
            ("logrotate", "the log directory feature writes entries for it"),
            ("sudo", "every privileged action the panel takes"),
            ("openssl", "the first boot issues the certificate with it"),
            ("avahi-daemon", "the panel is reached at <hostname>.local"),
            ("cloud-guest-utils", "growpart, and through it resize2fs and sfdisk, "
                                  "which the first boot grows the root with"),
        ):
            self.assertIn(package, listed, f"{package} is needed by: {caller}")


class UsbAdapterModeSwitchTest(BackendTestCase):
    """A Realtek USB adapter that boots as a CD drive.

    The RTL8153 enumerates as 0bda:8151, a 1.2 MB virtual CD with the Windows
    driver on it, until it is told to switch. usb-modeswitch-data 20191128 has
    no entry for that id, so no network driver bound and the second port of the
    bridge or the pair was not there after a cold boot. On the device on this
    desk that cut the network behind it: replugging sometimes skipped the CD,
    so it looked like a loose cable for weeks. Switched by hand with exactly
    the message below, after which it came back as 0bda:8153 on r8152.
    """

    CONFIG = PROJECT_ROOT / "deploy" / "rapi-usb-nic.modeswitch"
    RULE = PROJECT_ROOT / "deploy" / "rapi-usb-nic.rules"
    # The dispatcher looks a device up by this file name and by nothing else.
    INSTALLED_AS = "/etc/usb_modeswitch.d/0bda:8151"

    def settings(self) -> dict[str, str]:
        out = {}
        for line in self.CONFIG.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if "=" in line:
                key, value = line.split("=", 1)
                out[key.strip()] = value.strip().strip('"')
        return out

    def test_the_tool_that_switches_it_is_in_the_image(self):
        listed = {p.split("/")[0] for p in packages()}
        # The binary and the udev wrapper are in the first, the rule that runs
        # the wrapper at boot and the dispatcher's collection in the second.
        for package in ("usb-modeswitch", "usb-modeswitch-data"):
            self.assertIn(package, listed, package)

    def test_the_adapter_is_switched_to_its_network_mode(self):
        settings = self.settings()
        self.assertEqual(settings.get("TargetVendor"), "0x0bda")
        self.assertEqual(settings.get("TargetProduct"), "0x8153")
        # Realtek's command, verbatim. A mass storage command block: "USBC",
        # 31 bytes, which is what usb_modeswitch sends to the CD.
        message = settings.get("MessageContent", "")
        self.assertEqual(
            message, "555342430860d9a9c0000000800006e0000000000000000000000000000000")
        self.assertTrue(message.startswith("55534243"))
        self.assertEqual(len(bytes.fromhex(message)), 31)

    def test_the_rule_matches_the_cd_and_not_the_adapter(self):
        rule = [l for l in self.RULE.read_text().splitlines()
                if l.strip() and not l.startswith("#")]
        self.assertEqual(len(rule), 1, rule)
        self.assertIn('ATTR{idVendor}=="0bda"', rule[0])
        # 8151 and only 8151: a rule on 8153 would send a CD command to a
        # working network adapter every time it appears.
        self.assertIn('ATTR{idProduct}=="8151"', rule[0])
        self.assertNotIn("8153", rule[0])
        self.assertIn('ACTION=="add"', rule[0])
        # The package's wrapper, which only starts usb_modeswitch@.service and
        # returns. Running the switch from RUN directly would hold udev up, and
        # udev kills what outlives the event.
        self.assertIn("RUN+=\"/usr/lib/udev/usb_modeswitch '/%k'\"", rule[0])

    @unittest.skipUnless(Path("/usr/lib/udev/usb_modeswitch").exists(),
                         "usb-modeswitch is not installed here")
    def test_the_wrapper_the_rule_calls_exists_where_it_says(self):
        self.assertTrue(os.access("/usr/lib/udev/usb_modeswitch", os.X_OK))

    def test_an_adapter_already_plugged_in_is_not_left_unexplained(self):
        # udev fires no event for a device that is already there, so the rule
        # reaches the next plug and not the adapter in the port right now. Said
        # rather than triggered: a trigger replays add events for every USB
        # device, on what may be a probe with traffic crossing it.
        self.assertIn("udevadm trigger --subsystem-match=usb --action=add", INSTALL)
        ran = [l for l in INSTALL.splitlines()
               if "udevadm trigger" in l and not l.lstrip().startswith(("#", "echo"))]
        self.assertEqual(ran, [], ran)

    def test_both_installers_put_it_where_the_dispatcher_looks(self):
        for name, script in (("image/customize.sh", CUSTOMIZE),
                             ("scripts/install-service.sh", INSTALL)):
            with self.subTest(script=name):
                self.assertRegex(script, r"deploy/rapi-usb-nic\.modeswitch\"?\s*\\\n\s*\"?"
                                 r"(\$ROOTFS)?" + re.escape(self.INSTALLED_AS))
                self.assertIn("deploy/rapi-usb-nic.rules", script)
                self.assertRegex(script, r"/etc/udev/rules\.d/[0-9]+-rapi-usb-nic\.rules")


class PartitionIdentityTest(BackendTestCase):
    """cmdline.txt, fstab and the partition table have to agree.

    They are three files written by three different steps, and disagreement
    shows up as a board that boots to an initramfs prompt with no explanation.
    """

    def disk_id(self) -> str:
        match = re.search(r"^DISK_ID=0x([0-9A-Fa-f]{8})", BUILD, re.M)
        self.assertTrue(match, "DISK_ID missing from scripts/build-image.sh")
        return match.group(1).upper()

    def test_the_root_partition_in_cmdline_is_the_one_that_gets_created(self):
        cmdline = (IMAGE / "cmdline.txt").read_text()
        self.assertIn(f"root=PARTUUID={self.disk_id()}-02", cmdline)

    def test_fstab_names_both_partitions_of_this_image(self):
        fstab = (IMAGE / "fstab").read_text()
        self.assertIn(f"PARTUUID={self.disk_id()}-01", fstab)
        self.assertIn(f"PARTUUID={self.disk_id()}-02", fstab)

    def test_the_boot_partition_is_first_and_fat(self):
        self.assertRegex(BUILD, r"start=\$START, size=\$BOOT_SECTORS, type=c, bootable")


class UnitTemplateTest(BackendTestCase):
    """Both installers have to fill in every placeholder.

    A leftover @DATA_DIR@ is not a syntax error to systemd - it is a service
    that starts and writes its database to a directory named after the
    placeholder.
    """

    def placeholders(self) -> set[str]:
        return set(re.findall(r"@[A-Z_]+@", UNIT_TEMPLATE))

    def test_the_template_has_the_four_it_documents(self):
        self.assertEqual(
            self.placeholders(),
            {"@PANEL_ROOT@", "@DATA_DIR@", "@PYTHON@", "@PANEL_USER@"},
        )

    def test_the_checkout_installer_substitutes_all_of_them(self):
        for placeholder in self.placeholders():
            self.assertIn(f"s|{placeholder}|", INSTALL)

    def test_the_image_build_substitutes_all_of_them(self):
        for placeholder in self.placeholders():
            self.assertIn(f"s|{placeholder}|", CUSTOMIZE)


class LogDirectoriesTest(BackendTestCase):
    """The cleanup must not take the log directories with it.

    Deleting /var/log/* wholesale removed /var/log/suricata, which the package
    creates and the engine needs: it exits immediately with "error opening file
    /var/log/suricata//suricata.log" and the appliance boots with no detection.
    """

    def test_only_files_are_removed_from_var_log(self):
        self.assertIn('find "$ROOTFS/var/log" -type f -delete', CUSTOMIZE)
        self.assertNotIn('rm -rf "$ROOTFS"/var/log', CUSTOMIZE)


class FirstBootTest(BackendTestCase):
    def test_the_unit_starts_the_script_the_build_installs(self):
        unit = (IMAGE / "first-boot" / "rapi-first-boot.service").read_text()
        path = re.search(r"^ExecStart=(\S+)", unit, re.M).group(1)
        self.assertIn(f'"$ROOTFS{path}"', CUSTOMIZE)

    def test_it_runs_before_ssh(self):
        # The image ships with no host keys, and sshd will not start without
        # them. Ordering, not a restart loop, is what makes that deterministic.
        unit = (IMAGE / "first-boot" / "rapi-first-boot.service").read_text()
        before = [l for l in unit.splitlines() if l.startswith("Before=")]
        self.assertTrue(any("ssh.service" in l for l in before), before)

    def test_it_runs_before_the_panel(self):
        # The panel would otherwise start without a certificate, on the one boot
        # where the password is set.
        unit = (IMAGE / "first-boot" / "rapi-first-boot.service").read_text()
        self.assertIn("Before=rapi-panel.service", unit)

    def test_it_runs_once(self):
        unit = (IMAGE / "first-boot" / "rapi-first-boot.service").read_text()
        self.assertIn("ConditionPathExists=!", unit)

    def test_the_per_device_secrets_are_not_in_the_image(self):
        # Two devices from one image must not share a host key, a machine id or
        # a certificate authority.
        self.assertIn("rm -f \"$ROOTFS\"/etc/ssh/ssh_host_*", CUSTOMIZE)
        self.assertRegex(CUSTOMIZE, r':\s*>\s*"\$ROOTFS/etc/machine-id"')
        # And nothing about the network the image was built on.
        self.assertRegex(CUSTOMIZE, r':\s*>\s*"\$ROOTFS/etc/resolv.conf"')
        script = (IMAGE / "first-boot" / "rapi-first-boot.sh").read_text()
        self.assertIn("ssh-keygen -A", script)
        self.assertIn("setup-tls.sh", script)

    def test_home_net_is_decided_on_the_device(self):
        # Baked into the image it would describe the network the image was built
        # on, and 88 % of the rules would never match at the site.
        script = (IMAGE / "first-boot" / "rapi-first-boot.sh").read_text()
        self.assertIn("setup-suricata-override.sh", script)

    # --- growing the root, which had never once worked ---------------------
    #
    # Found the first time the image was booted in a virtual machine rather than
    # a container, because a container has no partition table to grow. Two
    # separate faults, both silent: `parted resizepart` refuses on a mounted
    # partition and the root is always mounted, and the image had no resize2fs
    # in it at all. Everything below pins one of those.

    def test_the_partition_is_grown_by_something_that_works_while_mounted(self):
        script = (IMAGE / "first-boot" / "rapi-first-boot.sh").read_text()
        # Comments stripped, because the one explaining why parted was dropped
        # names it, and a test that reads comments tests the wrong thing.
        code = "\n".join(l for l in script.splitlines() if not l.strip().startswith("#"))
        self.assertIn("growpart", code)
        # parted printed "Partition /dev/vda2 is being used. Are you sure you
        # want to continue?" and gave up, and the failure was logged and ignored.
        self.assertNotIn("parted", code)

    def test_the_image_carries_the_tools_that_resize_it(self):
        # growpart depends on e2fsprogs and fdisk, so listing it is what puts
        # resize2fs and sfdisk in the image. Before this the image shipped an
        # ext4 root with no resize2fs and no fsck.ext4 - and cmdline.txt asks
        # for the second one on every boot.
        listed = {p.split("/")[0] for p in packages()}
        self.assertIn("cloud-guest-utils", listed)

    def test_a_resize_that_fails_is_still_only_logged(self):
        # Deliberate: a device that cannot grow its filesystem is a device with
        # less space, while a first boot that aborts here is a device with no
        # certificate, no host keys and no HOME_NET. The order in the script is
        # what makes that safe, so it is worth a test.
        script = (IMAGE / "first-boot" / "rapi-first-boot.sh").read_text()
        self.assertLess(script.index("grow_root"), script.index("ssh_host_keys"))


class FirstBootFinishTest(BackendTestCase):
    """The stamp that stops the first boot from ever running again.

    It was written whatever had happened: a certificate that failed to issue
    stayed missing for the life of the card, and the panel, which cannot start
    without one, restarted forever. The end of the real script is run here,
    with the steps replaced and the paths pointed into a temporary tree.
    """

    SCRIPT = (IMAGE / "first-boot" / "rapi-first-boot.sh").read_text()

    def _run(self, failing: str = "", certificate: bool = True, wired: bool = True):
        data = self.tmp / "data"
        (data / "tls").mkdir(parents=True)
        if certificate:
            (data / "tls" / "server.crt").write_text("crt")
            (data / "tls" / "server.key").write_text("key")
        yaml = self.tmp / "suricata.yaml"
        yaml.write_text("include:\n  - /etc/suricata/rapi-overrides.yaml\n" if wired else "vars: {}\n")
        tail = self.SCRIPT[self.SCRIPT.index("failed=()"):]
        tail = (tail.replace("/etc/suricata/suricata.yaml", str(yaml))
                    .replace('install -d -o rapi -g rapi "$DATA_DIR"', ":"))
        steps = "".join(
            f"{name}() {{ {'return 1' if name == failing else 'return 0'}; }}\n"
            for name in ("grow_root", "ssh_host_keys", "apply_userconf", "wire_engine", "issue_tls"))
        script = (f'DATA_DIR="{data}"\nSTAMP="{data}/.first-boot-done"\n'
                  'log() { echo "first-boot: $*"; }\n' + steps + tail)
        proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
        return proc, (data / ".first-boot-done").exists()

    def test_a_clean_run_is_stamped(self):
        proc, stamped = self._run()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(stamped)

    def test_a_failed_step_leaves_it_to_run_again(self):
        for step in ("ssh_host_keys", "apply_userconf", "wire_engine", "issue_tls"):
            with self.subTest(step=step):
                self.tmp = Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, self.tmp, True)
                proc, stamped = self._run(failing=step)
                self.assertNotEqual(proc.returncode, 0)
                self.assertFalse(stamped)
                self.assertIn(step, proc.stdout)

    def test_a_missing_certificate_is_caught_whatever_the_steps_said(self):
        proc, stamped = self._run(certificate=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(stamped)
        self.assertIn("no panel certificate", proc.stdout)

    def test_an_engine_without_the_override_is_caught(self):
        proc, stamped = self._run(wired=False)
        self.assertFalse(stamped)
        self.assertIn("engine override not wired", proc.stdout)

    def test_a_card_that_cannot_grow_still_finishes(self):
        # As before: less space is not worth a first boot that never ends.
        proc, stamped = self._run(failing="grow_root")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertTrue(stamped)


class NoRootThroughThePanelTest(BackendTestCase):
    """The account whose password the panel knows must not reach root.

    The image put rapi in group sudo, and Debian lets that group run anything
    with its own password. The panel runs as rapi and may set that password
    (it becomes the SSH one), so a panel taken over could set a password it
    knows and `sudo -S` whatever it liked; whoever claimed the panel first got
    root over SSH the same way.
    """

    def test_the_image_does_not_put_the_panel_account_in_sudo(self):
        line = next(l for l in CUSTOMIZE.splitlines() if "useradd" in l and "$PANEL_USER" in l)
        self.assertNotIn("sudo", line)
        # Logs stay readable over SSH.
        self.assertIn("adm,systemd-journal", line)

    def test_a_password_from_userconf_brings_sudo_with_it(self):
        script = (IMAGE / "first-boot" / "rapi-first-boot.sh").read_text()
        self.assertRegex(script, r"usermod -p \"\$hash\" \"\$user\" && printf 'card %s\\n' "
                                 r"\"\$user\" > /var/lib/rapi-ssh-login \\\n\s*&& usermod -aG sudo \"\$user\"")

    def test_the_panel_s_grant_names_no_blanket_command(self):
        # What sudo gives the account beyond the group is the narrow file.
        sudoers = (PROJECT_ROOT / "deploy" / "sudoers-rapi-panel").read_text()
        self.assertNotRegex(sudoers, r"NOPASSWD:\s*ALL")


class BuildWithoutReadmeTest(BackendTestCase):
    """The public export has no README.md; both builds must still work.

    tar was handed README.md unconditionally, could not stat it on a public
    checkout, and set -e ended the build: no image from the public branch.
    The copying part of each script is run here, on a tree with and without it.
    """

    def _copy_step(self, script: str, start: str, end: str) -> str:
        return script[script.index(start):script.index(end) + len(end)]

    def _tree(self, readme: bool) -> Path:
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        for d in ("backend/app", "deploy", "scripts", "image", "frontend/dist/rapi-panel/browser"):
            (root / d).mkdir(parents=True)
        for f in ("backend/requirements.txt", "scripts/setup-suricata-override.sh",
                  "scripts/setup-tls.sh", "LICENSE"):
            (root / f).write_text("x\n")
        if readme:
            (root / "README.md").write_text("readme\n")
        return root

    def _run(self, step: str, env: dict) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", "-c", "set -euo pipefail\n" + step],
                              capture_output=True, text=True, env={**os.environ, **env})

    def test_the_image_build_copies_without_a_readme(self):
        step = self._copy_step(BUILD, "OPTIONAL=()", '| tar -C "$WORK/src" -xf -')
        for readme in (False, True):
            with self.subTest(readme=readme):
                root, work = self._tree(readme), Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, work, True)
                (work / "src").mkdir()
                proc = self._run(step, {"ROOT": str(root), "WORK": str(work)})
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual((work / "src" / "README.md").exists(), readme)

    def test_the_image_gets_the_english_readme_and_never_the_polish_one(self):
        step = self._copy_step(CUSTOMIZE, "OPTIONAL=()",
                               'mv "$ROOTFS$PANEL_ROOT/README.en.md" "$ROOTFS$PANEL_ROOT/README.md"\nfi')
        src, rootfs = self._tree(readme=True), Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, rootfs, True)
        (src / "README.md").write_text("polski\n")
        (src / "README.en.md").write_text("english\n")
        (rootfs / "opt/rapi-panel").mkdir(parents=True)
        proc = self._run(step, {"SRC": str(src), "ROOTFS": str(rootfs),
                                "PANEL_ROOT": "/opt/rapi-panel"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual((rootfs / "opt/rapi-panel/README.md").read_text(), "english\n")
        self.assertFalse((rootfs / "opt/rapi-panel/README.en.md").exists())

    def test_the_licence_goes_onto_the_card(self):
        # The image carries GPL-3.0 code; the licence has to go with every copy.
        for script, end in ((BUILD, '| tar -C "$WORK/src" -xf -'),
                            (CUSTOMIZE, '| tar -C "$ROOTFS$PANEL_ROOT" -xf -')):
            with self.subTest(script=end):
                self.assertIn("    LICENSE \\\n", self._copy_step(script, "OPTIONAL=()", end))
        step = self._copy_step(CUSTOMIZE, "OPTIONAL=()", '| tar -C "$ROOTFS$PANEL_ROOT" -xf -')
        src, rootfs = self._tree(readme=False), Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, rootfs, True)
        (rootfs / "opt/rapi-panel").mkdir(parents=True)
        proc = self._run(step, {"SRC": str(src), "ROOTFS": str(rootfs),
                                "PANEL_ROOT": "/opt/rapi-panel"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue((rootfs / "opt/rapi-panel/LICENSE").exists())

    def test_the_build_source_carries_the_english_readme(self):
        step = self._copy_step(BUILD, "OPTIONAL=()", '| tar -C "$WORK/src" -xf -')
        root, work = self._tree(readme=True), Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, work, True)
        (root / "README.en.md").write_text("english\n")
        (work / "src").mkdir()
        proc = self._run(step, {"ROOT": str(root), "WORK": str(work)})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue((work / "src" / "README.en.md").exists())
        self.assertFalse((work / "src" / "README.md").exists())

    def test_the_customisation_copies_without_a_readme(self):
        step = self._copy_step(CUSTOMIZE, "OPTIONAL=()", '| tar -C "$ROOTFS$PANEL_ROOT" -xf -')
        for readme in (False, True):
            with self.subTest(readme=readme):
                src, rootfs = self._tree(readme), Path(tempfile.mkdtemp())
                self.addCleanup(shutil.rmtree, rootfs, True)
                (rootfs / "opt/rapi-panel").mkdir(parents=True)
                proc = self._run(step, {"SRC": str(src), "ROOTFS": str(rootfs),
                                        "PANEL_ROOT": "/opt/rapi-panel"})
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual((rootfs / "opt/rapi-panel/README.md").exists(), readme)


class TlsKeyOwnershipTest(BackendTestCase):
    """The CA key stays root's; the panel gets the server pair only.

    The first boot gave the whole TLS directory to the panel's account, CA key
    included. A panel process taken over could then sign certificates that
    every machine which imported ca.crt trusts, for any name at all.
    """

    SCRIPT = (IMAGE / "first-boot" / "rapi-first-boot.sh").read_text()

    def body(self) -> str:
        return re.search(r"issue_tls\(\) \{(.*?)\n\}", self.SCRIPT, re.S).group(1)

    def test_the_directory_is_no_longer_handed_over_whole(self):
        self.assertNotIn('chown -R rapi:rapi "$DATA_DIR/tls"', self.SCRIPT)

    def test_the_ca_key_is_root_only(self):
        body = self.body()
        self.assertIn('chown root:root "$tls/ca.key" && chmod 0600 "$tls/ca.key"', body)

    def test_the_panel_can_still_read_what_it_serves_with(self):
        body = self.body()
        self.assertIn('chown rapi:rapi "$tls/server.key" && chmod 0600 "$tls/server.key"', body)
        # Into the directory through its group, and nothing more.
        self.assertIn('chown root:rapi "$tls" && chmod 0750 "$tls"', body)
        unit = (PROJECT_ROOT / "deploy" / "rapi-panel.service.in").read_text()
        served = set(re.findall(r"--ssl-\w+file\s+@DATA_DIR@/tls/(\S+)", unit))
        self.assertEqual(served, {"server.crt", "server.key"})


class NothingOfThisNetworkTest(BackendTestCase):
    """The image carries no address, name or card of the machine that built it.

    Everything here ships: customize.sh copies backend/app, deploy, two scripts,
    the built frontend, the README and docs into /opt/rapi-panel, and the
    appliance goes to somebody else's network. An address or a MAC from the
    development device is a note about a private network travelling inside a
    product, and once it is in an image somebody flashed it cannot be recalled.

    Examples are not banned, only real ones: the documentation ranges of
    RFC 5737, the private ranges of RFC 1918, the loopback and link-local
    blocks, the public resolvers named as resolvers, and the documentation MAC
    of RFC 7042 with the fixture prefixes the test scripts use.
    """

    # What goes into /opt/rapi-panel, plus the frontend sources the shipped
    # bundle is built from: a comment stripped by the build is still worth
    # keeping clean, and a string in a template is not stripped at all.
    SHIPPED = ("backend/app", "deploy", "scripts/setup-suricata-override.sh",
               "scripts/setup-tls.sh", "README.en.md", "frontend/src")

    IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
    # Resolvers are named in the text as what they are, not as somebody's
    # network, and the point of naming them is that the reader recognises them.
    RESOLVERS = {"1.1.1.1", "9.9.9.9", "8.8.8.8", "8.8.4.4", "1.0.0.1"}
    MAC_PREFIXES = ("00:00:5e:", "00:00:00:", "de:ad:be:ef:", "02:00:00:",
                    "52:54:00:", "aa:aa:aa:", "aa:bb:cc:")

    def allowed_ip(self, address: str) -> bool:
        try:
            parts = [int(p) for p in address.split(".")]
        except ValueError:
            return True
        if len(parts) != 4 or any(p > 255 for p in parts):
            return True   # a version number, a size, a rule id
        a, b = parts[0], parts[1]
        return (
            address in self.RESOLVERS
            or a in (0, 127)                                    # unspecified, loopback
            or (a, b) == (169, 254)                             # link-local
            or a == 10 or (a == 192 and b == 168)               # RFC 1918
            or (a == 172 and 16 <= b <= 31)
            or parts[:3] in ([192, 0, 2], [198, 51, 100], [203, 0, 113])  # RFC 5737
            or a >= 224                                          # multicast, broadcast
        )

    def offences(self, files=None, known=()):
        if files is None:
            files = []
            for name in self.SHIPPED:
                path = PROJECT_ROOT / name
                files += [path] if path.is_file() else sorted(
                    f for f in path.rglob("*") if f.is_file())
        found = []
        for file in files:
            try:
                text = file.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                where = f"{file.relative_to(PROJECT_ROOT)}:{line_no}"
                for address in self.IPV4.findall(line):
                    if not self.allowed_ip(address) and address not in known:
                        found.append(f"{where}: {address}")
                for mac in self.MAC.findall(line):
                    if not mac.lower().startswith(self.MAC_PREFIXES):
                        found.append(f"{where}: {mac}")
        return found

    # What the published repository holds beyond the image: the tests, the
    # build scripts, the image recipe. The owner's rule is about all of it:
    # no address in the code may speak of the owner's network. A fixture copied
    # from a real alert carried a real host, and the guard's own test named an
    # address out of the network it was written on.
    PRIVATE = ("docs/", "README.md")
    # Not addresses, or addresses that are the subject of a test of this guard.
    KNOWN = {"100.64.0.1", "198.51.99.7"}

    def test_nothing_in_the_published_tree_names_a_real_address(self):
        files = self._published()
        if not files:
            self.skipTest("not a git checkout")
        found = self.offences(files, self.KNOWN)
        self.assertEqual(found, [], "Real addresses in what gets published:\n"
                                    + "\n".join(found))

    def _published(self):
        listed = subprocess.run(["git", "ls-files"], cwd=PROJECT_ROOT,
                                capture_output=True, text=True).stdout.split("\n")
        return [PROJECT_ROOT / name for name in listed
                if name and not name.startswith(self.PRIVATE)
                and not name.endswith(("package-lock.json", ".png", ".svg"))
                and (PROJECT_ROOT / name).is_file()]

    def test_nothing_published_names_the_machine_it_was_written_on(self):
        """Not an address, and it went out anyway: a comment in the sudoers
        template gave the manual install with the checkout's own path in it,
        and the template is copied into the image.

        What to look for is taken from the machine running the tests, so the
        test itself names nothing: the directory the checkout is in, the home
        directory above it, and the host's name.
        """
        import socket
        files = self._published()
        if not files:
            self.skipTest("not a git checkout")
        needles = {str(PROJECT_ROOT)}
        home = Path.home()
        if home != Path("/") and len(home.parts) > 2 and PROJECT_ROOT.is_relative_to(home):
            # The home directory with the first directory under it: the bare
            # home of the product's own account is in the code on purpose.
            needles.add(str(home / PROJECT_ROOT.relative_to(home).parts[0]))
        host = socket.gethostname().split(".")[0]
        # The image's own name is in the code on purpose; a builder's is not.
        host_re = (re.compile(rf"(?<![\w-]){re.escape(host)}(?![\w-])")
                   if len(host) >= 4 and host not in ("localhost", "rapi-ids") else None)
        found = []
        for file in files:
            try:
                text = file.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                if any(n in line for n in needles) or (host_re and host_re.search(line)):
                    found.append(f"{file.relative_to(PROJECT_ROOT)}:{line_no}")
        self.assertEqual(found, [], "The build machine's own paths or name:\n" + "\n".join(found))

    def test_no_address_or_card_of_this_network_ships(self):
        found = self.offences()
        self.assertEqual(found, [], "Real addresses in what the image carries:\n"
                                    + "\n".join(found))

    def test_the_scan_covers_what_the_build_copies(self):
        # The list above is a copy of the one in customize.sh, and a file added
        # there would otherwise travel unread.
        for name in self.SHIPPED:
            if name.startswith("frontend"):
                continue
            self.assertIn(name, CUSTOMIZE, name)

    def test_the_development_journal_stays_out_of_the_image(self):
        # docs/ is the project's working journal, in Polish, thousands of lines
        # of how every fix was found. Nothing on a device needs it, and the
        # image goes to other people's networks.
        for script in (CUSTOMIZE, BUILD):
            copied = re.search(r"tar -C \"\$(?:SRC|ROOT)\" -cf - \\\n(.*?)\| tar", script, re.S)
            self.assertIsNotNone(copied)
            self.assertNotRegex(copied.group(1), r"(?m)(^|\s)docs(\s|\\|$)")

    def test_it_would_notice_an_address_from_a_real_network(self):
        # The check itself, on a line it must reject and one it must not.
        self.assertFalse(self.allowed_ip("100.64.0.1"))
        self.assertFalse(self.allowed_ip("198.51.99.7"))
        self.assertTrue(self.allowed_ip("198.51.100.7"))
        self.assertTrue(self.allowed_ip("192.168.1.1"))
        self.assertTrue(self.allowed_ip("127.0.0.1"))
        self.assertTrue(self.allowed_ip("1.1.1.1"))


class ImagerSettingsTest(BackendTestCase):
    """custom.toml, the file the official flashing tool leaves on the card.

    Run for real against a throwaway tree, with the commands it calls replaced
    by stubs that record themselves. What is checked is what a device would
    have on disk after the first boot: the wizard's answers, and no copy of the
    Wi-Fi password left on a partition any machine can read.
    """

    TOML = """
[system]
hostname = "ids-example"

[user]
name = "operator"
password = "$5$rounds=5000$abc$hashhashhash"

[ssh]
enabled = true
password_authentication = false
authorized_keys = [ "ssh-ed25519 AAAAC3NzaExample key@example" ]

[wlan]
ssid = "Example Wi-Fi"
password = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
password_encrypted = true
hidden = true
country = "PL"

[locale]
keymap = "pl"
timezone = "Europe/Warsaw"
"""

    SCRIPT = IMAGE / "first-boot" / "rapi-imager-config"
    # The file the tool leaves. PreseedSettingsTest below runs every test in
    # this class again against rpi-preseed.toml, the name Imager 2.x uses.
    FILE = "custom.toml"

    def setUp(self):
        super().setUp()
        self.boot = self.tmp / "boot"
        self.root = self.tmp / "root"
        self.bin = self.tmp / "stub-bin"
        for path in (self.boot, self.root, self.bin):
            path.mkdir(parents=True, exist_ok=True)
        (self.root / "etc").mkdir(exist_ok=True)
        (self.root / "etc" / "hosts").write_text(
            "127.0.0.1\tlocalhost\n127.0.1.1\trapi-ids\n")
        (self.root / "usr" / "share" / "zoneinfo" / "Europe").mkdir(parents=True)
        (self.root / "usr" / "share" / "zoneinfo" / "Europe" / "Warsaw").write_text("tz")
        self.log = self.tmp / "commands.log"
        for name in ("useradd", "usermod", "systemctl", "chown", "iw", "hostname"):
            stub = self.bin / name
            stub.write_text("#!/bin/sh\n"
                            f'echo "{name} $*" >> "{self.log}"\n'
                            "exit 0\n")
            stub.chmod(0o755)

    def run_it(self, text=None):
        (self.boot / self.FILE).write_text(self.TOML if text is None else text)
        env = dict(os.environ)
        env.update({
            "RAPI_BOOT_DIR": str(self.boot),
            "RAPI_TARGET": str(self.root),
            "PATH": f"{self.bin}:{env.get('PATH', '')}",
        })
        return subprocess.run(["/usr/bin/python3", str(self.SCRIPT)],
                              capture_output=True, text=True, env=env)

    def commands(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_the_wireless_network_is_written_before_anything_starts(self):
        """The answer that decides whether the device has a network at all.

        Written as a keyfile rather than added with nmcli: this runs before
        NetworkManager, so there is no daemon to ask.
        """
        proc = self.run_it()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        keyfile = (self.root / "etc/NetworkManager/system-connections"
                   / "Example_Wi-Fi.nmconnection")
        text = keyfile.read_text()
        self.assertIn("ssid=Example Wi-Fi", text)
        self.assertIn("key-mgmt=wpa-psk", text)
        self.assertIn("hidden=true", text)
        self.assertNotIn("nmcli", " ".join(self.commands()))

    def test_an_ssid_is_never_part_of_the_path(self):
        """SSIDs are somebody else's text and this one becomes a file name.

        "Home/Guests" would put the keyfile in a subdirectory NetworkManager
        does not read, so the network would quietly not exist; one starting
        with ".." would write outside the directory altogether.
        """
        self.run_it(self.TOML.replace('ssid = "Example Wi-Fi"',
                                      'ssid = "../../Home/Guests"'))
        conf = self.root / "etc/NetworkManager/system-connections"
        written = [f for f in conf.iterdir()]
        self.assertEqual([f.name for f in written], ["______Home_Guests.nmconnection"])
        # The name the wizard gave is kept where it belongs, inside the file.
        self.assertIn("ssid=../../Home/Guests", written[0].read_text())
        self.assertEqual(list(self.root.glob("*.nmconnection")), [])

    def test_the_wireless_secret_is_not_left_world_readable(self):
        # NetworkManager refuses a keyfile anybody can read, and so should we.
        self.run_it()
        keyfile = (self.root / "etc/NetworkManager/system-connections"
                   / "Example_Wi-Fi.nmconnection")
        self.assertEqual(stat.S_IMODE(keyfile.stat().st_mode), 0o600)

    def test_nothing_of_the_wizard_is_left_on_the_card(self):
        # The card is readable in any machine, and the file holds the Wi-Fi
        # password and the account hash.
        self.run_it()
        self.assertFalse((self.boot / self.FILE).exists())

    def test_the_name_is_set_on_the_running_system_too(self):
        """systemd read /etc/hostname in PID 1, long before this unit.

        Without this the whole first boot keeps the old name: avahi publishes
        it, and the certificate rapi-first-boot issues minutes later carries it
        in the SAN. That certificate is issued once, so the panel would warn
        about a name mismatch for the life of the card.
        """
        self.run_it()
        self.assertIn("hostname ids-example", self.commands())

    def test_a_name_that_would_break_avahi_is_refused(self):
        for name in ("ids-zolw".replace("z", "\u017c"), "-leading", "", "x" * 64):
            with self.subTest(name=name):
                self.run_it(self.TOML.replace('hostname = "ids-example"',
                                              f'hostname = "{name}"'))
                self.assertFalse((self.root / "etc/hostname").exists(), name)

    def test_the_name_reaches_both_places_that_have_to_agree(self):
        # The panel is reached as <name>.local, and avahi publishes the system
        # hostname: a /etc/hostname nobody else agrees with is a device
        # answering to a name it does not think it has.
        self.run_it()
        self.assertEqual((self.root / "etc/hostname").read_text().strip(),
                         "ids-example")
        hosts = (self.root / "etc/hosts").read_text()
        self.assertIn("127.0.1.1\tids-example", hosts)
        self.assertNotIn("rapi-ids", hosts)

    def test_the_account_from_the_wizard_is_created_beside_the_panel_s_own(self):
        # Renaming the shipped account would take the panel unit, the sudoers
        # entry and every path in the image with it.
        self.run_it()
        commands = self.commands()
        self.assertTrue(any(c.startswith("useradd") and "operator" in c for c in commands),
                        commands)
        self.assertTrue(any(c.startswith("usermod -p") and "operator" in c for c in commands),
                        commands)
        self.assertFalse(any("rapi" in c for c in commands), commands)

    def test_the_password_hash_is_passed_as_a_hash(self):
        # The wizard writes a crypt hash; a plain password must never start
        # existing on the device because of this script.
        self.run_it()
        line = [c for c in self.commands() if c.startswith("usermod")][0]
        self.assertIn("$5$rounds=5000$abc$hashhashhash", line)

    def test_a_password_from_the_card_is_marked_as_the_card_s(self):
        # The panel's SSH helper reads this and then leaves the account alone:
        # the password chosen when the card was prepared stays the SSH one.
        self.run_it()
        marker = self.root / "var" / "lib" / "rapi-ssh-login"
        self.assertEqual(marker.read_text(), "card operator\n")

    def test_keys_and_no_password_are_marked_as_keys(self):
        # Whoever prepared the card chose keys; the panel must not add a
        # password, which in Debian would switch password logins on.
        without = self.TOML.replace('password = "$5$rounds=5000$abc$hashhashhash"\n', "")
        self.assertNotEqual(without, self.TOML)
        self.run_it(without)
        marker = self.root / "var" / "lib" / "rapi-ssh-login"
        self.assertEqual(marker.read_text(), "key operator\n")

    def test_nothing_from_the_card_leaves_the_account_to_the_panel(self):
        without = re.sub(r"authorized_keys = \[.*?\]\n", "",
                         self.TOML.replace('password = "$5$rounds=5000$abc$hashhashhash"\n', ""),
                         flags=re.S)
        self.assertNotIn("authorized_keys", without)
        self.run_it(without)
        self.assertFalse((self.root / "var" / "lib" / "rapi-ssh-login").exists())

    def test_userconf_is_marked_as_the_card_s_too(self):
        # The other way a password comes with the card, applied by first boot.
        script = (IMAGE / "first-boot" / "rapi-first-boot.sh").read_text()
        self.assertRegex(script, r'usermod -p "\$hash" "\$user" && '
                                 r"printf 'card %s\\n' \"\$user\" > /var/lib/rapi-ssh-login")

    def test_a_key_on_the_boot_partition_is_marked_as_keys(self):
        # The same choice made with authorized_keys on the FAT partition, and a
        # password from userconf.txt, handled just before, still wins.
        script = (IMAGE / "first-boot" / "rapi-first-boot.sh").read_text()
        keys = script[script.index('if [[ -f "$BOOT/authorized_keys" ]]'):]
        self.assertRegex(keys, r"if ! grep -q '\^card ' /var/lib/rapi-ssh-login[^\n]*; then\n"
                               r"\s*printf 'key rapi\\n' > /var/lib/rapi-ssh-login")

    def test_the_ssh_answers_are_applied(self):
        self.run_it()
        keys = (self.root / "home/operator/.ssh/authorized_keys")
        self.assertIn("ssh-ed25519 AAAAC3NzaExample key@example", keys.read_text())
        self.assertEqual(stat.S_IMODE(keys.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(keys.parent.stat().st_mode), 0o700)
        conf = (self.root / "etc/ssh/sshd_config.d/99-rapi-imager.conf").read_text()
        self.assertIn("PasswordAuthentication no", conf)

    def test_ssh_is_switched_off_at_both_ends(self):
        # openssh-server in trixie can be started by its socket, so a service
        # disabled on its own leaves port 22 open through it.
        self.run_it(self.TOML.replace("enabled = true", "enabled = false"))
        line = [c for c in self.commands() if c.startswith("systemctl disable")]
        self.assertEqual(line, ["systemctl disable --now ssh.service ssh.socket"])

    def test_the_locale_answers_are_applied(self):
        self.run_it()
        self.assertEqual((self.root / "etc/timezone").read_text().strip(),
                         "Europe/Warsaw")
        self.assertTrue((self.root / "etc/localtime").is_symlink())
        self.assertIn('XKBLAYOUT="pl"',
                      (self.root / "etc/default/keyboard").read_text())

    def test_the_regulatory_domain_outlives_the_boot_it_was_set_on(self):
        # `iw reg set` does not survive a reboot, and a radio on the wrong
        # domain loses channels rather than failing outright.
        self.run_it()
        self.assertIn("ieee80211_regdom=PL",
                      (self.root / "etc/modprobe.d/rapi-regdom.conf").read_text())

    def test_a_card_it_cannot_write_to_is_reported_not_raised(self):
        # A FAT partition remounted read-only is what a tired card looks like,
        # and a traceback on a device whose only screen is the login banner
        # tells nobody anything.
        self.run_it()
        (self.boot / self.FILE).write_text(self.TOML)
        self.boot.chmod(0o555)
        self.addCleanup(self.boot.chmod, 0o755)
        proc = self.run_it()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("could not be removed from the card", proc.stdout)

    def test_a_file_it_cannot_read_is_left_for_a_person_to_look_at(self):
        proc = self.run_it("this is not toml = = =\n")
        self.assertEqual(proc.returncode, 1)
        self.assertTrue((self.boot / self.FILE).exists())
        self.assertIn("could not be read", proc.stdout)

    def test_a_wizard_that_answered_nothing_changes_nothing(self):
        proc = self.run_it("[system]\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.commands(), [])
        self.assertFalse((self.root / "etc/hostname").exists())
        self.assertFalse((self.boot / self.FILE).exists())

    def test_no_file_is_no_work(self):
        env = dict(os.environ)
        env.update({"RAPI_BOOT_DIR": str(self.boot), "RAPI_TARGET": str(self.root)})
        proc = subprocess.run(["/usr/bin/python3", str(self.SCRIPT)],
                              capture_output=True, text=True, env=env)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")

    # --- how it reaches the device ------------------------------------------

    def test_the_build_installs_the_script_the_unit_starts(self):
        unit = (IMAGE / "first-boot" / "rapi-imager-config.service").read_text()
        path = re.search(r"^ExecStart=(\S+)", unit, re.M).group(1)
        self.assertIn(f'"$ROOTFS{path}"', CUSTOMIZE)
        self.assertIn("rapi-imager-config.service", CUSTOMIZE)

    def test_it_runs_before_the_network_it_configures(self):
        unit = (IMAGE / "first-boot" / "rapi-imager-config.service").read_text()
        before = [l for l in unit.splitlines() if l.startswith("Before=")]
        self.assertTrue(any("NetworkManager.service" in l for l in before), before)
        self.assertTrue(any("rapi-first-boot.service" in l for l in before), before)

    def test_it_waits_for_the_partition_the_file_is_on(self):
        # A nofail mount is not ordered before local-fs.target. On the first
        # real card the unit's conditions ran before /boot/firmware was
        # mounted, and the settings file was never read.
        unit = (IMAGE / "first-boot" / "rapi-imager-config.service").read_text()
        lines = [l for l in unit.splitlines() if not l.startswith("#")]
        after = " ".join(l for l in lines if l.startswith("After="))
        wants = " ".join(l for l in lines if l.startswith("Wants="))
        self.assertIn("boot-firmware.mount", after)
        self.assertIn("boot-firmware.mount", wants)
        # The partition's device is not known to systemd before udev is
        # triggered, so being ordered before that would wait for a device that
        # cannot appear.
        before = " ".join(l for l in lines if l.startswith("Before="))
        self.assertNotIn("systemd-udev-trigger.service", before)
        # And the mount point named here is the one fstab mounts.
        self.assertRegex((IMAGE / "fstab").read_text(), r"(?m)^\S+\s+/boot/firmware\s+vfat\s")

    def test_it_is_skipped_on_a_card_nobody_customised(self):
        unit = (IMAGE / "first-boot" / "rapi-imager-config.service").read_text()
        self.assertIn(f"ConditionPathExists=|/boot/firmware/{self.FILE}", unit)


class PreseedSettingsTest(ImagerSettingsTest):
    """rpi-preseed.toml, what Imager 2.0.11 and later leave on the card.

    Every test above, again, against the file exactly as Imager's
    generateRpiPreseedToml writes it: config_version first, the account hash
    with password_encrypted, groups and passwordless_sudo, SSH keys as a
    multi-line array. Without this reader the Wi-Fi typed into the wizard
    never reached the card.
    """

    FILE = "rpi-preseed.toml"
    TOML = """config_version = "1.0"

[system]
hostname = "ids-example"

[user]
name = "operator"
password = "$5$rounds=5000$abc$hashhashhash"
password_encrypted = true
groups = ["sudo"]
passwordless_sudo = true

[ssh]
enabled = true
password_authentication = false
authorized_keys = [
  "ssh-ed25519 AAAAC3NzaExample key@example",
]

[wlan]
ssid = "Example Wi-Fi"
password = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
password_encrypted = true
hidden = true
country = "PL"

[locale]
keymap = "pl"
timezone = "Europe/Warsaw"
"""

    def keyfile(self) -> str:
        return (self.root / "etc/NetworkManager/system-connections"
                / "Example_Wi-Fi.nmconnection").read_text()

    def test_rapi_named_by_the_wizard_with_a_password_gets_sudo(self):
        # The image leaves rapi without sudo; a password from the card, which
        # the panel never sees, is what brings it back.
        text = self.TOML.replace('name = "operator"', 'name = "rapi"')
        self.assertNotEqual(text, self.TOML)
        self.run_it(text)
        self.assertIn("usermod -aG sudo rapi", self.commands())

    def test_keys_alone_bring_no_sudo(self):
        text = self.TOML.replace('name = "operator"', 'name = "rapi"').replace(
            'password = "$5$rounds=5000$abc$hashhashhash"\n', "")
        self.run_it(text)
        self.assertNotIn("usermod -aG sudo rapi", self.commands())

    def test_a_network_name_that_is_not_utf8_arrives_as_bytes(self):
        # Imager writes ssid_hex for such a name; NetworkManager takes the
        # octets as a list of byte values.
        text = self.TOML.replace('ssid = "Example Wi-Fi"', 'ssid_hex = "4578ff41"')
        self.assertNotEqual(text, self.TOML)
        self.run_it(text)
        files = list((self.root / "etc/NetworkManager/system-connections").iterdir())
        self.assertEqual(len(files), 1, files)
        self.assertIn("\nssid=69;120;255;65;\n", files[0].read_text())

    def test_a_plain_account_password_goes_through_chpasswd_on_stdin(self):
        # Imager always writes a hash; a file written by hand may not. usermod
        # -p would store the plain text as if it were a hash, and an argument
        # would show it to everyone in `ps`.
        stub = self.bin / "chpasswd"
        stub.write_text(f'#!/bin/sh\necho "chpasswd $*" >> "{self.log}"\n'
                        f'cat > "{self.tmp}/chpasswd.stdin"\n')
        stub.chmod(0o755)
        text = (self.TOML.replace('password = "$5$rounds=5000$abc$hashhashhash"',
                                  'password = "plain words here"')
                .replace("password_encrypted = true\ngroups", "password_encrypted = false\ngroups"))
        self.run_it(text)
        self.assertEqual((self.tmp / "chpasswd.stdin").read_text(), "operator:plain words here\n")
        self.assertFalse([c for c in self.commands() if c.startswith("usermod -p")])
        self.assertFalse([c for c in self.commands() if "plain words" in c])

    def test_both_files_are_applied_and_both_are_wiped(self):
        # A card prepared twice, by two versions of the tool.
        (self.boot / "custom.toml").write_text('[system]\nhostname = "older-name"\n')
        proc = self.run_it()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse((self.boot / "custom.toml").exists())
        self.assertFalse((self.boot / self.FILE).exists())
        # The newer file is applied last, so its answer is the one that stays.
        self.assertEqual((self.root / "etc/hostname").read_text(), "ids-example\n")


class ImagerManifestTest(BackendTestCase):
    """scripts/imager-manifest.py: what makes Imager show its settings at all.

    An image picked with "Use custom" gets init_format "none" in Imager 2.x,
    which means no settings step, so the Wi-Fi typed into it could not reach
    the card by any route. A manifest entry with init_format "rpi-preseed" is
    the only way to get the step for an image that is not in Raspberry Pi's
    own repository.
    """

    SCRIPT = PROJECT_ROOT / "scripts" / "imager-manifest.py"

    def _image(self) -> tuple[Path, bytes]:
        import lzma
        payload = b"RAPI" * 300_000
        image = self.tmp / "rapi-ids-trixie-arm64-20260924.img.xz"
        image.write_bytes(lzma.compress(payload))
        return image, payload

    def _write(self, *extra: str) -> dict:
        import json
        image, _ = self._image()
        proc = subprocess.run(["/usr/bin/python3", str(self.SCRIPT), str(image), *extra],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads((self.tmp / "rapi-ids.rpi-imager-manifest").read_text())

    def test_the_entry_asks_for_the_settings_step(self):
        entry = self._write()["os_list"][0]
        self.assertEqual(entry["init_format"], "rpi-preseed")
        self.assertEqual(entry["devices"], ["pi5-64bit"])
        self.assertEqual(entry["release_date"], "2026-09-24")

    def test_the_hashes_are_the_ones_imager_will_check(self):
        import hashlib
        image, payload = self._image()
        entry = self._write()["os_list"][0]
        self.assertEqual(entry["extract_size"], len(payload))
        self.assertEqual(entry["extract_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(entry["image_download_size"], image.stat().st_size)
        self.assertEqual(entry["image_download_sha256"],
                         hashlib.sha256(image.read_bytes()).hexdigest())

    def test_the_image_is_named_by_an_absolute_file_url(self):
        # As Raspberry Pi's create_local_json.py does it.
        entry = self._write()["os_list"][0]
        self.assertEqual(entry["url"], self._image()[0].resolve().as_uri())

    def test_a_release_names_the_image_by_its_download_address(self):
        import json
        image, _ = self._image()
        out = self.tmp / "release" / "rapi-ids.rpi-imager-manifest"
        proc = subprocess.run(
            ["/usr/bin/python3", str(self.SCRIPT), str(image), "--base-url",
             "https://example.org/releases/download/v1/", "--output", str(out)],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        entry = json.loads(out.read_text())["os_list"][0]
        self.assertEqual(entry["url"], f"https://example.org/releases/download/v1/{image.name}")
        # The local manifest, with its file:// address, is left alone.
        self.assertFalse((self.tmp / "rapi-ids.rpi-imager-manifest").exists())

    def test_a_release_address_has_to_be_https(self):
        image, _ = self._image()
        proc = subprocess.run(
            ["/usr/bin/python3", str(self.SCRIPT), str(image), "--base-url", "http://example.org/x"],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("https://", proc.stderr)

    def test_the_device_list_offers_the_pi5(self):
        devices = self._write()["imager"]["devices"]
        self.assertEqual([d["tags"] for d in devices], [["pi5-64bit"]])

    def test_the_build_passes_what_it_already_knows(self):
        entry = self._write("--extract-sha256", "ab" * 32, "--extract-size", "7")["os_list"][0]
        self.assertEqual((entry["extract_sha256"], entry["extract_size"]), ("ab" * 32, 7))

    def test_the_build_writes_it_next_to_every_compressed_image(self):
        self.assertIn('scripts/imager-manifest.py" "$IMG.xz"', BUILD)
        # Hashed before xz replaces the file it would hash.
        self.assertLess(BUILD.index('sha256sum "$IMG"'), BUILD.index('xz -T0 -6 -f "$IMG"'))


class TwoInstallersOneProductTest(BackendTestCase):
    """The image and the checkout installer must ship the same machine.

    They drifted, and the way it showed was the worst kind: the daily signature
    refresh was installed by scripts/install-service.sh and by nothing in the
    image, so every image ever built ran on the rules from the day it was made,
    for as long as it was plugged in, and reported itself healthy. That is word
    for word the failure the timer exists to prevent.

    Found by the blocking self test in scripts/test-image-vm.sh, which called a
    helper that was not there. Nothing else would have: the container test never
    waits a day.
    """

    # Files under deploy/ that belong to one of the two on purpose. Each needs a
    # reason, because an empty exception list is what let the drift happen.
    ONLY_IN_IMAGE = {
        # The console banner is for a device with a screen or a serial cable and
        # no account on it. A checkout runs on somebody's own Pi, which has both.
        "rapi-issue",
        "rapi-issue.service",
    }

    # Neither side is one script.
    #
    # A checkout install is install-service.sh, which calls
    # setup-suricata-override.sh, and the second is where most helpers come
    # from. The image is customize.sh plus that same override script, because
    # the image ships the whole tree and the first boot runs it from there -
    # which is why several helpers are absent from customize.sh and present on
    # the device anyway. test_the_first_boot_still_runs_the_override below is
    # what keeps that second half true.
    OVERRIDE = (PROJECT_ROOT / "scripts" / "setup-suricata-override.sh").read_text()
    FIRST_BOOT = (IMAGE / "first-boot" / "rapi-first-boot.sh").read_text()
    CHECKOUT = INSTALL + OVERRIDE
    IMAGE_SIDE = CUSTOMIZE + OVERRIDE

    def test_the_first_boot_still_runs_the_override(self):
        # The assumption the two comparisons below rest on. If this stops being
        # true, the image loses every helper customize.sh does not install by
        # name, and the comparisons would go on passing.
        self.assertIn("setup-suricata-override.sh", self.FIRST_BOOT)

    def references(self, text: str) -> set[str]:
        """Every deploy/ file a script installs, in either spelling.

        Both installers name some files by path and others through a `for helper
        in ...` list, and a check that only understood one spelling would have
        missed exactly the file that went missing.
        """
        found = set(re.findall(r"deploy/(rapi-[A-Za-z0-9._-]+)", text))
        for block in re.findall(r"for helper in (.*?);\s*do", text, re.S):
            found.update(re.findall(r"rapi-[A-Za-z0-9._-]+", block))
        return found

    def test_the_image_ships_everything_the_checkout_installer_does(self):
        missing = self.references(self.CHECKOUT) - self.references(self.IMAGE_SIDE)
        self.assertEqual(missing, set(),
                         f"the image does not install: {sorted(missing)}")

    def test_the_checkout_ships_everything_the_image_does(self):
        missing = (self.references(CUSTOMIZE)
                   - self.references(self.CHECKOUT) - self.ONLY_IN_IMAGE)
        self.assertEqual(missing, set(),
                         f"a checkout install does not get: {sorted(missing)}")

    def test_the_daily_refresh_is_switched_on_in_the_image(self):
        # Installed but not enabled is the same appliance with a longer story.
        self.assertRegex(CUSTOMIZE, r"systemctl enable[^\n]*(\\\n[^\n]*)*rapi-rules-update\.timer")

    def test_no_exception_outlives_its_file(self):
        for name in sorted(self.ONLY_IN_IMAGE):
            with self.subTest(name=name):
                self.assertIn(name, self.references(CUSTOMIZE))


class RuleLicenceTest(BackendTestCase):
    """68 000 of the rules in the image are somebody else's, under BSD.

    Redistributing them in binary form is free and needs no permission; the one
    condition is that the notice goes with them. suricata-update merges the set
    into a single suricata.rules and leaves LICENSE and BSD-License.txt inside
    the archive it cached, under /var/lib/suricata/update/cache, which is
    root-only. So the text was technically in the image and findable by nobody.

    Checked here as text because the extraction runs inside a build; the boot
    test asserts the files are really there afterwards.
    """

    CUSTOMIZE = (PROJECT_ROOT / "image" / "customize.sh").read_text(encoding="utf-8")
    BOOT_TEST = (PROJECT_ROOT / "scripts" / "test-image.sh").read_text(encoding="utf-8")

    def test_the_image_build_takes_the_licence_out_of_the_archive(self):
        self.assertIn("rules/LICENSE", self.CUSTOMIZE)
        self.assertIn("rules/BSD-License.txt", self.CUSTOMIZE)
        self.assertIn("/usr/share/doc/emerging-threats-rules", self.CUSTOMIZE)

    def test_it_is_taken_from_the_archive_that_was_actually_used(self):
        # Newest by mtime, not first by name: the cache is keyed by a hash of
        # the source URL and the URL carries the engine version, so an upgraded
        # engine leaves the previous set sitting next to the current one.
        extraction = self.CUSTOMIZE.split("ET_ARCHIVE=")[1].split("fi\n")[0]
        self.assertIn("sort -n | tail -n 1", extraction)

    def test_the_boot_test_checks_the_licence_arrived(self):
        # A build step with no check is a build step that stops running quietly.
        self.assertIn("/usr/share/doc/emerging-threats-rules/LICENSE", self.BOOT_TEST)

    def test_the_engine_rules_are_not_claimed_as_emerging_threats(self):
        """ET's own LICENSE claims SIDs 2000000-2799999, engine rules included.

        The 2200000-2299999 range is Suricata's, shipped by the Debian package
        under GPL-2, and it happens to fall inside the range that text claims.
        Recorded next to the extraction so nobody later reads the ET notice as
        covering them.
        """
        self.assertIn("GPL-2", self.CUSTOMIZE)
        self.assertIn("Debian suricata package", self.CUSTOMIZE)


class ConsoleBannerTest(BackendTestCase):
    """What the screen says to somebody who just powered the device up.

    They have no account on it - there is none until the panel is opened - and
    the one thing they need is a URL that depends on an address the device only
    learns at boot. "rapi-ids login:" on its own is a dead end.
    """

    def script(self) -> str:
        return (PROJECT_ROOT / "deploy" / "rapi-issue").read_text()

    def test_the_banner_is_installed_and_enabled(self):
        self.assertIn("rapi-issue", CUSTOMIZE)
        self.assertRegex(CUSTOMIZE, r"systemctl enable[^\n]*(\\\n\s*)?[^\n]*rapi-issue\.service")

    def test_it_is_written_before_the_login_prompt_is_drawn(self):
        unit = (PROJECT_ROOT / "deploy" / "rapi-issue.service").read_text()
        self.assertIn("Before=", unit)
        self.assertIn("getty", unit)
        # And after there is an address to print, which is the whole content.
        self.assertIn("network-online.target", unit)

    def test_it_follows_the_address_and_not_only_the_boot(self):
        # A lease that arrives or changes later would otherwise leave a URL on
        # screen that no longer works.
        self.assertIn("dispatcher.d/50-rapi-issue", CUSTOMIZE)

    def test_prompts_already_on_screen_are_redrawn(self):
        # agetty reads /etc/issue when it draws the prompt. Without this the
        # banner is one boot old on a device that just got its address.
        self.assertIn("agetty --reload", self.script())

    def test_the_capture_interface_is_not_offered_as_a_way_in(self):
        # It carries no address on purpose. Printing it as somewhere to browse
        # to would send the reader at the one port that cannot answer.
        script = self.script()
        self.assertIn("CAPTURE", script)
        self.assertIn('"$iface" == "$CAPTURE"', script)

    def test_the_image_does_not_ship_debians_default_banner(self):
        # Which is the distribution name: the one fact nobody powering up an
        # appliance needed.
        self.assertRegex(CUSTOMIZE, r'cat > "\$ROOTFS/etc/issue"')


class BootTestScriptTest(BackendTestCase):
    """The image is booted in a container before it goes anywhere near a card.

    It boots a *copy*, and that is the whole point: booting the artifact itself
    stamps the first boot into it, so the next device from that image would skip
    generating its own host keys and its own certificate. It happened once, by
    hand, before this script existed.
    """

    def test_it_boots_a_copy_and_not_the_artifact(self):
        script = (PROJECT_ROOT / "scripts" / "test-image.sh").read_text()
        self.assertRegex(script, r'COPY=.*\$\{IMAGE%\.img\}')
        self.assertRegex(script, r'cp "\$IMAGE" "\$COPY"')
        # nspawn must be pointed at the mount of the copy, never at $IMAGE.
        nspawn = [l for l in script.splitlines() if "systemd-nspawn" in l and not l.strip().startswith("#")]
        for line in nspawn:
            self.assertNotIn("$IMAGE", line)

    def test_it_cleans_up_after_itself(self):
        script = (PROJECT_ROOT / "scripts" / "test-image.sh").read_text()
        self.assertIn("trap cleanup EXIT", script)
        self.assertIn("machinectl terminate", script)

    def test_the_two_units_that_cannot_work_in_a_container_are_named(self):
        # Anything else failing is a finding, so the exceptions have to be an
        # explicit list rather than a shrug at the whole report.
        script = (PROJECT_ROOT / "scripts" / "test-image.sh").read_text()
        self.assertIn("fake-hwclock-load", script)
        self.assertIn("systemd-remount-fs", script)


class GuiWalkthroughTest(BackendTestCase):
    """scripts/gui-walkthrough.py presses every button the API has.

    Each route was tested on its own against mocks, and the bugs that reached
    the user lived between them: a re-saved layout that refused blocking, a
    switch whose answer landed off screen. The walkthrough runs them in a row
    on a booted image (test-image-vm.sh --gui). A route added later and left
    out of it would quietly go back to being tested only in isolation.
    """

    WALK = (PROJECT_ROOT / "scripts" / "gui-walkthrough.py").read_text()
    VM = (PROJECT_ROOT / "scripts" / "test-image-vm.sh").read_text()

    def test_every_api_route_is_walked(self):
        from app.main import app
        missing = []
        for route in app.routes:
            methods = getattr(route, "methods", None)
            if not methods or not route.path.startswith("/api/"):
                continue
            # A path parameter is filled in by the walkthrough: an f-string
            # field, or a literal value such as "reload".
            pattern = re.escape(route.path)
            pattern = re.sub(r"\\\{[a-z_]+\\\}", r"(\\{[^}]+\\}|[a-z0-9_-]+)", pattern)
            for method in methods - {"HEAD"}:
                if method == "GET":
                    found = re.search(r'"' + pattern + r'[?"]', self.WALK)
                else:
                    found = re.search(r'"' + method + r'", f?"' + pattern + r'"', self.WALK)
                if not found:
                    missing.append(f"{method} {route.path}")
        self.assertEqual(missing, [], "not in scripts/gui-walkthrough.py")

    def test_the_vm_runs_it_and_the_screens(self):
        self.assertIn('scripts/gui-walkthrough.py" \\', self.VM)
        self.assertIn('scripts/screenshots.py" \\', self.VM)
        self.assertIn("--gui)     GUI=1", self.VM)

    def test_the_traffic_comes_from_inside_the_guest(self):
        # The host scans nothing: the alerts come from the guest's own requests
        # to the Debian mirror, never from the host probing anything.
        fixture = self.VM[self.VM.index("rapi-gui-traffic\" >/dev/null <<'TRAFFIC'"):
                          self.VM.index("\nTRAFFIC\n")]
        self.assertIn('"User-Agent", "wget 3.0"', fixture)
        self.assertNotRegex(fixture, r"\b(nmap|ping|nc|hping3?)\b")

    def test_interactive_and_gui_are_refused_together(self):
        # --interactive execs QEMU before any check: the walkthrough never ran,
        # and the traffic fixture stayed on the kept disk, raising test alerts
        # on every later interactive boot.
        out = self.tmp / "image-out"
        out.mkdir()
        result = subprocess.run(
            ["bash", str(PROJECT_ROOT / "scripts" / "test-image-vm.sh"), "--interactive", "--gui"],
            env={**os.environ, "RAPI_IMAGE_OUT": str(out)},
            capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("pick one", result.stderr)
        self.assertEqual(list(out.iterdir()), [])

    def test_the_basic_run_boots_a_card_as_imager_writes_it(self):
        # Every earlier test ran the settings script directly, with the
        # directory handed to it. Whether the unit ever started on a booted
        # card was not tested, and it did not.
        self.assertIn('sudo tee "$FAT/rpi-preseed.toml"', self.VM)
        for check in ("the hostname from Imager is set",
                      "the Wi-Fi from Imager is a saved connection",
                      "the account password from Imager is in use",
                      "the settings file is wiped off the card"):
            self.assertIn(check, self.VM)

    def test_the_traffic_lasts_until_the_machine_stops(self):
        fixture = self.VM[self.VM.index("rapi-gui-traffic\" >/dev/null <<'TRAFFIC'"):
                          self.VM.index("\nTRAFFIC\n")]
        self.assertIn("while :; do", fixture)

    def test_demo_alerts_come_after_the_walkthrough_and_only_with_gui(self):
        result = subprocess.run(
            ["bash", str(PROJECT_ROOT / "scripts" / "test-image-vm.sh"), "--demo"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        # Injected only once the walkthrough's last engine change is over, so
        # a made-up "blocked" event cannot satisfy the real blocking check.
        fixture = self.VM[self.VM.index("rapi-demo-inject\" >/dev/null <<'DEMO'"):
                          self.VM.index("\nDEMO\n")]
        self.assertIn("until [ -d /var/log/rapi-walkthrough ]", fixture)

    def test_demo_alerts_name_real_rules_and_no_real_host(self):
        import ipaddress
        import json
        rules = self.tmp / "demo.rules"
        lines = []
        for sid, (rating, name) in enumerate((
                ("Critical", "ET MALWARE Cobalt Strike Beacon Observed"),
                ("Major", "ET MALWARE Win32/Emotet CnC Checkin"),
                ("Minor", "ET ADWARE_PUP Fake Wget User-Agent"),
                ("Informational", "ET INFO Observed DNS Query to .cc TLD")), start=2900001):
            lines.append(f'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"{name}"; '
                         f'classtype:trojan-activity; sid:{sid}; rev:2; '
                         f'metadata:signature_severity {rating}, created_at 2020_01_01;)')
        rules.write_text("\n".join(lines) + "\n")
        result = subprocess.run(
            ["python3", str(PROJECT_ROOT / "scripts" / "demo-alerts.py"), "--rules", str(rules),
             "--classification", "/nonexistent", "--home", "10.0.2.0/24"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertGreater(len(events), 100)
        documentation = [ipaddress.ip_network(n) for n in
                         ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
        home = ipaddress.ip_network("10.0.2.0/24")
        for event in events:
            self.assertIn(event["alert"]["signature_id"], range(2900001, 2900005))
            self.assertIn(ipaddress.ip_address(event["src_ip"]), home)
            remote = ipaddress.ip_address(event["dest_ip"])
            self.assertTrue(any(remote in net for net in documentation), remote)
        self.assertEqual({e["alert"]["metadata"]["signature_severity"][0] for e in events},
                         {"Critical", "Major", "Minor", "Informational"})
        self.assertIn("blocked", {e["alert"]["action"] for e in events})

    def test_it_fails_when_a_check_fails(self):
        result = subprocess.run(
            ["python3", str(PROJECT_ROOT / "scripts" / "gui-walkthrough.py"),
             "--url", "https://127.0.0.1:9"],
            env={**os.environ, "RAPI_PASS": "x" * 16}, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAIL", result.stdout)


class InteractiveVmSshTest(BackendTestCase):
    """The interactive machine can be reached over SSH, not only the panel.

    Only 443 was forwarded, so the guest's own SSH, which a real card offers,
    could not be tried at all. Same address as the panel, so --bind decides
    who can reach both.
    """

    SCRIPT = (PROJECT_ROOT / "scripts" / "test-image-vm.sh").read_text()

    def test_port_22_is_forwarded_on_the_panel_s_address(self):
        net = next(l for l in self.SCRIPT.splitlines() if l.startswith("NET=(-netdev"))
        self.assertIn("hostfwd=tcp:$BIND:$HOST_PORT-:443", net)
        self.assertIn("hostfwd=tcp:$BIND:$SSH_PORT-:22", net)

    def test_the_banner_says_how_to_use_it(self):
        self.assertIn('ssh -p $SSH_PORT rapi@$BIND', self.SCRIPT)

    def test_the_blocking_self_test_goes_through_the_panel(self):
        # It called rapi-ips-mode directly, so the button, the API and set_mode
        # were never run on a live system, and "Detection and blocking" failed
        # in the panel with every VM test green.
        fixture = self.SCRIPT[self.SCRIPT.index("rapi-ips-selftest\" >/dev/null <<'SELFTEST'"):
                              self.SCRIPT.index("\nSELFTEST\n")]
        self.assertIn('api POST /api/auth/setup', fixture)
        self.assertIn("api POST /api/suricata/protection/mode '{\"block\": true}'", fixture)
        self.assertIn("api POST /api/suricata/protection/mode '{\"block\": false}'", fixture)
        self.assertNotRegex(fixture, r"(?m)^\s*(if )?/usr/local/sbin/rapi-ips-mode ips")
        # The panel writes its own policy files; the fixture must not do it
        # for it, or a panel that stopped would pass.
        self.assertNotIn('> "$DATA/drop.conf"', fixture)
        self.assertNotIn('> "$DATA/disable.conf"', fixture)
        # The control request stays first: without the internet the result is
        # "not proven", not a failure, and nothing below may pass on its own.
        self.assertLess(fixture.index('say "ok the control request reached the internet"'),
                        fixture.index("api POST /api/auth/setup"))
        # Every early FAIL also says done, or the host waits out its timeout.
        lines = fixture.splitlines()
        for number, line in enumerate(lines):
            if line.strip() == "exit 0" and "FAIL" in "\n".join(lines[max(0, number - 4):number]):
                with self.subTest(line=number):
                    self.assertIn('say "done"', "\n".join(lines[number - 2:number]))
        for line in ("the panel switched to blocking", "blocking is off again"):
            with self.subTest(line=line):
                self.assertIn(f'said "{line}"', self.SCRIPT)

    def test_the_modules_are_copied_into_the_directory_not_nested(self):
        # cp -a DIR DIR over an existing directory nests it ($kv/$kv).
        body = self.SCRIPT[self.SCRIPT.index("generic_modules_into() {"):]
        body = body[:body.index("\n}\n")]
        self.assertIn('"$KDIR/x/usr/lib/modules/$kv/." "$1/usr/lib/modules/$kv/"', body)
        self.assertNotIn('"$KDIR/x/usr/lib/modules/$kv" "$1/usr/lib/modules/$kv"', body)

    def test_the_interactive_machine_gets_the_netfilter_modules(self):
        # Without them, blocking on "This device only" failed with "Unable to
        # initialize Netlink socket: Protocol not supported" in the panel.
        block = self.SCRIPT[self.SCRIPT.index("if [[ $INTERACTIVE -eq 1 || $PRESEED -eq 1 ]]; then\n  ROOTFS="):]
        block = block[:block.index("\nfi\n")]
        self.assertIn('generic_modules_into "$ROOTFS"', block)
        # Before the loop device is let go, or there is nothing to mount.
        self.assertLess(self.SCRIPT.index("if [[ $INTERACTIVE -eq 1 || $PRESEED -eq 1 ]]; then\n  ROOTFS="),
                        self.SCRIPT.index('sudo losetup -d "$LOOP"; LOOP=""'))


class InlineVmTestScriptTest(BackendTestCase):
    """The virtual machine that proves a pair really drops a packet.

    A self test that cannot run says SKIP, and SKIP is not a failure, so every
    way it could quietly prove nothing has to be pinned here instead.
    """

    SCRIPT = (PROJECT_ROOT / "scripts" / "test-image-vm.sh").read_text()

    def _selftest(self) -> str:
        start = self.SCRIPT.index("rapi-inline-selftest\" >/dev/null <<'SELFTEST'")
        return self.SCRIPT[start:self.SCRIPT.index("\nSELFTEST\n", start)]

    def test_the_cards_it_wires_are_the_cards_the_guest_looks_for(self):
        """Found by address, so the addresses on both sides have to be the same.

        One wrong digit and the guest finds no card, says SKIP, and the run
        reports that nothing was proven, in a colour that is not red.
        """
        wired = set(re.findall(r"cable_end \w+ ([0-9a-f:]{17})", self.SCRIPT))
        wanted = set(re.findall(r"by_mac ([0-9a-f:]{17})", self._selftest()))
        self.assertEqual(len(wired), 4)
        self.assertEqual(wired, wanted)

    def test_each_cable_joins_a_pair_port_to_the_host_behind_it(self):
        # A cable whose two ends name the same socket twice, or cross to the
        # wrong card, carries nothing, and the path would never come up.
        ends = dict(re.findall(r"cable_end (\w+) [0-9a-f:]{17} (\w+) \w+", self.SCRIPT))
        remotes = dict(re.findall(r"cable_end (\w+) [0-9a-f:]{17} \w+ (\w+)", self.SCRIPT))
        self.assertEqual((ends["pa"], remotes["pa"]), (remotes["cl"], ends["cl"]))
        self.assertEqual((ends["pb"], remotes["pb"]), (remotes["sv"], ends["sv"]))
        self.assertNotEqual(ends["pa"], ends["pb"])

    def test_the_server_is_outside_home_net(self):
        """SID 2007961 is `$HOME_NET any -> $EXTERNAL_NET any`.

        With both hosts inside HOME_NET the rule never fires. The pair would
        then stop nothing, the bridge would report nothing, and the run would
        fail or pass for a reason unrelated to the swap.
        """
        selftest = self._selftest()
        self.assertIn('HOME="[10.99.0.1/32]"', selftest)
        self.assertIn("10.99.0.2/24", selftest)

    def test_it_walks_there_and_back(self):
        # The way back is the half four reviews found closed.
        selftest = self._selftest()
        swaps = re.findall(r"^if swap (\w+);", selftest, re.M)
        self.assertEqual(swaps, ["bridge", "pair", "bridge"])

    def test_every_check_the_guest_can_pass_is_one_the_host_asks_about(self):
        # A line the guest prints and the host never greps for is a result
        # nobody sees.
        # The swap says "the swap to $1 went through" for both of its targets,
        # so each sentence is written out for both before it is compared.
        #
        # And compared the way the host really looks, which is `grep` for
        # "ok <phrase>": the phrase has to start the sentence. The first version
        # of this test accepted a phrase anywhere in it, passed, and the VM run
        # then reported that the pair did not stop a request it had stopped.
        said = [line.replace("$1", target)
                for line in re.findall(r'say "ok ([^"]+)"', self._selftest())
                for target in ("bridge", "pair")]
        asked = re.findall(r'inline_said "([^"]+)"', self.SCRIPT)
        for phrase in asked:
            with self.subTest(phrase=phrase):
                self.assertTrue(any(line.startswith(phrase) for line in said), phrase)
        self.assertGreaterEqual(len(asked), 10)

    def test_the_wait_online_exception_belongs_to_the_inline_run_only(self):
        """The four cable ends are cards without DHCP, so waiting times out.

        That is this fixture's wiring. Allowed for every run, it would hide a
        NetworkManager that really does not come online on an ordinary boot,
        which is exactly the kind of failure the check exists to report.
        """
        guard = self.SCRIPT.index('EXPECTED="$EXPECTED|NetworkManager-wait-online"')
        opening = self.SCRIPT.rindex("\nif ", 0, guard)
        self.assertEqual(self.SCRIPT[opening:self.SCRIPT.index("\n", opening + 1)],
                         "\nif [[ $INLINE -eq 1 ]]; then")
        self.assertIn("EXPECTED='fake-hwclock-load|systemd-remount-fs'", self.SCRIPT)

    def test_a_unit_name_with_capitals_is_read_whole(self):
        """Run, not read: the pattern the script uses, on the line it meets.

        Lower case only, NetworkManager-wait-online came out as
        "anager-wait-online", which no exception could match and which named
        nothing a person could look up.
        """
        pattern = re.search(r"grep -oE '([^']+\\.service)'", self.SCRIPT).group(1)
        line = "[  61.2] systemd[1]: Failed to start NetworkManager-wait-online.service - Network Manager Wait Online."
        proc = subprocess.run(["grep", "-oE", pattern], input=line,
                              capture_output=True, text=True)
        self.assertEqual(proc.stdout.strip(), "NetworkManager-wait-online.service")

    def test_the_self_tests_are_never_run_together(self):
        # --gui joined --ips and --inline: each takes the engine over.
        self.assertIn('if [[ $(( IPS + INLINE + GUI )) -gt 1 ]]; then', self.SCRIPT)

    def test_the_bridge_module_reaches_the_generic_kernel(self):
        # The bridge is a module in Debian's kernel, and the image carries
        # modules for another one. Without the copy, br-rapi is never built.
        start = self.SCRIPT.index('if [[ $INLINE -eq 1 ]]; then\n  echo "==> Putting')
        # The outer block ends after the unit file, not at the first `fi` of the
        # shell script it writes into the guest.
        after_unit = self.SCRIPT.index("\nUNIT\n", start)
        block = self.SCRIPT[after_unit:self.SCRIPT.index("\nfi\n", after_unit)]
        self.assertIn('generic_modules_into "$ROOTFS"', block)


class ShellSyntaxTest(BackendTestCase):
    def test_the_image_scripts_parse(self):
        for script in (PROJECT_ROOT / "scripts" / "build-image.sh",
                       PROJECT_ROOT / "scripts" / "test-image.sh",
                       PROJECT_ROOT / "scripts" / "test-image-vm.sh",
                       IMAGE / "customize.sh",
                       IMAGE / "first-boot" / "rapi-first-boot.sh"):
            with self.subTest(script=script.name):
                proc = subprocess.run(["bash", "-n", str(script)],
                                      capture_output=True, text=True)
                self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_they_stop_on_an_error(self):
        # A build that keeps going after a failed step produces an image that
        # looks finished and is missing whatever the failed step was for.
        for script in (PROJECT_ROOT / "scripts" / "build-image.sh",
                       IMAGE / "customize.sh"):
            with self.subTest(script=script.name):
                self.assertIn("\nset -euo pipefail\n", script.read_text())


if __name__ == "__main__":
    unittest.main()
