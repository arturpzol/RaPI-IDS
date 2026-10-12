"""What the panel's own account may actually do as root.

The project keeps a deliberately narrow `sudoers` entry: engine reload, the rule
rebuild, and four root-owned helper scripts. That narrowing is only worth
anything if it is the *only* grant the account has, and on a machine somebody
else provisioned it very often is not. This device is the example: cloud-init
had written

    /etc/sudoers.d/90-cloud-init-users:  rapi ALL=(ALL) NOPASSWD:ALL

which made the whole design decorative - the panel's user could run anything as
root without a password, so every line of the narrow file was advice rather than
a limit.

Nothing here changes any of that. It reads `sudo -n -l` once at startup and says
so in the log, because an appliance that quietly has more privilege than it was
designed for is worse than one that says it does.
"""
from __future__ import annotations

import logging
import re
import subprocess

log = logging.getLogger(__name__)

# A grant of everything, in the shapes `sudo -l` prints it: "(ALL : ALL) ALL",
# "(ALL) NOPASSWD: ALL", "(root) ALL". The trailing ALL is the command, and that
# is the part that matters - a grant of every command, whoever it runs as.
_BLANKET = re.compile(r"^\s*\((?:ALL|root)(?:\s*:\s*ALL)?\)\s*(?:NOPASSWD:\s*)?ALL\s*$")


def blanket_grants(listing: str) -> list[str]:
    """Lines from `sudo -l` that hand over every command."""
    return [line.strip() for line in listing.splitlines() if _BLANKET.match(line)]


def check(timeout: int = 10) -> list[str]:
    """Log a warning when the panel's account has more than the narrow entry.

    Returns the offending lines, for the test. A `sudo` that cannot answer -
    no sudo at all, a password prompt, a machine that does not use it - is not
    a finding: it means the question could not be asked, not that the answer
    was bad.
    """
    try:
        proc = subprocess.run(
            ["sudo", "-n", "-l"], capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.SubprocessError, OSError):
        return []
    if proc.returncode != 0:
        return []

    grants = blanket_grants(proc.stdout)
    if grants:
        log.warning(
            "This account may run any command as root (%s). deploy/sudoers-rapi-panel "
            "narrows the panel to a handful of commands, and another sudoers file is "
            "undoing that. Look for one granting ALL, often left by cloud-init or by "
            "the distribution's first-user setup.",
            "; ".join(grants),
        )
    return grants
