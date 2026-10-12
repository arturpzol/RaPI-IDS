# Contributing to RaPi IDS

Thank you for considering a contribution. This file covers how the project is
licensed, what you agree to when you contribute, and how to get a change in.

## Licence

RaPi IDS is copyright (C) 2026 Artur Piechocki and is released under the GNU
General Public License, version 3 or (at your option) any later version
(GPL-3.0-or-later). The full text is in [LICENSE](LICENSE).

The image this project builds also carries third party software under its own
licences, Suricata (GPL-2.0) and the Emerging Threats rules (BSD) among them.
Those licences are unchanged by this one.

## What you agree to when you contribute

The project may in future offer paid editions or paid features beside the free
GPL edition. To keep that possible, every contribution comes with the
following grant. By opening a pull request, sending a patch, or otherwise
submitting a contribution, you confirm that:

1. The contribution is your own work, or you have the right to submit it under
   these terms.
2. You license it to the project under GPL-3.0-or-later.
3. You also grant Artur Piechocki a perpetual, worldwide, non-exclusive,
   royalty-free, irrevocable licence to use, modify, distribute and sublicense
   the contribution under any other terms, including proprietary or
   commercial ones.
4. You keep the copyright in your contribution and may use it in any way you
   like yourself.

Please add this line to the description of your pull request:

    I agree to the terms in CONTRIBUTING.md.

A pull request without it cannot be merged.

## Getting a change in

- Run the whole test suite before you open a pull request: `scripts/test.sh`
  runs the backend (unittest) and the frontend (Karma) tests.
- A bug fix comes with a test that fails on the old code.
- Code, comments and interface text are in English. Text files are ASCII.
- Packages come from the Debian archives (trixie and trixie-backports) and
  archive.raspberrypi.com only. Nothing is downloaded from anywhere else.
- Never include anything from your own network in a change: addresses, host
  names, MAC addresses or captures. The tests check for it.

## Trademarks

Raspberry Pi is a trademark of Raspberry Pi Ltd. RaPi IDS is an independent
project, not affiliated with or endorsed by Raspberry Pi Ltd.
