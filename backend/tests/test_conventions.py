"""The rule in docs/code-conventions.md, enforced instead of remembered.

Code and interface in English, Polish only in README.md and docs/. It held for
months and then two strings slipped through anyway - one of them printed into
the page header on every visit to the System tab. Both were written months
apart by somebody who had the rule in front of them, which is the argument for
checking it here rather than at review time.

A word list rather than a language detector: these are function words with no
English homograph, so a hit is a hit. It will not catch every Polish sentence,
and it does not have to - it catches the ones somebody actually types.
"""
from __future__ import annotations

import ast
import re
import unittest
import tempfile
from pathlib import Path

from app import main

from .helpers import PRIVATE_DOCS, PRIVATE_DOCS_SKIP, PROJECT_ROOT, BackendTestCase

# Deliberately short. Every entry has to be a word that cannot appear inside an
# English identifier, string or comment, or this test becomes something people
# work around instead of obeying.
POLISH = [
    "nieznany", "nieznane", "brak", "blad", "bledy", "sie", "wiec", "ktory",
    "ktora", "ktore", "zeby", "przez", "oraz", "tylko", "jest", "urzadzenie",
    "siec", "reguly", "zapisz", "anuluj", "wlacz", "wylacz", "sprawdz",
    "komunikaty", "postac", "klient", "moze", "mowi", "zaden", "skanuj",
]
WORDS = re.compile(r"\b(" + "|".join(POLISH) + r")\b", re.IGNORECASE)
# Ends the one line allowed to list Polish words: the public export's guard.
WORD_LIST_MARK = "# polish-word-list"

# Where the rule applies. README.md and docs/ are Polish on purpose.
SOURCES = [
    (PROJECT_ROOT / "backend" / "app", ("*.py",)),
    (PROJECT_ROOT / "frontend" / "src" / "app", ("*.ts", "*.html", "*.css")),
    (PROJECT_ROOT / "deploy", ("*",)),
    (PROJECT_ROOT / "scripts", ("*.sh", "*.py")),
    # The tests are published with the rest. A docstring in main.py and three
    # quoted remarks in test comments went out in Polish because nothing here
    # looked at them.
    (PROJECT_ROOT / "backend" / "tests", ("*.py",)),
    (PROJECT_ROOT / "image", ("*",)),
]

# Tests whose fixtures are Polish text on purpose: this file's own word list,
# and the export guard's proof that it refuses a Polish document.
POLISH_FIXTURES = {"backend/tests/test_conventions.py", "backend/tests/test_deploy.py"}


# Everything above, plus the places Polish is allowed. The rule about
# characters applies to all of them.
TEXTS = SOURCES + [
    (PROJECT_ROOT, ("*.md",)),
    (PROJECT_ROOT / "docs", ("*.md",)),
    (PROJECT_ROOT / "frontend" / "public", ("*.md",)),
]

# Nothing we wrote. A vendored README full of emoji is not our rule to enforce,
# and rglob from the project root walks straight into thousands of them.
VENDORED = {"node_modules", ".venv", "dist", ".git", "__pycache__", "browser"}

# The Polish half of the project. These carry prose, so they are held to ASCII;
# the interface is not, because a degree sign is a unit and an arrow is a
# button.
PROSE = [
    (PROJECT_ROOT, ("*.md",)),
    (PROJECT_ROOT / "docs", ("*.md",)),
    (PROJECT_ROOT / "frontend" / "public", ("*.md",)),
]

# The one file that has to contain the character it forbids, because it is
# where the ban is written down.
ASCII_EXEMPT = {"docs/code-conventions.md"}


class LanguageTest(BackendTestCase):
    def test_the_code_and_the_interface_are_in_english(self):
        offences: list[str] = []
        for root, patterns in SOURCES:
            for pattern in patterns:
                for path in sorted(root.rglob(pattern)):
                    if not path.is_file():
                        continue
                    if str(path.relative_to(PROJECT_ROOT)) in POLISH_FIXTURES:
                        continue
                    for number, line in enumerate(
                            path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                        if line.rstrip().endswith(WORD_LIST_MARK):
                            continue
                        found = WORDS.search(line)
                        if found:
                            rel = path.relative_to(PROJECT_ROOT)
                            offences.append(f"{rel}:{number}: {found.group(0)!r} in {line.strip()}")
        self.assertEqual(offences, [], "Polish in code or interface:\n" + "\n".join(offences))

    def test_the_only_word_list_is_the_export_guard(self):
        # A line may carry Polish words when it is a list of them to look for,
        # which is what the public export checks against. One such line, in
        # one file: the marker must not become a way round the rule.
        marked = [str(path.relative_to(PROJECT_ROOT))
                  for root, patterns in SOURCES for pattern in patterns
                  for path in root.rglob(pattern) if path.is_file()
                  for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
                  if line.rstrip().endswith(WORD_LIST_MARK)]
        self.assertEqual(marked, ["scripts/export-public.sh"])

    def test_the_check_would_notice(self):
        # A guard that passes because its pattern is broken guards nothing.
        self.assertIsNotNone(WORDS.search('    model = "nieznany"'))
        self.assertIsNotNone(WORDS.search('return 124, f"timeout po {t}s"'.replace("po", "wiec")))
        self.assertIsNone(WORDS.search('    model = "unknown model"'))
        self.assertIsNone(WORDS.search("# the interface the engine listens on"))


class CharacterTest(BackendTestCase):
    """The two rules in docs/code-conventions.md about characters, mechanised.

    Both were being checked by eye and by a grep somebody had to remember. In
    one day three slipped: a Cyrillic letter hiding inside a Polish word, then
    "szesc", then "pasc". None of them looks wrong on the rendered page, so
    every one cost an explicit byte scan to find. This is that scan, run for
    free with the rest of the suite.
    """

    def _files(self, roots):
        for root, patterns in roots:
            for pattern in patterns:
                for path in sorted(root.rglob(pattern)):
                    if not path.is_file() or VENDORED & set(path.parts):
                        continue
                    rel = path.relative_to(PROJECT_ROOT).as_posix()
                    if rel in ASCII_EXEMPT:
                        continue
                    yield rel, path.read_text(encoding="utf-8", errors="replace")

    def test_the_polish_files_carry_no_diacritics(self):
        # Polish here is written without them on purpose, so anything outside
        # ASCII in README.md or docs/ is a slip rather than a choice. The GUI
        # is a different matter and is checked separately below: a degree sign
        # and an arrow are interface, not prose.
        offences: list[str] = []
        for rel, text in self._files(PROSE):
            for number, line in enumerate(text.splitlines(), 1):
                outside = sorted({c for c in line if ord(c) > 127})
                if outside:
                    offences.append(f"{rel}:{number}: {outside} in {line.strip()[:70]}")
        self.assertEqual(offences, [], "Characters outside ASCII:\n" + "\n".join(offences))

    def test_no_em_dash_anywhere(self):
        # The rule names README, docs/, the interface strings and the comments
        # in the code, so this reads all of them.
        offences: list[str] = []
        for rel, text in self._files(TEXTS):
            for number, line in enumerate(text.splitlines(), 1):
                # Spelled in two halves, so that the line naming the entity
                # is not itself a line that contains it.
                if "\u2014" in line or ("&" + "mdash;") in line:
                    offences.append(f"{rel}:{number}: {line.strip()[:70]}")
        self.assertEqual(offences, [], "Em dash:\n" + "\n".join(offences))

    # Drawing components: their strings are SVG path data and transforms, where
    # a minus is arithmetic. Nothing in them is read by a person.
    DASH_EXEMPT = {"frontend/src/app/shared/line-chart.ts",
                   "frontend/src/app/shared/topology-diagram.ts"}

    # Quoted text, of all three kinds TypeScript has.
    _STRINGS = re.compile(r"""'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)"|`((?:\\.|[^`\\])*)`""")

    @classmethod
    def _prose(cls, line: str, *, quoted_only: bool) -> str:
        """The part of a line a reader could end up seeing.

        Interpolations and regular expressions are code that happens to sit
        inside quotes, and both are full of arithmetic minuses. In a .ts file
        only the quoted parts are text at all; in a template the line is text
        already, so taking the quoted parts there would read the bindings and
        miss everything between the tags.
        """
        line = re.sub(r"/(?:\\.|[^/\\\n])+/[gimsuy]*", "", line)   # /regex/
        if quoted_only:
            line = " ".join(m.group(1) or m.group(2) or m.group(3) or ""
                            for m in cls._STRINGS.finditer(line))
        return re.sub(r"\$\{[^{}]*\}", "", line)                   # ${ ... }

    @classmethod
    def _dash_offences(cls, root: Path) -> tuple[list[str], int]:
        """Every dash clause under `root`, and how many files were read.

        The count is returned because the interesting way for this to break is
        for it to read nothing: a narrowed suffix filter or a widened exemption
        makes every assertion below pass by looking at an empty list.
        """
        offences: list[str] = []
        scanned = 0
        for path in sorted(root.rglob("*")):
            if path.suffix not in (".html", ".ts") or path.name.endswith(".spec.ts"):
                continue
            rel = (str(path.relative_to(PROJECT_ROOT))
                   if path.is_relative_to(PROJECT_ROOT) else str(path.relative_to(root)))
            if rel in cls.DASH_EXEMPT:
                continue
            scanned += 1
            text = path.read_text(encoding="utf-8")
            if path.suffix == ".html":
                text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
            for number, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith(("//", "*", "/*")):
                    continue
                if " - " in cls._prose(line, quoted_only=path.suffix == ".ts"):
                    offences.append(f"{rel}:{number}: {stripped[:70]}")
        return offences, scanned

    def test_no_dash_clause_in_anything_a_person_reads(self):
        """The em dash rule is about the construction, not about the character.

        docs/code-conventions.md says to replace it with "kropka, przecinek,
        dwukropek, nawias albo inne zdanie": a full stop, a comma, a colon, a
        parenthesis or another sentence. A hyphen is none of those, and writing
        " - " instead was the same sentence in a different character. The test
        checked only for the character, so it never noticed.
        """
        offences, scanned = self._dash_offences(PROJECT_ROOT / "frontend" / "src" / "app")
        self.assertGreater(scanned, 30, "the scan read almost nothing")
        self.assertEqual(offences, [], "Dash clause:\n" + "\n".join(offences))

    def test_the_dash_scan_finds_what_is_planted_in_front_of_it(self):
        """A scan that reads nothing passes every assertion above it.

        Three of the ways this can break narrow the scan rather than break the
        code, so it is shown a tree it has to get exactly right.
        """
        tree = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (tree / "page.html").write_text(
            "<p>the link is up - nothing reaches it</p>\n"
            "<!-- a comment - not read by anybody -->\n", encoding="utf-8")
        (tree / "code.ts").write_text(
            "const a = 'the sensor is inline - and blind';\n"
            "// see the label 'the link is up - nothing reaches it'\n"
            "const b = units.length - 1;\n"
            "const c = `M${x - 2} ${y}`;\n", encoding="utf-8")
        (tree / "thing.spec.ts").write_text("const t = 'a spec - not shipped';\n",
                                            encoding="utf-8")

        offences, scanned = self._dash_offences(tree)
        self.assertEqual(scanned, 2, "the spec file should not be read")
        self.assertEqual(len(offences), 2, offences)
        self.assertTrue(any("page.html:1" in o for o in offences), offences)
        self.assertTrue(any("code.ts:1" in o for o in offences), offences)

    # Strings where the dash is not a dash clause, each with the reason.
    PY_DASH_EXEMPT = (
        # SQL, not prose: the schema carries `--` comments of its own.
        ("backend/app/db.py", "CREATE TABLE"),
        # A list of permitted characters, in which the dash is one of them.
        ("backend/app/modules/suricata/logdir.py", "letters, digits and . _ - /"),
    )

    @classmethod
    def _python_offences(cls, root: Path) -> tuple[list[str], int]:
        """Dash clauses in Python strings a person can end up reading.

        Half the text on the screen is written in the backend: the layout
        descriptions, the mode explanation, every HTTPException detail, the
        headers written into files on the device, and the log lines. The scan
        covered only frontend/src/app, so a rule about the interface was being
        applied to half the interface.

        Docstrings are left out. The convention names comments too, and there
        the construction is everywhere - it is a bigger job than this and it is
        not what somebody reads off the screen.
        """
        offences: list[str] = []
        scanned = 0
        for path in sorted(root.rglob("*.py")):
            rel = (str(path.relative_to(PROJECT_ROOT))
                   if path.is_relative_to(PROJECT_ROOT) else str(path.relative_to(root)))
            scanned += 1
            tree = ast.parse(path.read_text(encoding="utf-8"))
            docs = set()
            for node in ast.walk(tree):
                body = getattr(node, "body", None)
                if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                     ast.ClassDef)) and body:
                    first = body[0]
                    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                       and isinstance(first.value.value, str):
                        docs.add(id(first.value))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                if id(node) in docs or " - " not in node.value:
                    continue
                if any(rel.endswith(f) and fragment in node.value
                       for f, fragment in cls.PY_DASH_EXEMPT):
                    continue
                line = next(p for p in node.value.split("\n") if " - " in p)
                offences.append(f"{rel}:{node.lineno}: {line.strip()[:70]}")
        return offences, scanned

    def test_no_dash_clause_in_the_text_the_backend_writes(self):
        offences, scanned = self._python_offences(PROJECT_ROOT / "backend" / "app")
        self.assertGreater(scanned, 15, "the scan read almost nothing")
        self.assertEqual(offences, [], "Dash clause:\n" + "\n".join(offences))

    def test_the_python_scan_finds_what_is_planted_in_front_of_it(self):
        tree = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (tree / "mod.py").write_text(
            '"""A docstring - not read off any screen."""\n'
            'MESSAGE = "the sensor is inline - and blind"\n'
            '# a comment - not read off any screen\n'
            'WIDTH = 10 - 1\n', encoding="utf-8")
        offences, scanned = self._python_offences(tree)
        self.assertEqual(scanned, 1)
        self.assertEqual(len(offences), 1, offences)
        self.assertIn("mod.py:2", offences[0])

    def test_the_dash_scan_would_notice(self):
        # Three halves, really: prose in a template, prose in a string, and
        # arithmetic and regular expressions left alone.
        def html(line): return self._prose(line, quoted_only=False)
        def ts(line): return self._prose(line, quoted_only=True)
        self.assertIn(" - ", html("<p>the link is up - nothing reaches it</p>"))
        self.assertIn(" - ", ts("      + 'the link is up - nothing reaches it';"))
        self.assertNotIn(" - ", ts("`M${x - 2} ${y}`"))
        self.assertNotIn(" - ", ts("while (i < units.length - 1) {"))
        self.assertNotIn(" - ", ts(".sort((a, b) => b.count - a.count)"))

    @unittest.skipUnless(PRIVATE_DOCS, PRIVATE_DOCS_SKIP)
    def test_the_scan_reads_the_files_it_claims_to(self):
        # An exemption list or a bad glob would make both tests above pass by
        # looking at nothing at all.
        prose = {rel for rel, _ in self._files(PROSE)}
        self.assertIn("README.md", prose)
        self.assertIn("docs/obraz-ids.md", prose)
        self.assertNotIn("docs/code-conventions.md", prose)   # the one exemption
        everything = {rel for rel, _ in self._files(TEXTS)}
        self.assertIn("backend/app/db.py", everything)
        self.assertIn("frontend/src/app/app.ts", everything)
        self.assertIn("deploy/rapi-ips-mode", everything)

    def test_the_scan_would_notice(self):
        # A guard that passes because its condition is broken guards nothing.
        # These are the characters that actually slipped.
        for bad in ("lata\u043dina", "sze\u015b\u0107", "mial pa\u015b\u0107"):
            self.assertTrue([c for c in bad if ord(c) > 127],
                            f"{bad!r} would slip through")
        for good in ("latanina", "szesc", "mial pasc"):
            self.assertEqual([c for c in good if ord(c) > 127], [])
        self.assertIn("\u2014", "a \u2014 b")
        self.assertNotIn("\u2014", "a - b")


class DocumentationTest(BackendTestCase):
    """The Polish documents describe behaviour, and behaviour moves.

    Every test in this project checks what the code does. None checked what the
    project says about it, so for weeks the code changed under tests that held
    it while the prose stayed where it was. An audit found around thirty
    statements that had each been true on the day they were written: a removed
    endpoint still documented, a screen described as the opposite of what it
    does, a GUI language convention stated backwards.

    These two catch the mechanical half of that - a named path that does not
    exist any more. The rest still needs a reader, but this is the half that
    rots silently.
    """

    # Current-state documents only. docs/obraz-ids.md is a dated journal: an
    # entry there describes what was true on its date and is superseded by a
    # later one, so a feature named in it having since been removed is the file
    # working as intended, not drift.
    DOCS = ("README.md", "docs/code-conventions.md")

    # Illustrative rather than real: the how-to for adding a module invents a
    # module name, and one path is elided with dots for width.
    EXAMPLES = {"backend/app/modules/moj_modul/router.py"}

    @staticmethod
    def _placeholders(path: str) -> str:
        """`/alerts/{id}` and `/alerts/{alert_id}` are the same route."""
        return re.sub(r"\{[^}]*\}", "{}", path)

    def _text(self) -> str:
        return "\n".join((PROJECT_ROOT / name).read_text(encoding="utf-8")
                          for name in self.DOCS)

    @unittest.skipUnless(PRIVATE_DOCS, PRIVATE_DOCS_SKIP)
    def test_every_api_path_the_documents_name_exists(self):
        """GET /api/suricata/rules outlived its screen and stayed in the table.

        An endpoint nothing calls behaves exactly like one that works, so the
        row went on describing it for as long as anybody cared to read.
        """
        registered = {self._placeholders(getattr(r, "path", ""))
                      for r in main.app.routes}
        named = set(re.findall(r"`(/api/[A-Za-z0-9_/{}|.-]+)`", self._text()))
        self.assertGreater(len(named), 15, "the scan found almost no paths")
        for path in sorted(named):
            # The tables write alternatives as /service/{start|stop}.
            for variant in re.findall(r"[^{|]+|\{[^}]*\}", path) and [path]:
                with self.subTest(path=variant):
                    self.assertIn(self._placeholders(variant), registered)

    @unittest.skipUnless(PRIVATE_DOCS, PRIVATE_DOCS_SKIP)
    def test_every_source_file_the_documents_name_exists(self):
        """`shared/bar-chart.ts` was in the layout listing after it was deleted."""
        pattern = (r"`((?:backend|frontend|deploy|scripts|image|docs)"
                   r"/[A-Za-z0-9_./@-]+)`")
        named = set(re.findall(pattern, self._text()))
        self.assertGreater(len(named), 20, "the scan found almost no files")
        for name in sorted(named):
            if name.endswith("/") or "*" in name or "..." in name:
                continue
            if name in self.EXAMPLES:
                continue
            with self.subTest(file=name):
                self.assertTrue((PROJECT_ROOT / name).exists(),
                                f"{name} is named in the documents and is not there")

    def test_the_scan_would_notice_a_path_that_went_away(self):
        # A scan that reads nothing passes every assertion above it.
        registered = {self._placeholders(getattr(r, "path", ""))
                      for r in main.app.routes}
        self.assertNotIn("/api/suricata/rules", registered)
        self.assertIn("/api/suricata/status", registered)


class BusyButtonTest(BackendTestCase):
    """A button that says it is working also shows it.

    Long actions changed only their label ("Applying...", "Rebuilding
    rules..."), which on a minute-long restart reads as a page that hung. The
    spinner is CSS on [aria-busy="true"]; this keeps every such button on it,
    including the next one somebody adds.
    """

    BUTTON = re.compile(r"<button\b([^>]*)>(.*?)</button>", re.S)
    WORKING = re.compile(r"\{\{\s*(.+?)\s*\?\s*'[^']*\.\.\.'", re.S)

    def buttons(self):
        root = PROJECT_ROOT / "frontend" / "src" / "app"
        for path in sorted(root.rglob("*.html")):
            for attrs, body in self.BUTTON.findall(path.read_text(encoding="utf-8")):
                working = self.WORKING.search(body)
                if working:
                    yield path.relative_to(PROJECT_ROOT), attrs, working.group(1).strip()

    def test_every_working_label_has_its_spinner(self):
        found = list(self.buttons())
        self.assertGreater(len(found), 15, "the scan found almost no buttons")
        for path, attrs, condition in found:
            with self.subTest(file=str(path), condition=condition):
                self.assertIn(f'[attr.aria-busy]="({condition}) || null"', attrs)

    def test_the_spinner_is_styled(self):
        css = (PROJECT_ROOT / "frontend" / "src" / "styles.css").read_text(encoding="utf-8")
        self.assertIn('.btn[aria-busy="true"]::before', css)
        self.assertIn("prefers-reduced-motion", css)


class LicenceTest(BackendTestCase):
    """The public repository needs a licence, or nobody may use the code at all."""

    def test_the_licence_is_the_gpl_version_3(self):
        text = (PROJECT_ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("GNU GENERAL PUBLIC LICENSE", text.splitlines()[0])
        self.assertIn("Version 3, 29 June 2007", text)
        # The text verbatim: a licence edited by hand is a different licence.
        import hashlib
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(),
                         "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986")

    def test_contributions_carry_the_grant_paid_editions_need(self):
        # Under the GPL, code from others can only go into a paid edition with
        # their permission; the grant is what gives it.
        text = (PROJECT_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        self.assertIn("GPL-3.0-or-later", text)
        self.assertIn("including proprietary or\n   commercial ones", text)
        self.assertIn("I agree to the terms in CONTRIBUTING.md.", text)
        self.assertIn("Raspberry Pi is a trademark of Raspberry Pi Ltd", text)

    def test_the_public_export_keeps_it(self):
        # export-public.sh leaves private paths out; the licence is not one.
        script = (PROJECT_ROOT / "scripts" / "export-public.sh").read_text(encoding="utf-8")
        private = re.search(r"^PRIVATE=\((.*?)\)", script, re.M).group(1).split()
        self.assertNotIn("LICENSE", private)
        self.assertNotIn("CONTRIBUTING.md", private)


class TrademarkTest(BackendTestCase):
    """Raspberry Pi's trademark rules, where this project uses the name.

    4(i): every use comes with "Raspberry Pi is a trademark of Raspberry Pi
    Ltd". 4(ii): the name goes with a referential phrase ("for", "runs on").
    3(i): never the name of the product or the repository.
    """

    ACK = "Raspberry Pi is a trademark of Raspberry Pi Ltd"

    @unittest.skipUnless(PRIVATE_DOCS, PRIVATE_DOCS_SKIP)
    def test_the_readme_carries_the_acknowledgement(self):
        text = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(self.ACK, text)

    def test_the_public_readme_carries_the_acknowledgement(self):
        text = (PROJECT_ROOT / "README.en.md").read_text(encoding="utf-8")
        self.assertIn(self.ACK, text)
        # A name, not the mark: the title is the product, the Pi is "for".
        self.assertTrue(text.startswith("# RaPi IDS\n"))

    def test_the_imager_entry_carries_it_and_says_for(self):
        script = (PROJECT_ROOT / "scripts" / "imager-manifest.py").read_text(encoding="utf-8")
        entry = script[script.index('"name": "RaPi IDS"'):]
        entry = entry[:entry.index('"url"')]
        self.assertIn("for Raspberry Pi 5", entry)
        self.assertIn(self.ACK, entry)

    def test_the_product_name_is_not_the_mark(self):
        # 3(i): no "Raspberry" in the product's name at all, whatever follows.
        script = (PROJECT_ROOT / "scripts" / "imager-manifest.py").read_text(encoding="utf-8")
        entry = script[script.index("entry = {"):script.index('"url"')]
        name = re.search(r'"name": "([^"]+)"', entry).group(1)
        self.assertEqual(name, "RaPi IDS")
        self.assertNotIn("Raspberry", name)

    def test_the_panel_does_not_show_the_mark(self):
        """The panel's own texts name the product, not Raspberry Pi.

        The page description said "Raspberry Pi admin panel", the API
        "Modular panel for the Raspberry Pi" and a module "Raspberry Pi
        health": the mark, with no acknowledgement, on every page load.
        """
        shown = [PROJECT_ROOT / "frontend" / "src" / "index.html"]
        shown += sorted((PROJECT_ROOT / "frontend" / "src" / "app").rglob("*.html"))
        found = []
        for path in shown:
            text = re.sub(r"<!--.*?-->", "", path.read_text(encoding="utf-8"), flags=re.S)
            if "Raspberry Pi" in text:
                found.append(str(path.relative_to(PROJECT_ROOT)))
        for path in sorted((PROJECT_ROOT / "backend" / "app").rglob("*.py")):
            for match in re.finditer(r'description="([^"]*)"', path.read_text(encoding="utf-8")):
                if "Raspberry Pi" in match.group(1):
                    found.append(f"{path.relative_to(PROJECT_ROOT)}: {match.group(1)}")
        self.assertEqual(found, [])
