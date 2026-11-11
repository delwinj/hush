#!/usr/bin/env python3
"""Tests for hush. Run from the repo root: python3 -m unittest -v test_hush.py"""

import contextlib
import importlib.util
import io
import os
import re
import select
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parent / "hush.py"

_spec = importlib.util.spec_from_file_location("hush", SCRIPT)
hush = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(hush)

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
SYSTEM_PATH = "/usr/bin:/bin"


class HushTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.empty_bin = self.tmp / "empty-bin"
        self.empty_bin.mkdir()

    def write_config(self, content, name="secrets.txt", mode=0o600):
        path = self.tmp / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        path.chmod(mode)
        return path

    def load(self, content):
        path = self.write_config(content)
        with mock.patch.dict(os.environ, {"HUSH_SECRETS_FILE": str(path)}):
            return hush.load_secrets()

    def redact(self, content, text):
        secrets = self.load(content)
        return hush.redact(text, secrets, hush.build_pattern(secrets))

    def redacted(self, content, text):
        return self.redact(content, text)[0]

    def run_cli(self, args=(), input=b"", env=None):
        full_env = {"HOME": str(self.tmp), "PATH": str(self.empty_bin)}
        full_env.update(env or {})
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            input=input,
            capture_output=True,
            env=full_env,
            timeout=20,
        )


# --------------------------------------------------
# Secrets file format
# --------------------------------------------------

class FormatTests(HushTestCase):
    def test_redacted_label(self):
        self.assertEqual(
            self.redacted("redacted: abc\n", "x abc y"), "x <REDACTED> y"
        )

    def test_custom_label(self):
        self.assertEqual(
            self.redacted("email: john@example.com\n", "to john@example.com"),
            "to <REDACTED-EMAIL>",
        )

    def test_label_case_insensitive(self):
        self.assertEqual(
            self.redacted("Aws-Account_id: 123456789012\n", "id 123456789012"),
            "id <REDACTED-AWS-ACCOUNT_ID>",
        )

    def test_redacted_label_any_case(self):
        self.assertEqual(self.redacted("REDACTED: abc\n", "abc"), "<REDACTED>")

    def test_comments_and_blank_lines_ignored(self):
        content = "# note\n\n   \n   # indented comment\nredacted: abc\n"
        self.assertEqual(len(self.load(content)), 1)

    def test_colons_and_equals_in_secret(self):
        content = "password: pass=word:with:colons\nredacted: dGVzdA==\n"
        self.assertEqual(
            self.redacted(content, "a pass=word:with:colons b dGVzdA=="),
            "a <REDACTED-PASSWORD> b <REDACTED>",
        )

    def test_no_escaping_needed(self):
        content = "redacted: #hash\nredacted: [x]\nredacted: \\back\n"
        self.assertEqual(
            self.redacted(content, "#hash [x] \\back"),
            "<REDACTED> <REDACTED> <REDACTED>",
        )

    def test_whitespace_after_colon_flexible(self):
        self.assertEqual(
            self.redacted("email:\t   john@example.com\n", "john@example.com"),
            "<REDACTED-EMAIL>",
        )

    def test_line_whitespace_stripped(self):
        self.assertEqual(self.load("   redacted: abc   \n")[0][0], "abc")

    def test_tab_inside_secret(self):
        self.assertEqual(
            self.redacted("redacted: abc\tdef\n", "abc\tdef"), "<REDACTED>"
        )

    def test_missing_space_after_colon(self):
        with self.assertRaises(hush.HushError) as ctx:
            self.load("user:password\n")
        self.assertIn("line 1", str(ctx.exception))

    def test_missing_label(self):
        with self.assertRaises(hush.HushError):
            self.load("AKIAIOSFODNN7EXAMPLE\n")

    def test_empty_secret(self):
        for content in ("email:\n", "email:    \n"):
            with self.assertRaises(hush.HushError):
                self.load(content)

    def test_invalid_label(self):
        for content in ("my label: secret\n", "e.mail: secret\n"):
            with self.assertRaises(hush.HushError):
                self.load(content)

    def test_old_section_header_hint(self):
        with self.assertRaises(hush.HushError) as ctx:
            self.load("[email]\njohn@example.com\n")
        self.assertIn("Section headers are no longer supported", str(ctx.exception))

    def test_errors_never_include_line_content(self):
        for content in ("user:zq7hunter2\n", "[zq7hunter2]\n", "zq7hunter2\n"):
            with self.assertRaises(hush.HushError) as ctx:
                self.load(content)
            self.assertNotIn("zq7hunter2", str(ctx.exception))

    def test_duplicates_ignored_with_warning(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            secrets = self.load("redacted: zq7secret\nemail: ZQ7SECRET\n")
        self.assertEqual(len(secrets), 1)
        self.assertIn("duplicate", stderr.getvalue())
        self.assertNotIn("zq7secret", stderr.getvalue().lower())

    def test_case_distinct_secrets_both_kept(self):
        self.assertEqual(len(self.load("redacted: straße\nredacted: STRASSE\n")), 2)

    def test_empty_file_is_error(self):
        with self.assertRaises(hush.HushError) as ctx:
            self.load("")
        self.assertIn("No secrets defined", str(ctx.exception))

    def test_comments_only_is_error(self):
        with self.assertRaises(hush.HushError):
            self.load("# a\n# b\n")

    def test_bom_is_ignored(self):
        content = "\ufeffredacted: abc\n".encode("utf-8")
        self.assertEqual(self.redacted(content, "abc"), "<REDACTED>")

    def test_crlf_line_endings(self):
        self.assertEqual(
            self.redacted(b"redacted: abc\r\nredacted: def\r\n", "abc def"),
            "<REDACTED> <REDACTED>",
        )


# --------------------------------------------------
# Matching
# --------------------------------------------------

class MatchingTests(HushTestCase):
    def test_case_insensitive(self):
        self.assertEqual(
            self.redacted("redacted: my-secret\n", "MY-SECRET"), "<REDACTED>"
        )

    def test_special_characters_are_literal(self):
        self.assertEqual(
            self.redacted("redacted: my.password\n", "myXpassword my.password"),
            "myXpassword <REDACTED>",
        )

    def test_longest_secret_wins(self):
        content = "a: secret\nb: secret-key\n"
        self.assertEqual(self.redacted(content, "secret-key"), "<REDACTED-B>")

    def test_ip_not_matched_inside_longer_number(self):
        text = "10.10.10.150 110.10.10.15"
        self.assertEqual(self.redacted("ip: 10.10.10.15\n", text), text)

    def test_ip_with_separators(self):
        self.assertEqual(
            self.redacted(
                "ip: 10.10.10.15\n", "host=10.10.10.15:8080, (10.10.10.15)."
            ),
            "host=<REDACTED-IP>:8080, (<REDACTED-IP>).",
        )

    def test_account_id_in_arn(self):
        self.assertEqual(
            self.redacted(
                "redacted: 123456789012\n", "arn:aws:iam::123456789012:role/x"
            ),
            "arn:aws:iam::<REDACTED>:role/x",
        )

    def test_letters_adjacent_still_redacted(self):
        self.assertEqual(
            self.redacted("redacted: mysecret\n", "mysecretABC xmysecret"),
            "<REDACTED>ABC x<REDACTED>",
        )

    def test_after_json_escape(self):
        self.assertEqual(
            self.redacted("redacted: mysecret\n", r'"line\nmysecret"'),
            r'"line\n<REDACTED>"',
        )

    def test_after_url_encoding(self):
        self.assertEqual(
            self.redacted("redacted: mysecret\n", "token%3Dmysecret%26"),
            "token%3D<REDACTED>%26",
        )

    def test_counts(self):
        content = "email: a@b.com\nip: 1.2.3.4\n"
        _, counts = self.redact(content, "a@b.com A@B.COM 1.2.3.4")
        self.assertEqual(
            counts, Counter({"<REDACTED-EMAIL>": 2, "<REDACTED-IP>": 1})
        )

    def test_unicode_case_edge_does_not_crash(self):
        result, counts = self.redact("redacted: i\n", "İ ı I i")
        self.assertEqual(sum(counts.values()), result.count("<REDACTED>"))

    def test_no_match_leaves_text_unchanged(self):
        result, counts = self.redact("redacted: abc\n", "nothing here")
        self.assertEqual(result, "nothing here")
        self.assertFalse(counts)


# --------------------------------------------------
# Secrets file location and access
# --------------------------------------------------

class LocationTests(HushTestCase):
    def test_env_file_missing(self):
        missing = self.tmp / "nope.txt"
        with mock.patch.dict(os.environ, {"HUSH_SECRETS_FILE": str(missing)}):
            with self.assertRaises(hush.HushError) as ctx:
                hush.get_secrets_file()
        self.assertIn("HUSH_SECRETS_FILE", str(ctx.exception))
        self.assertIn(str(missing), str(ctx.exception))

    def test_env_empty(self):
        with mock.patch.dict(os.environ, {"HUSH_SECRETS_FILE": "  "}):
            with self.assertRaises(hush.HushError) as ctx:
                hush.get_secrets_file()
        self.assertIn("set but empty", str(ctx.exception))

    def test_env_points_to_directory(self):
        with mock.patch.dict(os.environ, {"HUSH_SECRETS_FILE": str(self.tmp)}):
            with self.assertRaises(hush.HushError) as ctx:
                hush.get_secrets_file()
        self.assertIn("not a regular file", str(ctx.exception))

    def test_default_missing(self):
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.tmp)}):
            os.environ.pop("HUSH_SECRETS_FILE", None)
            with self.assertRaises(hush.HushError) as ctx:
                hush.get_secrets_file()
        message = str(ctx.exception)
        self.assertIn("default location", message)
        self.assertIn(str(self.tmp / "hush" / "secrets.txt"), message)

    def test_default_found(self):
        expected = self.tmp / "hush" / "secrets.txt"
        expected.parent.mkdir()
        expected.write_text("redacted: abc\n")
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.tmp)}):
            os.environ.pop("HUSH_SECRETS_FILE", None)
            self.assertEqual(hush.get_secrets_file(), expected)

    def test_tilde_expanded(self):
        path = self.write_config("redacted: abc\n", name="s.txt")
        env = {"HOME": str(self.tmp), "HUSH_SECRETS_FILE": "~/s.txt"}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(hush.get_secrets_file(), path)

    @unittest.skipIf(IS_ROOT, "root can read any file")
    def test_unreadable_file(self):
        path = self.write_config("redacted: abc\n", mode=0o000)
        self.addCleanup(path.chmod, 0o600)
        with mock.patch.dict(os.environ, {"HUSH_SECRETS_FILE": str(path)}):
            with self.assertRaises(hush.HushError) as ctx:
                hush.load_secrets()
        self.assertIn("Unable to read", str(ctx.exception))

    @unittest.skipIf(IS_ROOT, "root can read any directory")
    def test_inaccessible_parent_directory(self):
        locked = self.tmp / "locked"
        locked.mkdir()
        (locked / "secrets.txt").write_text("redacted: abc\n")
        locked.chmod(0o000)
        self.addCleanup(locked.chmod, 0o700)
        target = str(locked / "secrets.txt")
        with mock.patch.dict(os.environ, {"HUSH_SECRETS_FILE": target}):
            with self.assertRaises(hush.HushError):
                hush.get_secrets_file()

    def test_exposed_file_warning(self):
        path = self.write_config("redacted: abc\n", mode=0o644)
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"HUSH_SECRETS_FILE": str(path)}):
            with contextlib.redirect_stderr(stderr):
                hush.load_secrets()
        self.assertIn("accessible by other users", stderr.getvalue())


# --------------------------------------------------
# Command line: pipe mode
# --------------------------------------------------

class PipeCliTests(HushTestCase):
    def setUp(self):
        super().setUp()
        config = self.write_config("email: john@example.com\nip: 10.10.10.15\n")
        self.env = {"HUSH_SECRETS_FILE": str(config)}

    def test_redacts_stdin(self):
        proc = self.run_cli(
            input=b"Contact JOHN@example.com at 10.10.10.15\n", env=self.env
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(
            proc.stdout, b"Contact <REDACTED-EMAIL> at <REDACTED-IP>\n"
        )
        self.assertIn(b"redacted 2:", proc.stderr)

    def test_quiet(self):
        proc = self.run_cli(["-q"], input=b"john@example.com", env=self.env)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, b"")

    def test_no_match_message(self):
        proc = self.run_cli(input=b"nothing", env=self.env)
        self.assertEqual(proc.stdout, b"nothing")
        self.assertIn(b"no configured secrets found", proc.stderr)

    def test_config_error_outputs_nothing(self):
        env = {"HUSH_SECRETS_FILE": str(self.tmp / "nope.txt")}
        proc = self.run_cli(input=b"john@example.com\n", env=env)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"Secrets file not found (HUSH_SECRETS_FILE)", proc.stderr)
        self.assertIn(str(self.tmp / "nope.txt").encode(), proc.stderr)

    def test_invalid_file_outputs_nothing(self):
        config = self.write_config("[email]\njohn@example.com\n", name="old.txt")
        proc = self.run_cli(
            input=b"john@example.com\n", env={"HUSH_SECRETS_FILE": str(config)}
        )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, b"")

    def test_non_utf8_passes_through(self):
        proc = self.run_cli(input=b"\xff\xfe john@example.com\n", env=self.env)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"\xff\xfe <REDACTED-EMAIL>\n")

    def test_tty_stdin_rejected(self):
        master, slave = os.openpty()
        try:
            proc = subprocess.run(
                [sys.executable, str(SCRIPT)],
                stdin=slave,
                capture_output=True,
                env={"HOME": str(self.tmp), **self.env},
                timeout=20,
            )
        finally:
            os.close(master)
            os.close(slave)
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"no input piped", proc.stderr)

    def test_preview_requires_clipboard(self):
        proc = self.run_cli(["-p"], input=b"x", env=self.env)
        self.assertEqual(proc.returncode, 2)

    def test_version(self):
        proc = self.run_cli(["--version"])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, f"hush {hush.VERSION}\n".encode())

    def test_help_mentions_add(self):
        proc = self.run_cli(["--help"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn(b"hush add", proc.stdout)

    def test_broken_pipe_is_quiet(self):
        cmd = (
            f"{shlex.quote(sys.executable)} {shlex.quote(str(SCRIPT))} -q"
            " | head -c 1 > /dev/null"
        )
        proc = subprocess.run(
            cmd,
            shell=True,
            input=b"a" * 300_000,
            capture_output=True,
            env={**os.environ, **self.env},
            timeout=20,
        )
        self.assertNotIn(b"Traceback", proc.stderr)


# --------------------------------------------------
# Command line: clipboard mode (with fake clipboard tools)
# --------------------------------------------------

FAKE_WL_PASTE = """#!/bin/sh
[ -s "$FAKE_CLIP" ] || { echo "Nothing is copied" >&2; exit 1; }
cat "$FAKE_CLIP"
"""

FAKE_WL_COPY = """#!/bin/sh
touch "$FAKE_CLIP.written"
cat > "$FAKE_CLIP"
"""

FAKE_XCLIP = """#!/bin/sh
for arg in "$@"; do
    if [ "$arg" = "-o" ]; then
        [ -s "$FAKE_CLIP" ] || exit 1
        cat "$FAKE_CLIP"
        exit 0
    fi
done
touch "$FAKE_CLIP.written"
cat > "$FAKE_CLIP"
"""


class ClipboardCliTests(HushTestCase):
    ORIGINAL = b"Contact john@example.com\n"
    REDACTED = b"Contact <REDACTED-EMAIL>\n"

    def setUp(self):
        super().setUp()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.make_tool("wl-paste", FAKE_WL_PASTE)
        self.make_tool("wl-copy", FAKE_WL_COPY)
        self.make_tool("xclip", FAKE_XCLIP)

        self.clip = self.tmp / "clip"
        self.clip.write_bytes(self.ORIGINAL)
        self.written_marker = Path(f"{self.clip}.written")

        config = self.write_config("email: john@example.com\n")
        self.env = {
            "PATH": f"{self.bin}:{SYSTEM_PATH}",
            "WAYLAND_DISPLAY": "fake-wayland",
            "FAKE_CLIP": str(self.clip),
            "HUSH_SECRETS_FILE": str(config),
        }

    def make_tool(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def test_redacts_clipboard_in_place(self):
        proc = self.run_cli(["-c"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.clip.read_bytes(), self.REDACTED)
        self.assertIn(b"redacted 1:", proc.stderr)

    def test_preview_does_not_modify(self):
        proc = self.run_cli(["-c", "-p"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, self.REDACTED)
        self.assertEqual(self.clip.read_bytes(), self.ORIGINAL)
        self.assertFalse(self.written_marker.exists())
        self.assertIn(b"NOT modified", proc.stderr)

    def test_no_match_does_not_write(self):
        self.clip.write_bytes(b"nothing secret")
        proc = self.run_cli(["-c"], env=self.env)
        self.assertEqual(proc.returncode, 0)
        self.assertFalse(self.written_marker.exists())
        self.assertIn(b"no configured secrets found", proc.stderr)

    def test_empty_clipboard_is_error(self):
        self.clip.write_bytes(b"")
        proc = self.run_cli(["-c"], env=self.env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"Unable to read clipboard", proc.stderr)

    def test_wl_clipboard_missing(self):
        env = {**self.env, "PATH": str(self.empty_bin)}
        proc = self.run_cli(["-c"], env=env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"wl-clipboard is not installed", proc.stderr)

    def test_no_graphical_session(self):
        env = {k: v for k, v in self.env.items() if k != "WAYLAND_DISPLAY"}
        proc = self.run_cli(["-c"], env=env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"No graphical session", proc.stderr)

    def test_x11_path(self):
        env = {k: v for k, v in self.env.items() if k != "WAYLAND_DISPLAY"}
        env["DISPLAY"] = ":99"
        proc = self.run_cli(["-c"], env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.clip.read_bytes(), self.REDACTED)

    def test_verification_failure(self):
        self.make_tool(
            "wl-copy", '#!/bin/sh\ncat > /dev/null\nprintf tampered > "$FAKE_CLIP"\n'
        )
        proc = self.run_cli(["-c"], env=self.env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"verification failed", proc.stderr)

    def test_delayed_write_passes_verification(self):
        self.make_tool(
            "wl-copy",
            '#!/bin/sh\ntmp="$FAKE_CLIP.tmp"\ncat > "$tmp"\n'
            '( sleep 0.15; mv "$tmp" "$FAKE_CLIP" ) >/dev/null 2>&1 &\n',
        )
        proc = self.run_cli(["-c"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.clip.read_bytes(), self.REDACTED)

    def test_config_error_leaves_clipboard(self):
        env = {**self.env, "HUSH_SECRETS_FILE": str(self.tmp / "nope.txt")}
        proc = self.run_cli(["-c"], env=env)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.clip.read_bytes(), self.ORIGINAL)
        self.assertFalse(self.written_marker.exists())


# --------------------------------------------------
# hush add
# --------------------------------------------------

class AddTests(HushTestCase):
    INITIAL = "# my secrets\nemail: john@example.com\n"

    def setUp(self):
        super().setUp()
        self.config = self.write_config(self.INITIAL)
        self.env = {"HUSH_SECRETS_FILE": str(self.config)}

    def add(self, data, *args, env=None):
        return self.run_cli(["add", *args], input=data, env=env or self.env)

    def lines(self):
        return self.config.read_text().splitlines()

    def assert_unchanged(self):
        self.assertEqual(self.config.read_text(), self.INITIAL)

    def test_default_label(self):
        proc = self.add(b"newsecret123\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            self.lines(),
            ["# my secrets", "email: john@example.com", "redacted: newsecret123"],
        )
        self.assertIn(b"added 1 secret as <REDACTED>", proc.stderr)

    def test_custom_label_and_redaction(self):
        proc = self.add(b"newsecret123\n", "-l", "Password")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.lines()[-1], "password: newsecret123")
        redact = self.run_cli(input=b"pw newsecret123", env=self.env)
        self.assertEqual(redact.stdout, b"pw <REDACTED-PASSWORD>")

    def test_note_with_date(self):
        proc = self.add(b"newsecret123\n", "--note", "SAA lab: alice")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = self.lines()
        self.assertEqual(lines[2], "")
        self.assertRegex(lines[3], r"^# \d{4}-\d{2}-\d{2}: SAA lab: alice$")
        self.assertEqual(lines[4], "redacted: newsecret123")

    def test_note_must_be_single_line(self):
        proc = self.add(b"newsecret123\n", "--note", "a\nb")
        self.assertEqual(proc.returncode, 2)
        self.assert_unchanged()

    def test_empty_note_rejected(self):
        proc = self.add(b"newsecret123\n", "--note", "   ")
        self.assertEqual(proc.returncode, 2)
        self.assert_unchanged()

    def test_tab_separated_values_split(self):
        data = b"AKIAEXAMPLEKEYID1234\twJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        proc = self.add(data)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            self.lines()[-2:],
            [
                "redacted: AKIAEXAMPLEKEYID1234",
                "redacted: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            ],
        )

    def test_no_split_keeps_line_whole(self):
        proc = self.add(b"firstpart\tsecondpart\n", "--no-split")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.lines()[-1], "redacted: firstpart\tsecondpart")
        redact = self.run_cli(input=b"firstpart\tsecondpart", env=self.env)
        self.assertEqual(redact.stdout, b"<REDACTED>")

    def test_multiple_lines(self):
        proc = self.add(b"secretone1\nsecrettwo2\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            self.lines()[-2:], ["redacted: secretone1", "redacted: secrettwo2"]
        )

    def test_blank_lines_ignored(self):
        proc = self.add(b"\n   \nsecretone1\n\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.lines()[-1], "redacted: secretone1")

    def test_empty_input_is_error(self):
        for data in (b"", b"\n\n", b"   \n"):
            proc = self.add(data)
            self.assertEqual(proc.returncode, 1)
            self.assertIn(b"No secret provided", proc.stderr)
            self.assert_unchanged()

    def test_short_secret_rejected(self):
        proc = self.add(b"abc\n")
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"--allow-short", proc.stderr)
        self.assert_unchanged()

    def test_allow_short(self):
        proc = self.add(b"abc\n", "--allow-short")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.lines()[-1], "redacted: abc")

    def test_surrounding_whitespace_rejected(self):
        for data in (b" padded-secret\n", b"padded-secret \n"):
            proc = self.add(data)
            self.assertEqual(proc.returncode, 1)
            self.assertIn(b"whitespace", proc.stderr)
            self.assert_unchanged()

    def test_all_or_nothing(self):
        proc = self.add(b"goodsecret1\nabc\n")
        self.assertEqual(proc.returncode, 1)
        self.assert_unchanged()

    def test_duplicate_of_existing_skipped(self):
        proc = self.add(b"JOHN@example.com\n")
        self.assertEqual(proc.returncode, 0)
        self.assertIn(b"already present", proc.stderr)
        self.assert_unchanged()

    def test_duplicate_within_input(self):
        proc = self.add(b"secretone1\nSECRETONE1\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.lines()[-1], "redacted: secretone1")
        self.assertEqual(len(self.lines()), 3)
        self.assertIn(b"1 already present", proc.stderr)

    def test_invalid_label(self):
        for label in ("bad label", "e.mail", ""):
            proc = self.add(b"newsecret123\n", "-l", label)
            self.assertEqual(proc.returncode, 2)
            self.assert_unchanged()

    def test_non_utf8_input(self):
        proc = self.add(b"\xff\xfeabcdefg\n")
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"not valid UTF-8", proc.stderr)
        self.assert_unchanged()

    def test_file_without_trailing_newline(self):
        self.config.write_text("email: john@example.com")
        proc = self.add(b"newsecret123\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            self.lines(), ["email: john@example.com", "redacted: newsecret123"]
        )

    def test_file_with_only_comments(self):
        self.config.write_text("# nothing yet\n")
        proc = self.add(b"newsecret123\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        redact = self.run_cli(input=b"newsecret123", env=self.env)
        self.assertEqual(redact.stdout, b"<REDACTED>")

    def test_invalid_file_refused(self):
        self.config.write_text("user:password\n")
        proc = self.add(b"newsecret123\n")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.config.read_text(), "user:password\n")

    def test_old_format_file_refused(self):
        self.config.write_text("[email]\njohn@example.com\n")
        proc = self.add(b"newsecret123\n")
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"Section headers are no longer supported", proc.stderr)

    def test_missing_file(self):
        env = {"HUSH_SECRETS_FILE": str(self.tmp / "nope.txt")}
        proc = self.add(b"newsecret123\n", env=env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"Secrets file not found", proc.stderr)
        self.assertFalse((self.tmp / "nope.txt").exists())

    def test_file_mode_becomes_600(self):
        self.config.chmod(0o644)
        proc = self.add(b"newsecret123\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_symlink_preserved(self):
        real = self.write_config("email: john@example.com\n", name="real.txt")
        link = self.tmp / "link.txt"
        link.symlink_to(real)
        proc = self.add(b"newsecret123\n", env={"HUSH_SECRETS_FILE": str(link)})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(link.is_symlink())
        self.assertIn("redacted: newsecret123", real.read_text())

    def test_no_temporary_files_left(self):
        self.add(b"newsecret123\n")
        leftovers = [p.name for p in self.tmp.iterdir() if p.name.startswith(".hush-")]
        self.assertEqual(leftovers, [])

    def test_never_prints_secrets(self):
        cases = [
            ([], b"zq7leak001\n"),             # added
            ([], b"zq7leak001\n"),             # duplicate
            ([], b"zq7\n"),                    # too short
            ([], b" zq7leak002\n"),            # whitespace
            (["-l", "email"], b"zq7leak003\n"),
            (["--note", "lab"], b"zq7leak004\tzq7leak005\n"),
        ]
        for args, data in cases:
            proc = self.add(data, *args)
            for secret in data.split():
                self.assertNotIn(secret, proc.stdout + proc.stderr)

    def test_interactive_prompt(self):
        master, slave = os.openpty()
        try:
            proc = subprocess.Popen(
                [sys.executable, str(SCRIPT), "add"],
                stdin=slave,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"HOME": str(self.tmp), **self.env},
                # No controlling terminal, so the prompt uses the pty
                # instead of the terminal running the tests.
                start_new_session=True,
            )

            # Wait for the prompt before typing: getpass discards input
            # that arrives before it switches off echo.
            stderr = b""
            deadline = time.monotonic() + 10
            while b"Secret" not in stderr:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    proc.kill()
                    self.fail("prompt not shown")
                ready, _, _ = select.select([proc.stderr], [], [], remaining)
                if ready:
                    chunk = os.read(proc.stderr.fileno(), 1024)
                    if not chunk:
                        break
                    stderr += chunk

            os.write(master, b"promptedsecret1\n")
            stdout, rest = proc.communicate(timeout=20)
            stderr += rest
        finally:
            os.close(master)
            os.close(slave)

        self.assertEqual(proc.returncode, 0, stderr)
        self.assertEqual(self.lines()[-1], "redacted: promptedsecret1")
        self.assertNotIn(b"promptedsecret1", stdout + stderr)


if __name__ == "__main__":
    unittest.main()
