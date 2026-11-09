#!/usr/bin/env python3
"""Tests for hush. Run from the repo root: python3 -m unittest -v test_hush.py"""

import contextlib
import importlib.util
import io
import os
import shlex
import subprocess
import sys
import tempfile
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
# Secrets file parsing
# --------------------------------------------------

class ParserTests(HushTestCase):
    def test_default_label(self):
        self.assertEqual(self.redacted("abc\n", "x abc y"), "x <REDACTED> y")

    def test_section_label(self):
        self.assertEqual(
            self.redacted("[email]\njohn@example.com\n", "to john@example.com"),
            "to <REDACTED-EMAIL>",
        )

    def test_label_uppercased(self):
        self.assertEqual(
            self.redacted("[aws-Account_id]\n123456789012\n", "id 123456789012"),
            "id <REDACTED-AWS-ACCOUNT_ID>",
        )

    def test_redacted_section_resets_label(self):
        self.assertEqual(
            self.redacted("[ip]\n1.2.3.4\n[redacted]\nabc\n", "1.2.3.4 abc"),
            "<REDACTED-IP> <REDACTED>",
        )

    def test_comments_and_blank_lines_ignored(self):
        self.assertEqual(len(self.load("# note\n\n   \nabc\n")), 1)

    def test_equals_inside_secrets(self):
        self.assertEqual(
            self.redacted("dGVzdA==\npass=word\n", "a dGVzdA== b pass=word"),
            "a <REDACTED> b <REDACTED>",
        )

    def test_backslash_escape(self):
        self.assertEqual(
            self.redacted("\\#hash\n\\[x]\n", "#hash [x]"),
            "<REDACTED> <REDACTED>",
        )

    def test_invalid_section_header(self):
        with self.assertRaises(hush.HushError) as ctx:
            self.load("[bad label]\n")
        self.assertIn("line 1", str(ctx.exception))

    def test_errors_never_include_secret_text(self):
        with self.assertRaises(hush.HushError) as ctx:
            self.load("[bad hunter2]\n")
        self.assertNotIn("hunter2", str(ctx.exception))

    def test_duplicates_ignored_with_warning(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            secrets = self.load("abc\nABC\n")
        self.assertEqual(len(secrets), 1)
        self.assertIn("duplicate", stderr.getvalue())
        self.assertNotIn("abc", stderr.getvalue().lower().replace("hush", ""))

    def test_casefold_distinct_secrets_both_kept(self):
        # L1: these are distinct for the regex, so both must be kept.
        self.assertEqual(len(self.load("straße\nSTRASSE\n")), 2)

    def test_empty_file_is_error(self):
        with self.assertRaises(hush.HushError) as ctx:
            self.load("")
        self.assertIn("No secrets defined", str(ctx.exception))

    def test_comments_only_is_error(self):
        with self.assertRaises(hush.HushError):
            self.load("# a\n# b\n")

    def test_bom_is_ignored(self):
        # M3
        content = "\ufeffabc\n".encode("utf-8")
        self.assertEqual(self.redacted(content, "abc"), "<REDACTED>")

    def test_crlf_line_endings(self):
        self.assertEqual(
            self.redacted(b"abc\r\ndef\r\n", "abc def"),
            "<REDACTED> <REDACTED>",
        )

    def test_surrounding_whitespace_stripped(self):
        self.assertEqual(self.load("   abc   \n")[0][0], "abc")


# --------------------------------------------------
# Matching
# --------------------------------------------------

class MatchingTests(HushTestCase):
    def test_case_insensitive(self):
        self.assertEqual(self.redacted("my-secret\n", "MY-SECRET"), "<REDACTED>")

    def test_special_characters_are_literal(self):
        self.assertEqual(
            self.redacted("my.password\n", "myXpassword my.password"),
            "myXpassword <REDACTED>",
        )

    def test_longest_secret_wins(self):
        config = "[a]\nsecret\n[b]\nsecret-key\n"
        self.assertEqual(self.redacted(config, "secret-key"), "<REDACTED-B>")

    def test_ip_not_matched_inside_longer_number(self):
        text = "10.10.10.150 110.10.10.15"
        self.assertEqual(self.redacted("10.10.10.15\n", text), text)

    def test_ip_with_separators(self):
        self.assertEqual(
            self.redacted("10.10.10.15\n", "host=10.10.10.15:8080, (10.10.10.15)."),
            "host=<REDACTED>:8080, (<REDACTED>).",
        )

    def test_account_id_in_arn(self):
        self.assertEqual(
            self.redacted("123456789012\n", "arn:aws:iam::123456789012:role/x"),
            "arn:aws:iam::<REDACTED>:role/x",
        )

    def test_letters_adjacent_still_redacted(self):
        # H1
        self.assertEqual(
            self.redacted("mysecret\n", "mysecretABC xmysecret"),
            "<REDACTED>ABC x<REDACTED>",
        )

    def test_after_json_escape(self):
        # H1
        self.assertEqual(
            self.redacted("mysecret\n", r'"line\nmysecret"'),
            r'"line\n<REDACTED>"',
        )

    def test_after_url_encoding(self):
        # H1
        self.assertEqual(
            self.redacted("mysecret\n", "token%3Dmysecret%26"),
            "token%3D<REDACTED>%26",
        )

    def test_counts(self):
        config = "[email]\na@b.com\n[ip]\n1.2.3.4\n"
        _, counts = self.redact(config, "a@b.com A@B.COM 1.2.3.4")
        self.assertEqual(
            counts, Counter({"<REDACTED-EMAIL>": 2, "<REDACTED-IP>": 1})
        )

    def test_unicode_case_edge_does_not_crash(self):
        result, counts = self.redact("i\n", "İ ı I i")
        self.assertEqual(sum(counts.values()), result.count("<REDACTED>"))

    def test_no_match_leaves_text_unchanged(self):
        result, counts = self.redact("abc\n", "nothing here")
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
        expected.write_text("abc\n")
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.tmp)}):
            os.environ.pop("HUSH_SECRETS_FILE", None)
            self.assertEqual(hush.get_secrets_file(), expected)

    def test_tilde_expanded(self):
        path = self.write_config("abc\n", name="s.txt")
        env = {"HOME": str(self.tmp), "HUSH_SECRETS_FILE": "~/s.txt"}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(hush.get_secrets_file(), path)

    @unittest.skipIf(IS_ROOT, "root can read any file")
    def test_unreadable_file(self):
        path = self.write_config("abc\n", mode=0o000)
        self.addCleanup(path.chmod, 0o600)
        with mock.patch.dict(os.environ, {"HUSH_SECRETS_FILE": str(path)}):
            with self.assertRaises(hush.HushError) as ctx:
                hush.load_secrets()
        self.assertIn("Unable to read", str(ctx.exception))

    @unittest.skipIf(IS_ROOT, "root can read any directory")
    def test_inaccessible_parent_directory(self):
        # M1: must be a clean HushError, not a PermissionError traceback.
        locked = self.tmp / "locked"
        locked.mkdir()
        (locked / "secrets.txt").write_text("abc\n")
        locked.chmod(0o000)
        self.addCleanup(locked.chmod, 0o700)
        target = str(locked / "secrets.txt")
        with mock.patch.dict(os.environ, {"HUSH_SECRETS_FILE": target}):
            with self.assertRaises(hush.HushError):
                hush.get_secrets_file()

    def test_exposed_file_warning(self):
        path = self.write_config("abc\n", mode=0o644)
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
        config = self.write_config("[email]\njohn@example.com\n[ip]\n10.10.10.15\n")
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

        config = self.write_config("[email]\njohn@example.com\n")
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
        # M2: the copy lands shortly after wl-copy returns.
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


if __name__ == "__main__":
    unittest.main()

