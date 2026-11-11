#!/usr/bin/env python3
"""Tests for hush. Run from the repo root: python3 -m unittest -v test_hush.py"""

import contextlib
import importlib.util
import io
import os
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


def read_until(stream, marker, timeout=10):
    """Read from a pipe until marker appears, without waiting for EOF."""
    data = b""
    deadline = time.monotonic() + timeout
    while marker not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return data
        ready, _, _ = select.select([stream], [], [], remaining)
        if ready:
            chunk = os.read(stream.fileno(), 1024)
            if not chunk:
                return data
            data += chunk
    return data


class HushTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.empty_bin = self.tmp / "empty-bin"
        self.empty_bin.mkdir()
        self.global_file = self.tmp / "config" / "hush" / "secrets.txt"

    def base_env(self, **extra):
        # Built from scratch, so nothing from the real environment leaks in.
        env = {"HOME": str(self.tmp), "XDG_CONFIG_HOME": str(self.tmp / "config")}
        env.update(extra)
        return env

    def write_file(self, path, content, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        path.chmod(mode)
        return path

    def write_global(self, content, mode=0o600):
        return self.write_file(self.global_file, content, mode)

    def write_extra(self, name, content, mode=0o600):
        return self.write_file(self.tmp / name, content, mode)

    def load(self, content=None, no_global=False, **env):
        if content is not None:
            self.write_global(content)
        with mock.patch.dict(os.environ, self.base_env(**env), clear=True):
            return hush.load_secrets(no_global=no_global)

    def redact(self, content, text):
        secrets = self.load(content)
        return hush.redact(text, secrets, hush.build_pattern(secrets))

    def redacted(self, content, text):
        return self.redact(content, text)[0]

    def cli_env(self, env):
        full_env = self.base_env(PATH=str(self.empty_bin))
        full_env.update(env or {})
        return full_env

    def run_cli(self, args=(), input=b"", env=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            input=input,
            capture_output=True,
            env=self.cli_env(env),
            timeout=20,
        )

    def run_cli_tty_stdout(self, args=(), input=b"", env=None):
        """Run hush with stdout on a pseudo-terminal; returns stderr."""
        master, slave = os.openpty()
        try:
            return subprocess.run(
                [sys.executable, str(SCRIPT), *args],
                input=input,
                stdout=slave,
                stderr=subprocess.PIPE,
                env=self.cli_env(env),
                timeout=20,
            )
        finally:
            os.close(slave)
            os.close(master)


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

    def test_section_header_rejected(self):
        with self.assertRaises(hush.HushError) as ctx:
            self.load("[email]\njohn@example.com\n")
        self.assertIn("Expected 'label: secret'", str(ctx.exception))

    def test_errors_never_include_line_content(self):
        for content in ("user:zq7hunter2\n", "[zq7hunter2]\n", "zq7hunter2\n"):
            with self.assertRaises(hush.HushError) as ctx:
                self.load(content)
            self.assertNotIn("zq7hunter2", str(ctx.exception))

    def test_duplicate_in_file_last_wins_with_warning(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            secrets = self.load("redacted: zq7secret\nemail: ZQ7SECRET\n")
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0][1], "<REDACTED-EMAIL>")
        self.assertIn("duplicate", stderr.getvalue())
        self.assertNotIn("zq7secret", stderr.getvalue().lower())

    def test_duplicate_in_file_same_label_still_warns(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.load("redacted: abcdef\nredacted: ABCDEF\n")
        self.assertIn("duplicate", stderr.getvalue())

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
# Which files are loaded
# --------------------------------------------------

class FilesTests(HushTestCase):
    def setUp(self):
        super().setUp()
        self.write_global("redacted: abcdef\n")
        self.a = self.write_extra("a.txt", "redacted: aaa111\n")
        self.b = self.write_extra("b.txt", "redacted: bbb222\n")

    def files(self, value=None, no_global=False, **env):
        if value is not None:
            env["HUSH_SECRETS_FILES"] = value
        with mock.patch.dict(os.environ, self.base_env(**env), clear=True):
            return hush.secrets_files(no_global)

    def assert_error(self, expected, value=None, no_global=False, **env):
        with self.assertRaises(hush.HushError) as ctx:
            self.files(value, no_global, **env)
        self.assertIn(expected, str(ctx.exception))
        return str(ctx.exception)

    def test_global_only(self):
        self.assertEqual(self.files(), [self.global_file])

    def test_global_missing(self):
        self.global_file.unlink()
        message = self.assert_error("Secrets file not found (global)")
        self.assertIn(str(self.global_file), message)

    def test_global_without_xdg_uses_home_config(self):
        with mock.patch.dict(os.environ, {"HOME": str(self.tmp)}, clear=True):
            self.assertEqual(
                hush.global_secrets_file(),
                self.tmp / ".config" / "hush" / "secrets.txt",
            )

    def test_load_order(self):
        self.assertEqual(
            self.files(f"{self.a}:{self.b}"), [self.global_file, self.a, self.b]
        )

    def test_global_listed_in_variable_is_ignored(self):
        self.assertEqual(
            self.files(f"{self.b}:{self.global_file}:{self.a}"),
            [self.global_file, self.b, self.a],
        )

    def test_repeated_entry_loads_at_first_position(self):
        self.assertEqual(
            self.files(f"{self.a}:{self.b}:{self.a}"),
            [self.global_file, self.a, self.b],
        )

    def test_symlink_to_listed_file_loads_once(self):
        link = self.tmp / "link.txt"
        link.symlink_to(self.a)
        self.assertEqual(
            self.files(f"{self.a}:{link}"), [self.global_file, self.a]
        )

    def test_tilde_expanded(self):
        self.assertEqual(self.files("~/a.txt"), [self.global_file, self.a])

    def test_whitespace_around_entries(self):
        self.assertEqual(
            self.files(f" {self.a} : {self.b} "),
            [self.global_file, self.a, self.b],
        )

    def test_relative_entry_rejected(self):
        self.assert_error("absolute", "a.txt")

    def test_unexpanded_variable_rejected(self):
        self.assert_error("absolute", "$HOME/a.txt")

    def test_empty_entry_rejected(self):
        for value in (f"{self.a}::{self.b}", f"{self.a}:", f":{self.a}"):
            self.assert_error("empty entry", value)

    def test_empty_variable_rejected(self):
        self.assert_error("set but empty", "   ")

    def test_missing_listed_file(self):
        missing = self.tmp / "nope.txt"
        message = self.assert_error(
            "Secrets file not found (HUSH_SECRETS_FILES)", str(missing)
        )
        self.assertIn(str(missing), message)

    def test_listed_directory(self):
        self.assert_error("not a regular file", str(self.tmp))

    def test_no_global(self):
        self.global_file.unlink()
        self.assertEqual(self.files(str(self.a), no_global=True), [self.a])

    def test_no_global_with_global_listed(self):
        self.assertEqual(
            self.files(f"{self.a}:{self.global_file}", no_global=True),
            [self.a, self.global_file],
        )

    def test_no_global_without_variable(self):
        self.assert_error("--no-global", no_global=True)

    def test_old_variable_ignored(self):
        self.assertEqual(
            self.files(HUSH_SECRETS_FILE=str(self.tmp / "nope.txt")),
            [self.global_file],
        )

    @unittest.skipIf(IS_ROOT, "root can read any file")
    def test_unreadable_listed_file(self):
        locked = self.write_extra("locked.txt", "redacted: abcdef\n", mode=0o000)
        self.addCleanup(locked.chmod, 0o600)
        with self.assertRaises(hush.HushError) as ctx:
            self.load(HUSH_SECRETS_FILES=str(locked))
        self.assertIn("Unable to read", str(ctx.exception))

    @unittest.skipIf(IS_ROOT, "root can read any directory")
    def test_inaccessible_parent_directory(self):
        locked = self.tmp / "locked"
        locked.mkdir()
        (locked / "s.txt").write_text("redacted: abcdef\n")
        locked.chmod(0o000)
        self.addCleanup(locked.chmod, 0o700)
        with self.assertRaises(hush.HushError):
            self.files(str(locked / "s.txt"))

    def test_exposed_file_warning(self):
        self.global_file.chmod(0o644)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.load()
        self.assertIn("accessible by other users", stderr.getvalue())

    def test_empty_listed_file_allowed(self):
        empty = self.write_extra("empty.txt", "# nothing yet\n")
        self.assertEqual(len(self.load(HUSH_SECRETS_FILES=str(empty))), 1)

    def test_all_files_empty_is_error(self):
        self.write_global("# nothing\n")
        empty = self.write_extra("empty.txt", "")
        with self.assertRaises(hush.HushError) as ctx:
            self.load(HUSH_SECRETS_FILES=str(empty))
        self.assertIn("No secrets defined in any", str(ctx.exception))


# --------------------------------------------------
# Duplicates across files
# --------------------------------------------------

class OverrideTests(HushTestCase):
    def load_files(self, global_content, *extras, order=None):
        self.write_global(global_content)
        paths = [
            self.write_extra(f"extra{i}.txt", content)
            for i, content in enumerate(extras)
        ]
        if order is not None:
            paths = [paths[i] for i in order]
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            secrets = self.load(HUSH_SECRETS_FILES=":".join(map(str, paths)))
        return dict(secrets), stderr.getvalue()

    def test_later_file_overrides(self):
        secrets, stderr = self.load_files(
            "redacted: 123456789012\n", "aws-account-id: 123456789012\n"
        )
        self.assertEqual(secrets["123456789012"], "<REDACTED-AWS-ACCOUNT-ID>")
        self.assertIn("overrides", stderr)
        self.assertIn(str(self.global_file), stderr)
        self.assertIn(str(self.tmp / "extra0.txt"), stderr)
        self.assertNotIn("123456789012", stderr)

    def test_later_file_wins_even_with_plain_label(self):
        secrets, stderr = self.load_files(
            "aws-account-id: 123456789012\n", "redacted: 123456789012\n"
        )
        self.assertEqual(secrets["123456789012"], "<REDACTED>")
        self.assertIn("overrides", stderr)

    def test_same_label_across_files_is_silent(self):
        secrets, stderr = self.load_files(
            "email: john@example.com\n", "email: JOHN@example.com\n"
        )
        self.assertEqual(len(secrets), 1)
        self.assertEqual(stderr, "")

    def test_order_follows_variable(self):
        secrets, _ = self.load_files(
            "redacted: unrelated1\n", "x: 999999\n", "y: 999999\n", order=[1, 0]
        )
        self.assertEqual(secrets["999999"], "<REDACTED-X>")


# --------------------------------------------------
# Command line: pipe mode
# --------------------------------------------------

class PipeCliTests(HushTestCase):
    def setUp(self):
        super().setUp()
        self.write_global("email: john@example.com\nip: 10.10.10.15\n")
        self.extra = self.write_extra("work.txt", "redacted: worksecret1\n")

    def test_redacts_stdin(self):
        proc = self.run_cli(input=b"Contact JOHN@example.com at 10.10.10.15\n")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(
            proc.stdout, b"Contact <REDACTED-EMAIL> at <REDACTED-IP>\n"
        )
        self.assertTrue(proc.stderr.startswith(b"hush: redacted 2:"))

    def test_extra_file_via_variable(self):
        proc = self.run_cli(
            input=b"john@example.com worksecret1",
            env={"HUSH_SECRETS_FILES": str(self.extra)},
        )
        self.assertEqual(proc.stdout, b"<REDACTED-EMAIL> <REDACTED>")

    def test_no_global(self):
        proc = self.run_cli(
            ["--no-global"],
            input=b"john@example.com worksecret1",
            env={"HUSH_SECRETS_FILES": str(self.extra)},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, b"john@example.com <REDACTED>")

    def test_no_global_without_variable(self):
        proc = self.run_cli(["--no-global"], input=b"x")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, b"")

    def test_files_one_per_line(self):
        proc = self.run_cli(
            ["--files"], env={"HUSH_SECRETS_FILES": str(self.extra)}
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            proc.stdout, f"{self.global_file}\n{self.extra}\n".encode()
        )

    def test_files_with_no_global(self):
        proc = self.run_cli(
            ["--files", "--no-global"],
            env={"HUSH_SECRETS_FILES": str(self.extra)},
        )
        self.assertEqual(proc.stdout, f"{self.extra}\n".encode())

    def test_files_fails_on_missing_file(self):
        proc = self.run_cli(
            ["--files"], env={"HUSH_SECRETS_FILES": str(self.tmp / "nope.txt")}
        )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, b"")

    def test_quiet(self):
        proc = self.run_cli(["-q"], input=b"john@example.com")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stderr, b"")

    def test_no_match_message(self):
        proc = self.run_cli(input=b"nothing")
        self.assertEqual(proc.stdout, b"nothing")
        self.assertIn(b"no configured secrets found", proc.stderr)

    def test_config_error_outputs_nothing(self):
        missing = self.tmp / "nope.txt"
        proc = self.run_cli(
            input=b"john@example.com\n", env={"HUSH_SECRETS_FILES": str(missing)}
        )
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, b"")
        self.assertIn(b"Secrets file not found (HUSH_SECRETS_FILES)", proc.stderr)
        self.assertIn(str(missing).encode(), proc.stderr)

    def test_invalid_file_outputs_nothing(self):
        self.write_global("[email]\njohn@example.com\n")
        proc = self.run_cli(input=b"john@example.com\n")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, b"")

    def test_non_utf8_passes_through(self):
        proc = self.run_cli(input=b"\xff\xfe john@example.com\n")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b"\xff\xfe <REDACTED-EMAIL>\n")

    def test_blank_line_before_messages_on_terminal(self):
        proc = self.run_cli_tty_stdout(input=b"x john@example.com\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(proc.stderr.startswith(b"\nhush: redacted"), proc.stderr)

    def test_missing_final_newline_completed_on_terminal(self):
        proc = self.run_cli_tty_stdout(input=b"x john@example.com")
        self.assertTrue(proc.stderr.startswith(b"\n\nhush: redacted"), proc.stderr)

    def test_no_separator_when_quiet(self):
        proc = self.run_cli_tty_stdout(["-q"], input=b"x john@example.com\n")
        self.assertEqual(proc.stderr, b"")

    def test_tty_stdin_rejected(self):
        master, slave = os.openpty()
        try:
            proc = subprocess.run(
                [sys.executable, str(SCRIPT)],
                stdin=slave,
                capture_output=True,
                env=self.base_env(),
                timeout=20,
            )
        finally:
            os.close(master)
            os.close(slave)
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b"no input piped", proc.stderr)

    def test_preview_requires_selection(self):
        proc = self.run_cli(["-n"], input=b"x")
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
        env = {k: v for k, v in os.environ.items() if not k.startswith("HUSH_")}
        env.update(self.base_env())
        cmd = (
            f"{shlex.quote(sys.executable)} {shlex.quote(str(SCRIPT))} -q"
            " | head -c 1 > /dev/null"
        )
        proc = subprocess.run(
            cmd,
            shell=True,
            input=b"a\n" * 300_000,
            capture_output=True,
            env=env,
            timeout=20,
        )
        self.assertNotIn(b"Traceback", proc.stderr)


# --------------------------------------------------
# Streaming
# --------------------------------------------------

class StreamingTests(HushTestCase):
    def setUp(self):
        super().setUp()
        self.write_global("email: john@example.com\n")

    def test_line_written_before_input_ends(self):
        proc = subprocess.Popen(
            [sys.executable, str(SCRIPT)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.cli_env({}),
        )
        try:
            proc.stdin.write(b"to john@example.com\n")
            proc.stdin.flush()
            first = read_until(proc.stdout, b"\n")
            still_running = proc.poll() is None

            proc.stdin.write(b"and JOHN@example.com\n")
            proc.stdin.close()
            rest, stderr = proc.communicate(timeout=20)
        finally:
            if proc.poll() is None:
                proc.kill()

        self.assertEqual(first, b"to <REDACTED-EMAIL>\n")
        self.assertTrue(still_running)
        self.assertEqual(rest, b"and <REDACTED-EMAIL>\n")
        self.assertIn(b"redacted 2:", stderr)

    def test_summary_only_after_input_ends(self):
        proc = subprocess.Popen(
            [sys.executable, str(SCRIPT)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.cli_env({}),
        )
        try:
            proc.stdin.write(b"john@example.com\n")
            proc.stdin.flush()
            read_until(proc.stdout, b"\n")
            ready, _, _ = select.select([proc.stderr], [], [], 0.3)
            proc.stdin.close()
            _, stderr = proc.communicate(timeout=20)
        finally:
            if proc.poll() is None:
                proc.kill()

        self.assertEqual(ready, [])
        self.assertIn(b"redacted 1:", stderr)

    def test_output_matches_whole_input_redaction(self):
        text = "10.10.10.15\n10.10.10.150\nx john@example.com y\nlast line"
        self.write_global("ip: 10.10.10.15\nemail: john@example.com\n")
        proc = self.run_cli(input=text.encode())
        expected = self.redacted(None, text)
        self.assertEqual(proc.stdout.decode(), expected)


# --------------------------------------------------
# Command line: clipboard and primary selection (with fake tools)
# --------------------------------------------------

FAKE_WL_PASTE = """#!/bin/sh
store="$FAKE_CLIP"
for arg in "$@"; do [ "$arg" = "--primary" ] && store="$FAKE_PRIMARY"; done
[ -s "$store" ] || { echo "Nothing is copied" >&2; exit 1; }
cat "$store"
"""

FAKE_WL_COPY = """#!/bin/sh
store="$FAKE_CLIP"
for arg in "$@"; do [ "$arg" = "--primary" ] && store="$FAKE_PRIMARY"; done
touch "$store.written"
cat > "$store"
"""

FAKE_XCLIP = """#!/bin/sh
store="$FAKE_CLIP"
output=0
previous=""
for arg in "$@"; do
    if [ "$previous" = "-selection" ] && [ "$arg" = "primary" ]; then
        store="$FAKE_PRIMARY"
    fi
    [ "$arg" = "-o" ] && output=1
    previous="$arg"
done
if [ "$output" = 1 ]; then
    [ -s "$store" ] || exit 1
    cat "$store"
    exit 0
fi
touch "$store.written"
cat > "$store"
"""


class ClipboardCliTests(HushTestCase):
    ORIGINAL = b"Contact john@example.com\n"
    REDACTED = b"Contact <REDACTED-EMAIL>\n"
    PRIMARY = b"Mail john@example.com\n"
    PRIMARY_REDACTED = b"Mail <REDACTED-EMAIL>\n"

    def setUp(self):
        super().setUp()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.make_tool("wl-paste", FAKE_WL_PASTE)
        self.make_tool("wl-copy", FAKE_WL_COPY)
        self.make_tool("xclip", FAKE_XCLIP)

        self.clip = self.tmp / "clip"
        self.clip.write_bytes(self.ORIGINAL)
        self.clip_written = Path(f"{self.clip}.written")

        # Empty by default: nothing selected.
        self.primary = self.tmp / "primary"
        self.primary.write_bytes(b"")
        self.primary_written = Path(f"{self.primary}.written")

        self.write_global("email: john@example.com\n")
        self.env = {
            "PATH": f"{self.bin}:{SYSTEM_PATH}",
            "WAYLAND_DISPLAY": "fake-wayland",
            "FAKE_CLIP": str(self.clip),
            "FAKE_PRIMARY": str(self.primary),
        }

    def make_tool(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def x11_env(self):
        env = {k: v for k, v in self.env.items() if k != "WAYLAND_DISPLAY"}
        env["DISPLAY"] = ":99"
        return env

    # Clipboard

    def test_redacts_clipboard_in_place(self):
        proc = self.run_cli(["-c"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.clip.read_bytes(), self.REDACTED)
        self.assertIn(b"redacted 1:", proc.stderr)

    def test_preview_does_not_modify(self):
        proc = self.run_cli(["-c", "-n"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, self.REDACTED)
        self.assertEqual(self.clip.read_bytes(), self.ORIGINAL)
        self.assertFalse(self.clip_written.exists())
        self.assertIn(b"nothing was modified", proc.stderr)

    def test_preview_separated_on_terminal(self):
        proc = self.run_cli_tty_stdout(["-cn"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(proc.stderr.startswith(b"\nhush: "), proc.stderr)

    def test_no_match_does_not_write(self):
        self.clip.write_bytes(b"nothing secret")
        proc = self.run_cli(["-c"], env=self.env)
        self.assertEqual(proc.returncode, 0)
        self.assertFalse(self.clip_written.exists())
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

    def test_x11_clipboard(self):
        proc = self.run_cli(["-c"], env=self.x11_env())
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
        env = {**self.env, "HUSH_SECRETS_FILES": str(self.tmp / "nope.txt")}
        proc = self.run_cli(["-c"], env=env)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.clip.read_bytes(), self.ORIGINAL)
        self.assertFalse(self.clip_written.exists())

    # Primary selection

    def test_primary_only(self):
        self.primary.write_bytes(self.PRIMARY)
        proc = self.run_cli(["-p"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.primary.read_bytes(), self.PRIMARY_REDACTED)
        self.assertEqual(self.clip.read_bytes(), self.ORIGINAL)
        self.assertFalse(self.clip_written.exists())

    def test_primary_only_warns_about_clipboard(self):
        self.primary.write_bytes(self.PRIMARY)
        proc = self.run_cli(["-p"], env=self.env)
        self.assertIn(b"WARNING: the clipboard also contains secrets", proc.stderr)
        self.assertIn(b"-c", proc.stderr)

    def test_clipboard_only_warns_about_primary(self):
        self.primary.write_bytes(self.PRIMARY)
        proc = self.run_cli(["-c"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(
            b"WARNING: the primary selection also contains secrets", proc.stderr
        )
        self.assertEqual(self.primary.read_bytes(), self.PRIMARY)
        self.assertFalse(self.primary_written.exists())

    def test_no_warning_when_other_selection_clean(self):
        self.primary.write_bytes(b"nothing here\n")
        proc = self.run_cli(["-c"], env=self.env)
        self.assertNotIn(b"WARNING", proc.stderr)

    def test_no_warning_when_other_selection_empty(self):
        proc = self.run_cli(["-c"], env=self.env)
        self.assertNotIn(b"WARNING", proc.stderr)
        self.assertNotIn(b"primary", proc.stderr)

    def test_primary_empty_is_noted_not_error(self):
        proc = self.run_cli(["-p"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(b"empty or unavailable", proc.stderr)
        self.assertFalse(self.primary_written.exists())

    def test_both(self):
        self.primary.write_bytes(self.PRIMARY)
        proc = self.run_cli(["-cp"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.clip.read_bytes(), self.REDACTED)
        self.assertEqual(self.primary.read_bytes(), self.PRIMARY_REDACTED)
        self.assertIn(b"hush: clipboard: redacted 1:", proc.stderr)
        self.assertIn(b"hush: primary selection: redacted 1:", proc.stderr)
        self.assertNotIn(b"WARNING", proc.stderr)

    def test_both_flag_order_irrelevant(self):
        self.primary.write_bytes(self.PRIMARY)
        proc = self.run_cli(["-pc"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.clip.read_bytes(), self.REDACTED)
        self.assertEqual(self.primary.read_bytes(), self.PRIMARY_REDACTED)

    def test_both_with_empty_primary(self):
        proc = self.run_cli(["-cp"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.clip.read_bytes(), self.REDACTED)
        self.assertIn(b"empty or unavailable", proc.stderr)
        # Only one block, so no labels.
        self.assertIn(b"hush: redacted 1:", proc.stderr)

    def test_preview_primary_only(self):
        self.primary.write_bytes(self.PRIMARY)
        proc = self.run_cli(["-pn"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, self.PRIMARY_REDACTED)
        self.assertFalse(self.primary_written.exists())

    def test_preview_both_labelled(self):
        self.primary.write_bytes(self.PRIMARY)
        proc = self.run_cli(["-cpn"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, self.REDACTED + self.PRIMARY_REDACTED)
        self.assertIn(b"hush: clipboard:\n", proc.stderr)
        self.assertIn(b"hush: primary selection:\n", proc.stderr)
        self.assertIn(b"nothing was modified", proc.stderr)
        self.assertFalse(self.clip_written.exists())
        self.assertFalse(self.primary_written.exists())

    def test_preview_both_quiet_keeps_labels(self):
        self.primary.write_bytes(self.PRIMARY)
        proc = self.run_cli(["-cpnq"], env=self.env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(b"hush: clipboard:\n", proc.stderr)
        self.assertIn(b"hush: primary selection:\n", proc.stderr)
        self.assertNotIn(b"redacted", proc.stderr)
        self.assertNotIn(b"nothing was modified", proc.stderr)

    def test_primary_write_failure_after_clipboard(self):
        self.primary.write_bytes(self.PRIMARY)
        self.make_tool(
            "wl-copy",
            '#!/bin/sh\n'
            'for arg in "$@"; do\n'
            '    [ "$arg" = "--primary" ] && { cat > /dev/null; exit 1; }\n'
            'done\n'
            'cat > "$FAKE_CLIP"\n',
        )
        proc = self.run_cli(["-cp"], env=self.env)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.clip.read_bytes(), self.REDACTED)
        self.assertEqual(self.primary.read_bytes(), self.PRIMARY)
        self.assertIn(b"clipboard was redacted", proc.stderr)

    def test_x11_primary(self):
        self.primary.write_bytes(self.PRIMARY)
        proc = self.run_cli(["-p"], env=self.x11_env())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.primary.read_bytes(), self.PRIMARY_REDACTED)
        self.assertEqual(self.clip.read_bytes(), self.ORIGINAL)


# --------------------------------------------------
# hush add
# --------------------------------------------------

class AddTests(HushTestCase):
    INITIAL = "# my secrets\nemail: john@example.com\n"

    def setUp(self):
        super().setUp()
        self.write_global(self.INITIAL)

    def add(self, data, *args, env=None):
        return self.run_cli(["add", *args], input=data, env=env)

    def lines(self, path=None):
        return (path or self.global_file).read_text().splitlines()

    def assert_unchanged(self):
        self.assertEqual(self.global_file.read_text(), self.INITIAL)

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
        redact = self.run_cli(input=b"pw newsecret123")
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
        redact = self.run_cli(input=b"firstpart\tsecondpart")
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
        self.global_file.write_text("email: john@example.com")
        proc = self.add(b"newsecret123\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            self.lines(), ["email: john@example.com", "redacted: newsecret123"]
        )

    def test_file_with_only_comments(self):
        self.global_file.write_text("# nothing yet\n")
        proc = self.add(b"newsecret123\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        redact = self.run_cli(input=b"newsecret123")
        self.assertEqual(redact.stdout, b"<REDACTED>")

    def test_invalid_file_refused(self):
        self.global_file.write_text("user:password\n")
        proc = self.add(b"newsecret123\n")
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(self.global_file.read_text(), "user:password\n")

    def test_section_header_file_refused(self):
        self.global_file.write_text("[email]\njohn@example.com\n")
        proc = self.add(b"newsecret123\n")
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"Expected 'label: secret'", proc.stderr)

    def test_missing_global_file(self):
        self.global_file.unlink()
        proc = self.add(b"newsecret123\n")
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"Secrets file not found (global)", proc.stderr)
        self.assertFalse(self.global_file.exists())

    def test_file_option(self):
        work = self.write_extra("work.txt", "# work\n")
        proc = self.add(b"newsecret123\n", "--file", str(work))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.lines(work), ["# work", "redacted: newsecret123"])
        self.assert_unchanged()

    def test_file_option_not_loaded_note(self):
        work = self.write_extra("work.txt", "# work\n")
        proc = self.add(b"newsecret123\n", "--file", str(work))
        self.assertIn(b"not loaded", proc.stderr)

    def test_file_option_loaded_no_note(self):
        work = self.write_extra("work.txt", "# work\n")
        proc = self.add(
            b"newsecret123\n", "--file", str(work),
            env={"HUSH_SECRETS_FILES": str(work)},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(b"not loaded", proc.stderr)

    def test_file_option_tilde(self):
        work = self.write_extra("work.txt", "# work\n")
        proc = self.add(b"newsecret123\n", "--file", "~/work.txt")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.lines(work)[-1], "redacted: newsecret123")

    def test_file_option_missing(self):
        proc = self.add(b"newsecret123\n", "--file", str(self.tmp / "nope.txt"))
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"Secrets file not found (--file)", proc.stderr)

    def test_variable_does_not_change_target(self):
        work = self.write_extra("work.txt", "# work\n")
        proc = self.add(b"newsecret123\n", env={"HUSH_SECRETS_FILES": str(work)})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.lines()[-1], "redacted: newsecret123")
        self.assertEqual(self.lines(work), ["# work"])

    def test_duplicates_checked_against_target_only(self):
        work = self.write_extra("work.txt", "# work\n")
        proc = self.add(b"john@example.com\n", "--file", str(work))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.lines(work)[-1], "redacted: john@example.com")

    def test_file_mode_becomes_600(self):
        self.global_file.chmod(0o644)
        proc = self.add(b"newsecret123\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(self.global_file.stat().st_mode & 0o777, 0o600)

    def test_symlink_preserved(self):
        real = self.write_extra("real.txt", "email: john@example.com\n")
        link = self.tmp / "link.txt"
        link.symlink_to(real)
        proc = self.add(b"newsecret123\n", "--file", str(link))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(link.is_symlink())
        self.assertIn("redacted: newsecret123", real.read_text())

    def test_no_temporary_files_left(self):
        self.add(b"newsecret123\n")
        leftovers = [
            p.name for p in self.global_file.parent.iterdir()
            if p.name.startswith(".hush-")
        ]
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
                env=self.base_env(),
                # No controlling terminal, so the prompt uses the pty
                # instead of the terminal running the tests.
                start_new_session=True,
            )

            # Wait for the prompt before typing: getpass discards input
            # that arrives before it switches off echo.
            stderr = read_until(proc.stderr, b"Secret")
            if b"Secret" not in stderr:
                proc.kill()
                self.fail("prompt not shown")

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
