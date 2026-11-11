#!/usr/bin/env python3
"""hush: redact configured secrets from piped input or the clipboard."""

import argparse
import datetime
import getpass
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

VERSION = "0.3.0"

FILES_VARIABLE = "HUSH_SECRETS_FILES"
DEFAULT_LABEL = "REDACTED"
LABEL_RE = re.compile(r"[A-Za-z0-9_-]+")
# A label, a colon, at least one whitespace character, then the secret.
ENTRY_RE = re.compile(r"([A-Za-z0-9_-]+):\s+(.*)")
MIN_ADD_LENGTH = 6

# Round-trip any bytes, even invalid UTF-8, without crashing.
ENCODING = "utf-8"
ERRORS = "surrogateescape"
CLIPBOARD_TIMEOUT = 10


class HushError(Exception):
    """A failure that stops hush with a message."""


def info(message):
    print(f"hush: {message}", file=sys.stderr)


def plural(count, word):
    return f"{count} {word}{'' if count == 1 else 's'}"


# --------------------------------------------------
# Secrets file locations
# --------------------------------------------------

def global_secrets_file():
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "hush" / "secrets.txt"


def configured_paths(no_global):
    """
    Return (path, source) pairs in load order, without checking that the
    files exist: the global file first (unless no_global), then each entry
    of HUSH_SECRETS_FILES. Entries must be absolute or start with ~/.
    """
    paths = []

    if not no_global:
        paths.append((global_secrets_file(), "global"))

    if FILES_VARIABLE in os.environ:
        value = os.environ[FILES_VARIABLE]
        if not value.strip():
            raise HushError(f"{FILES_VARIABLE} is set but empty.")

        for entry in value.split(":"):
            entry = entry.strip()
            if not entry:
                raise HushError(
                    f"{FILES_VARIABLE} contains an empty entry "
                    f"(check for '::' or a leading or trailing ':')."
                )
            if not (entry.startswith("/") or entry.startswith("~/")):
                raise HushError(
                    f"{FILES_VARIABLE} entries must be absolute paths or "
                    f"start with ~/: {entry}"
                )
            paths.append((Path(entry).expanduser(), FILES_VARIABLE))

    if not paths:
        raise HushError(
            f"--no-global was given but {FILES_VARIABLE} is not set, so there "
            f"are no secrets files to load."
        )

    return paths


def check_file(path, source):
    try:
        exists = path.exists()
        is_file = path.is_file()
    except OSError as error:
        raise HushError(
            f"Unable to access secrets file ({source}): {path}: {error.strerror}"
        )

    if not exists:
        raise HushError(f"Secrets file not found ({source}): {path}")
    if not is_file:
        raise HushError(f"Secrets path is not a regular file ({source}): {path}")


def secrets_files(no_global):
    """
    Return the secrets files to load, in load order. Every file must exist.
    A file listed more than once loads once, at its first position.
    """
    files = []
    seen = set()

    for path, source in configured_paths(no_global):
        check_file(path, source)
        key = path.resolve()
        if key not in seen:
            seen.add(key)
            files.append(path)

    return files


def is_loaded(path):
    """Whether path is one of the files a normal run would load."""
    try:
        listed = configured_paths(no_global=False)
    except HushError:
        return False
    target = path.resolve()
    return any(candidate.resolve() == target for candidate, _ in listed)


def warn_if_exposed(path):
    if path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        info(
            f"WARNING: {path} is accessible by other users. "
            f"Run: chmod 600 {path}"
        )


# --------------------------------------------------
# Secrets file format
# --------------------------------------------------

def read_config(path):
    try:
        # utf-8-sig drops a byte-order mark if an editor added one.
        return path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as error:
        raise HushError(f"Unable to read secrets file {path}: {error}")


def invalid_line_message(line, number, path):
    # Never include the line itself: it may contain a secret.
    if line.startswith("[") and line.endswith("]"):
        hint = (
            "Section headers are no longer supported; put the label at the "
            "start of each line. See 'Upgrading' in the README."
        )
    else:
        hint = (
            "Expected 'label: secret' (a label, a colon, at least one space, "
            "then the secret)."
        )
    return f"Invalid line {number} in {path}. {hint}"


def parse_config(text, path):
    """
    Parse secrets file text into a list of (secret, LABEL, line_number).

    Blank lines and lines starting with # are ignored. Every other line
    must be "label: secret". Duplicates are kept; load_secrets decides
    which definition applies.
    """
    entries = []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        match = ENTRY_RE.fullmatch(line)
        if not match:
            raise HushError(invalid_line_message(line, number, path))

        entries.append((match.group(2), match.group(1).upper(), number))

    return entries


def replacement_for(label):
    if label == DEFAULT_LABEL:
        return "<REDACTED>"
    return f"<REDACTED-{label}>"


def warn_duplicate(previous, label, path, number):
    # Never include the secret itself.
    _, old_label, old_path, old_number = previous

    change = ""
    if old_label != label:
        change = f" ({replacement_for(old_label)} -> {replacement_for(label)})"

    if old_path == path:
        info(
            f"WARNING: duplicate secret on line {number} of {path} "
            f"(also on line {old_number}); line {number} applies{change}."
        )
    elif old_label != label:
        info(
            f"WARNING: line {number} of {path} overrides line {old_number} "
            f"of {old_path}{change}."
        )


def load_secrets(no_global=False):
    files = secrets_files(no_global)

    # key -> (secret, LABEL, path, line_number). The last definition wins.
    # lower() matches how the regex compares case; casefold() would treat
    # secrets the regex sees as different (e.g. ß vs SS) as duplicates.
    merged = {}

    for path in files:
        warn_if_exposed(path)
        for secret, label, number in parse_config(read_config(path), path):
            key = secret.lower()
            if key in merged:
                warn_duplicate(merged[key], label, path, number)
            merged[key] = (secret, label, path, number)

    if not merged:
        if len(files) == 1:
            raise HushError(f"No secrets defined in {files[0]}")
        raise HushError(
            "No secrets defined in any of the loaded secrets files "
            "(list them with: hush --files)."
        )

    secrets = [
        (secret, replacement_for(label)) for secret, label, _, _ in merged.values()
    ]

    # Longer secrets first, so they win over secrets they contain.
    secrets.sort(key=lambda item: len(item[0]), reverse=True)
    return secrets


def write_config(path, content):
    """
    Replace a secrets file atomically: write a temporary file in the same
    directory, flush it to disk, then rename it over the original.
    Symlinks are followed, so a linked file is updated in place.
    """
    target = path.resolve()
    fd, tmp = tempfile.mkstemp(prefix=".hush-", suffix=".tmp", dir=target.parent)

    try:
        with os.fdopen(fd, "w", encoding=ENCODING, newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


# --------------------------------------------------
# Redaction engine
# --------------------------------------------------

def build_pattern(secrets):
    """
    One capture group per secret, so each match maps back to its
    replacement by group number.

    A secret that starts or ends with a digit won't match when another
    digit is directly next to it on that side, so 10.10.10.15 doesn't
    match inside 10.10.10.150. Letters are never boundaries: escapes like
    \\n and URL encoding like %3D put letters right before real secrets.
    """
    parts = []

    for secret, _ in secrets:
        part = re.escape(secret)
        if secret[0].isascii() and secret[0].isdigit():
            part = f"(?<![0-9]){part}"
        if secret[-1].isascii() and secret[-1].isdigit():
            part = f"{part}(?![0-9])"
        parts.append(f"({part})")

    return re.compile("|".join(parts), re.IGNORECASE)


def redact(text, secrets, pattern):
    counts = Counter()

    def replace(match):
        replacement = secrets[match.lastindex - 1][1]
        counts[replacement] += 1
        return replacement

    return pattern.sub(replace, text), counts


def report(counts, quiet):
    if quiet:
        return

    total = sum(counts.values())
    if not total:
        info("no configured secrets found; text unchanged.")
        return

    detail = ", ".join(f"{n} {label}" for label, n in counts.most_common())
    info(f"redacted {total}: {detail}")


# --------------------------------------------------
# Clipboard
# --------------------------------------------------

def clipboard_commands():
    if os.environ.get("WAYLAND_DISPLAY"):
        if shutil.which("wl-paste") and shutil.which("wl-copy"):
            return (
                ["wl-paste", "--no-newline", "--type", "text"],
                ["wl-copy"],
            )
        raise HushError(
            "Wayland session detected but wl-clipboard is not installed. "
            "Run: sudo apt install wl-clipboard"
        )

    if os.environ.get("DISPLAY"):
        if shutil.which("xclip"):
            return (
                ["xclip", "-selection", "clipboard", "-o", "-t", "UTF8_STRING"],
                ["xclip", "-selection", "clipboard", "-t", "UTF8_STRING"],
            )
        raise HushError(
            "X11 session detected but xclip is not installed. "
            "Run: sudo apt install xclip"
        )

    raise HushError(
        "No graphical session found (neither WAYLAND_DISPLAY nor DISPLAY is set)."
    )


def clipboard_read(paste):
    try:
        result = subprocess.run(
            paste, capture_output=True, timeout=CLIPBOARD_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        raise HushError("Timed out reading the clipboard.")

    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise HushError(
            f"Unable to read clipboard as text (is it empty or an image?): {detail}"
        )

    return result.stdout.decode(ENCODING, ERRORS)


def clipboard_write(copy, text):
    # wl-copy and xclip fork a background process that keeps serving the
    # clipboard. Output goes to /dev/null so we don't wait on that process.
    try:
        result = subprocess.run(
            copy,
            input=text.encode(ENCODING, ERRORS),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=CLIPBOARD_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise HushError("Timed out writing the clipboard. Do NOT paste.")

    if result.returncode != 0:
        raise HushError("Unable to write the clipboard. Do NOT paste.")


def clipboard_verify(paste, expected, attempts=10, delay=0.05):
    # The background clipboard process may take a moment to take over,
    # so retry briefly before declaring failure.
    for _ in range(attempts):
        try:
            if clipboard_read(paste) == expected:
                return
        except HushError:
            pass
        time.sleep(delay)

    raise HushError(
        "Clipboard verification failed. Do NOT paste; "
        "check the clipboard contents manually."
    )


# --------------------------------------------------
# Output
# --------------------------------------------------

def write_stdout(text, ensure_newline=False):
    """Write text to stdout and return exactly what was written."""
    if ensure_newline and text and not text.endswith("\n"):
        text += "\n"
    sys.stdout.buffer.write(text.encode(ENCODING, ERRORS))
    sys.stdout.flush()
    return text


def separate_messages(written, quiet):
    """
    When output goes to a terminal, put a blank line between it and the
    messages that follow. This goes to stderr, so piped or redirected
    output is never changed.
    """
    if quiet or not sys.stdout.isatty():
        return
    gap = "\n" if written and not written.endswith("\n") else ""
    sys.stderr.write(gap + "\n")
    sys.stderr.flush()


# --------------------------------------------------
# hush (redaction)
# --------------------------------------------------

def run_redact(argv):
    parser = argparse.ArgumentParser(
        prog="hush",
        description="Redact configured secrets from piped input or the clipboard.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "commands:\n"
            "  hush add    add secrets without printing them "
            "(see: hush add --help)\n"
            "\n"
            f"secrets files: {global_secrets_file()} (unless --no-global),\n"
            f"then each file in ${FILES_VARIABLE} (colon-separated)"
        ),
    )
    parser.add_argument(
        "-c", "--clipboard", action="store_true",
        help="redact the clipboard in place",
    )
    parser.add_argument(
        "-p", "--preview", action="store_true",
        help="with -c: print the redacted clipboard without changing it",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="don't print the redaction summary",
    )
    parser.add_argument(
        "--no-global", action="store_true",
        help=f"don't load the global secrets file; use only ${FILES_VARIABLE}",
    )
    parser.add_argument(
        "--files", action="store_true",
        help="print the secrets files that would be loaded, one per line",
    )
    parser.add_argument(
        "--version", action="version", version=f"hush {VERSION}",
    )
    args = parser.parse_args(argv)

    if args.files:
        for path in secrets_files(args.no_global):
            write_stdout(f"{path}\n")
        return 0

    if args.preview and not args.clipboard:
        parser.error("--preview requires --clipboard")

    if not args.clipboard and sys.stdin.isatty():
        parser.error(
            "no input piped. Pipe text in (e.g. 'env | hush') "
            "or use -c for the clipboard."
        )

    # Load and validate configuration before touching any input,
    # so a config problem never lets text through unredacted.
    secrets = load_secrets(args.no_global)
    pattern = build_pattern(secrets)

    if args.clipboard:
        paste, copy = clipboard_commands()
        text = clipboard_read(paste)
        result, counts = redact(text, secrets, pattern)

        if args.preview:
            written = write_stdout(result, ensure_newline=True)
            separate_messages(written, args.quiet)
            report(counts, args.quiet)
            if not args.quiet:
                info("preview only; clipboard was NOT modified.")
        else:
            if counts:
                clipboard_write(copy, result)
                clipboard_verify(paste, result)
            report(counts, args.quiet)

    else:
        text = sys.stdin.buffer.read().decode(ENCODING, ERRORS)
        result, counts = redact(text, secrets, pattern)
        written = write_stdout(result)
        separate_messages(written, args.quiet)
        report(counts, args.quiet)

    return 0


# --------------------------------------------------
# hush add
# --------------------------------------------------

def read_add_input():
    """Return the raw text of the secrets to add. Never echoes it."""
    if sys.stdin.isatty():
        try:
            return getpass.getpass("Secret (input hidden): ")
        except EOFError:
            return ""

    data = sys.stdin.buffer.read()
    try:
        return data.decode(ENCODING)
    except UnicodeDecodeError:
        raise HushError("Input is not valid UTF-8. Nothing was added.")


def split_values(text, split_tabs):
    values = []
    for line in text.splitlines():
        values.extend(line.split("\t") if split_tabs else [line])
    # Blank and whitespace-only values are ignored, like blank lines.
    return [value for value in values if value.strip()]


def validate_values(values, allow_short):
    # Errors refer to secrets by position and length, never by content.
    for index, value in enumerate(values, start=1):
        if value != value.strip():
            raise HushError(
                f"Secret {index} has leading or trailing whitespace, which "
                f"the secrets file can't store. Nothing was added."
            )
        if value.splitlines() != [value]:
            raise HushError(
                f"Secret {index} contains a line break. Nothing was added."
            )
        if len(value) < MIN_ADD_LENGTH and not allow_short:
            raise HushError(
                f"Secret {index} is {len(value)} characters; the minimum is "
                f"{MIN_ADD_LENGTH}. Use --allow-short if this is intended. "
                f"Nothing was added."
            )


def run_add(argv):
    parser = argparse.ArgumentParser(
        prog="hush add",
        description=(
            "Add secrets to a secrets file without printing them. Reads one "
            "secret per line from stdin, or prompts with hidden input when "
            "run in a terminal. Tab-separated values on one line are added "
            "as separate secrets."
        ),
    )
    parser.add_argument(
        "-l", "--label", default="redacted",
        help="label for the new secrets (default: redacted, giving <REDACTED>)",
    )
    parser.add_argument(
        "--file", metavar="PATH",
        help="secrets file to add to (default: the global secrets file)",
    )
    parser.add_argument(
        "--note",
        help=(
            "comment written above the new secrets, prefixed with today's "
            "date; never put a secret here"
        ),
    )
    parser.add_argument(
        "--allow-short", action="store_true",
        help=f"allow secrets shorter than {MIN_ADD_LENGTH} characters",
    )
    parser.add_argument(
        "--no-split", action="store_true",
        help="keep each input line as one secret instead of splitting on tabs",
    )
    args = parser.parse_args(argv)

    if not LABEL_RE.fullmatch(args.label):
        parser.error("labels may contain only letters, digits, - and _")

    note = None
    if args.note is not None:
        note = args.note.strip()
        if not note:
            parser.error("--note is empty")
        if note.splitlines() != [note]:
            parser.error("--note must be a single line")

    if args.file is not None:
        path = Path(args.file).expanduser()
        source = "--file"
    else:
        path = global_secrets_file()
        source = "global"

    # Validate the file before reading or prompting for any secret.
    check_file(path, source)
    warn_if_exposed(path)
    text = read_config(path)
    existing = {secret.lower() for secret, _, _ in parse_config(text, path)}

    values = split_values(read_add_input(), split_tabs=not args.no_split)
    if not values:
        raise HushError("No secret provided. Nothing was added.")
    validate_values(values, args.allow_short)

    new = []
    batch = set()
    skipped = 0
    for value in values:
        key = value.lower()
        if key in existing or key in batch:
            skipped += 1
            continue
        batch.add(key)
        new.append(value)

    if not new:
        info(
            f"nothing added; {plural(skipped, 'secret')} already present "
            f"in {path}."
        )
        return 0

    label = args.label.lower()
    replacement = replacement_for(label.upper())

    block = []
    if note:
        block.append(f"# {datetime.date.today().isoformat()}: {note}")
    block.extend(f"{label}: {value}" for value in new)

    content = text
    if content and not content.endswith("\n"):
        content += "\n"
    if note and content and not content.endswith("\n\n"):
        content += "\n"
    content += "\n".join(block) + "\n"

    # Confirm the new file parses and holds every new secret under the
    # right label before replacing the original.
    parsed = {secret: lbl for secret, lbl, _ in parse_config(content, path)}
    if any(parsed.get(value) != label.upper() for value in new):
        raise HushError("Internal check failed. The secrets file was not changed.")

    try:
        write_config(path, content)
    except OSError as error:
        raise HushError(
            f"Unable to write secrets file {path}: {error.strerror or error}. "
            f"Nothing was added."
        )

    message = f"added {plural(len(new), 'secret')} as {replacement} to {path}"
    if skipped:
        message += f" ({skipped} already present)"
    info(message)

    if args.file is not None and not is_loaded(path):
        info(
            f"note: {path} is not loaded (it isn't the global file or listed "
            f"in {FILES_VARIABLE}), so these secrets won't be redacted until "
            f"it is."
        )

    return 0


# --------------------------------------------------
# Main
# --------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    try:
        if argv[:1] == ["add"]:
            return run_add(argv[1:])
        return run_redact(argv)

    except HushError as error:
        info(f"ERROR: {error}")
        return 1

    except KeyboardInterrupt:
        info("cancelled.")
        return 130

    except BrokenPipeError:
        # e.g. `env | hush | head`; exit quietly.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 1


if __name__ == "__main__":
    sys.exit(main())
