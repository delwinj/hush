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

VERSION = "0.2.0"

ENV_VARIABLE = "HUSH_SECRETS_FILE"
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
# Secrets file location
# --------------------------------------------------

def default_secrets_file():
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "hush" / "secrets.txt"


def get_secrets_file():
    """
    1. HUSH_SECRETS_FILE, if set.
    2. $XDG_CONFIG_HOME/hush/secrets.txt (normally ~/.config/hush/secrets.txt).

    Whichever applies must exist and be readable. There is no fallback.
    """
    if ENV_VARIABLE in os.environ:
        value = os.environ[ENV_VARIABLE].strip()
        if not value:
            raise HushError(f"{ENV_VARIABLE} is set but empty.")
        path = Path(value).expanduser()
        source = ENV_VARIABLE
    else:
        path = default_secrets_file()
        source = "default location"

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

    return path


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
            "start of each line. See 'Upgrading to 0.2.0' in the README."
        )
    else:
        hint = (
            "Expected 'label: secret' (a label, a colon, at least one space, "
            "then the secret)."
        )
    return f"Invalid line {number} in {path}. {hint}"


def parse_config(text, path, warn=True):
    """
    Parse secrets file text into a list of (secret, LABEL) pairs.

    Blank lines and lines starting with # are ignored. Every other line
    must be "label: secret". Duplicates (ignoring case) keep the first.
    """
    entries = []
    seen = {}

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        match = ENTRY_RE.fullmatch(line)
        if not match:
            raise HushError(invalid_line_message(line, number, path))

        label = match.group(1).upper()
        secret = match.group(2)

        # lower() matches how the regex compares case; casefold() would
        # treat secrets the regex sees as different (e.g. ß vs SS) as
        # duplicates and drop one.
        key = secret.lower()
        if key in seen:
            if warn:
                info(
                    f"WARNING: duplicate secret on line {number} ignored "
                    f"(first defined on line {seen[key]})."
                )
            continue
        seen[key] = number

        entries.append((secret, label))

    return entries


def replacement_for(label):
    if label == DEFAULT_LABEL:
        return "<REDACTED>"
    return f"<REDACTED-{label}>"


def load_secrets():
    path = get_secrets_file()
    warn_if_exposed(path)

    entries = parse_config(read_config(path), path)
    if not entries:
        raise HushError(f"No secrets defined in {path}")

    secrets = [(secret, replacement_for(label)) for secret, label in entries]

    # Longer secrets first, so they win over secrets they contain.
    secrets.sort(key=lambda item: len(item[0]), reverse=True)
    return secrets


def write_config(path, content):
    """
    Replace the secrets file atomically: write a temporary file in the
    same directory, flush it to disk, then rename it over the original.
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
    if ensure_newline and text and not text.endswith("\n"):
        text += "\n"
    sys.stdout.buffer.write(text.encode(ENCODING, ERRORS))
    sys.stdout.flush()


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
            f"secrets file: ${ENV_VARIABLE} if set, "
            f"otherwise {default_secrets_file()}"
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
        "--version", action="version", version=f"hush {VERSION}",
    )
    args = parser.parse_args(argv)

    if args.preview and not args.clipboard:
        parser.error("--preview requires --clipboard")

    if not args.clipboard and sys.stdin.isatty():
        parser.error(
            "no input piped. Pipe text in (e.g. 'env | hush') "
            "or use -c for the clipboard."
        )

    # Load and validate configuration before touching any input,
    # so a config problem never lets text through unredacted.
    secrets = load_secrets()
    pattern = build_pattern(secrets)

    if args.clipboard:
        paste, copy = clipboard_commands()
        text = clipboard_read(paste)
        result, counts = redact(text, secrets, pattern)

        if args.preview:
            write_stdout(result, ensure_newline=True)
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
        write_stdout(result)
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
            "Add secrets to the secrets file without printing them. Reads one "
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

    # Validate the file before reading or prompting for any secret.
    path = get_secrets_file()
    warn_if_exposed(path)
    text = read_config(path)
    existing = {secret.lower() for secret, _ in parse_config(text, path)}

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
    parsed = dict(parse_config(content, path, warn=False))
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
