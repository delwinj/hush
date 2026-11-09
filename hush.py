#!/usr/bin/env python3
"""hush: redact configured secrets from piped input or the clipboard."""

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ENV_VARIABLE = "HUSH_SECRETS_FILE"
DEFAULT_LABEL = "REDACTED"
SECTION_RE = re.compile(r"\[\s*([A-Za-z0-9_-]+)\s*\]")

# Round-trip any bytes, even invalid UTF-8, without crashing.
ENCODING = "utf-8"
ERRORS = "surrogateescape"
CLIPBOARD_TIMEOUT = 10


class HushError(Exception):
    """A failure that stops hush with a message."""


def info(message):
    print(f"hush: {message}", file=sys.stderr)


# --------------------------------------------------
# Configuration
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


def replacement_for(label):
    if label == DEFAULT_LABEL:
        return "<REDACTED>"
    return f"<REDACTED-{label}>"


def load_secrets():
    path = get_secrets_file()
    warn_if_exposed(path)

    try:
        # utf-8-sig drops a byte-order mark if an editor added one.
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise HushError(f"Unable to read secrets file {path}: {error}")

    secrets = []
    seen = {}
    label = DEFAULT_LABEL

    for number, raw in enumerate(lines, start=1):
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        if line.startswith("\\"):
            # Escaped line: everything after the backslash is the secret.
            secret = line[1:]
        elif line.startswith("[") and line.endswith("]"):
            section = SECTION_RE.fullmatch(line)
            if not section:
                raise HushError(
                    f"Invalid section header on line {number} of {path}. "
                    f"Labels may contain only letters, digits, - and _. "
                    f"To use this line as a secret, prefix it with \\"
                )
            label = section.group(1).upper()
            continue
        else:
            secret = line

        if not secret:
            continue

        # lower() matches how the regex compares case; casefold() would
        # treat secrets the regex sees as different (e.g. ß vs SS) as
        # duplicates and drop one.
        key = secret.lower()
        if key in seen:
            info(
                f"WARNING: duplicate secret on line {number} ignored "
                f"(first defined on line {seen[key]})."
            )
            continue
        seen[key] = number

        secrets.append((secret, replacement_for(label)))

    if not secrets:
        raise HushError(f"No secrets defined in {path}")

    # Longer secrets first, so they win over secrets they contain.
    secrets.sort(key=lambda item: len(item[0]), reverse=True)
    return secrets


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
# Main
# --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="hush",
        description="Redact configured secrets from piped input or the clipboard.",
        epilog=(
            f"Secrets file: ${ENV_VARIABLE} if set, "
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
    args = parser.parse_args()

    if args.preview and not args.clipboard:
        parser.error("--preview requires --clipboard")

    if not args.clipboard and sys.stdin.isatty():
        parser.error(
            "no input piped. Pipe text in (e.g. 'env | hush') "
            "or use -c for the clipboard."
        )

    try:
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

    return 0


if __name__ == "__main__":
    sys.exit(main())

