# hush

Redact known secrets from text before you share it.

hush replaces the secrets listed in your secrets file with placeholders like
`<REDACTED>` or `<REDACTED-EMAIL>`, in piped text or directly in the
clipboard. Matching is exact and case-insensitive: hush never guesses what
might be sensitive, and it never uses a different secrets file than the one
configured.

Version 0.2.0. Upgrading from 0.1.0? See [Upgrading to 0.2.0](#upgrading-to-020).

## Install

Requires Linux with `python3` (standard library only). Clipboard mode needs
`wl-clipboard` on Wayland or `xclip` on X11:

```bash
sudo apt install wl-clipboard   # if `echo $XDG_SESSION_TYPE` prints wayland
sudo apt install xclip          # if it prints x11
```

Install:

```bash
git clone <repo-url> ~/src/hush
cd ~/src/hush
./install.sh
```

The installer copies `hush.py` to `~/.local/bin/hush` and creates
`~/.config/hush/secrets.txt` from `secrets.example.txt` if it doesn't exist.
The directory is set to mode `700` and the file to `600`. Make sure
`~/.local/bin` is in your `PATH`.

To update, pull, run the tests, then reinstall:

```bash
git pull && python3 -m unittest test_hush.py && ./install.sh
```

## Secrets file

hush reads `$HUSH_SECRETS_FILE` if it's set, otherwise
`~/.config/hush/secrets.txt` (or `$XDG_CONFIG_HOME/hush/secrets.txt`). The
file must exist; hush never falls back to another file.

Each secret is one line:

```text
# AWS lab
redacted: AKIAIOSFODNN7EXAMPLE
redacted: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

email: john@example.com
ip: 10.10.10.15
password: pass=word:with#odd[chars
```

- A line is `label: secret`. The label may contain letters, digits, `-` and
  `_`. The first colon ends it and must be followed by at least one space.
- The secret is the rest of the line, exactly as written; nothing is escaped.
- `redacted` gives `<REDACTED>`. Any other label gives `<REDACTED-LABEL>`,
  uppercased. A label tells readers what kind of value was removed, which is
  also information, so use `redacted` unless the distinction helps.
- Lines starting with `#` are comments. Blank lines are ignored.
- Whitespace around a line is ignored, so secrets can't start or end with
  spaces.
- Duplicate secrets (ignoring case) are skipped with a warning.
- Any other line is an error that stops hush. The error gives the line number,
  never its content.

The file holds your secrets in plain text. Keep it at mode `600`, out of
version control and out of shared backups. hush warns if other users can read
it.

## Usage

### Redact piped text

```bash
some-command | hush
some-command 2>&1 | hush               # also redact error output
hush < app.log > app.redacted.log      # redact a file
some-command | hush | wl-copy          # redact, then copy the result
```

Redacted text goes to stdout. A summary such as
`hush: redacted 3: 2 <REDACTED-EMAIL>, 1 <REDACTED-IP>` goes to stderr; use
`-q` to hide it.

If the secrets file is missing or invalid, hush exits with an error and writes
nothing to stdout, so text never passes through unredacted.

### Redact the clipboard

```bash
hush -c        # redact the clipboard in place
hush -c -p     # preview the redacted text without changing the clipboard
```

With `-c`, hush reads the clipboard as text, redacts it, writes it back, then
reads it again to confirm the write. If nothing matched, the clipboard isn't
touched. Paste with Ctrl+V afterwards; see [Limitations](#limitations) for
middle-click paste.

### Add secrets

`hush add` adds secrets to the secrets file without printing them. Avoid
`echo`-ing a secret to copy it: printed text ends up in scrollback, logs and
screen shares.

```bash
# From a command or a variable
aws configure get aws_secret_access_key --profile lab | hush add
printf '%s\n' "$SECRET" | hush add

# Several at once: one per line, or tab-separated on one line
printf '%s\t%s\n' "$KEY_ID" "$SECRET" | hush add

# At a hidden prompt
hush add

# With a label, or with a dated comment above the new entries
printf '%s\n' "$EMAIL" | hush add -l email
printf '%s\n' "$SECRET" | hush add --note "SAA lab: alice access key"
```

Input:

- Each line of input is a secret. Tab-separated values on one line are added
  as separate secrets, which matches the AWS CLI's `--output text`. Spaces
  don't split. `--no-split` keeps each line whole.
- With nothing piped in, hush prompts for one secret without echoing it.
- Secrets are never taken as command-line arguments, which would be visible
  in `ps` and shell history.

Validation happens before anything is written. If any value fails, nothing is
added:

- Empty input is an error. This catches unset variables.
- Secrets under 6 characters are rejected unless you pass `--allow-short`.
  Short values get redacted inside unrelated words.
- Secrets with leading or trailing whitespace are rejected.
- Secrets already in the file are skipped and reported.

New entries are appended to the end of the file. `--note` adds a blank line
and a comment such as `# 2026-11-11: SAA lab: alice access key` above them.
The note is visible in shell history, so never put a secret in it. The file is
replaced atomically, symlinks are followed, and the mode is set to `600`.

### Use a different secrets file

`HUSH_SECRETS_FILE` selects the file for both redaction and `hush add`:

```bash
HUSH_SECRETS_FILE=~/.config/hush/work.txt hush -c
printf '%s\n' "$TOKEN" | HUSH_SECRETS_FILE=~/.config/hush/work.txt hush add

export HUSH_SECRETS_FILE=~/.config/hush/work.txt   # for the whole session
```

`hush add` works on an empty file; redaction needs at least one secret.

## Reference

```text
hush [-c] [-p] [-q]
hush add [-l LABEL] [--note TEXT] [--allow-short] [--no-split]
hush --version
```

| Option | Meaning |
| --- | --- |
| `-c`, `--clipboard` | Redact the clipboard in place. |
| `-p`, `--preview` | With `-c`: print the result without changing the clipboard. |
| `-q`, `--quiet` | Hide the summary and informational messages. Errors and warnings still print. |
| `add -l`, `--label LABEL` | Label for new secrets. Default: `redacted`. |
| `add --note TEXT` | Dated comment written above the new secrets. |
| `add --allow-short` | Allow secrets shorter than 6 characters. |
| `add --no-split` | Don't split input lines on tabs. |

| Exit code | Meaning |
| --- | --- |
| `0` | Success, including when nothing matched or nothing new was added. |
| `1` | Error: secrets file, input, clipboard or write failure. |
| `2` | Usage error: invalid options, or nothing piped in without `-c`. |
| `130` | Cancelled with Ctrl+C. |

All messages go to stderr, prefixed with `hush:`, and never contain a secret.

## Matching rules

- Matching is literal (`.` and `*` are ordinary characters) and
  case-insensitive.
- If one secret contains another, the longer one wins.
- A secret that starts or ends with a digit doesn't match when another digit
  is directly next to it, so `10.10.10.15` doesn't match inside
  `10.10.10.150`.
- Letters next to a secret don't prevent a match. Escapes like `\n` and URL
  encoding like `%3D` put letters right before real secrets, and over-redacting
  is safer than leaking.

With `ip: 10.10.10.15` and `redacted: mysecret`:

| Input | Output |
| --- | --- |
| `host=10.10.10.15:8080` | `host=<REDACTED-IP>:8080` |
| `10.10.10.150` | `10.10.10.150` |
| `MYSECRET` | `<REDACTED>` |
| `mysecretABC` | `<REDACTED>ABC` |
| `token%3Dmysecret` | `token%3D<REDACTED>` |

## Limitations

- Only listed secrets are redacted. New or rotated credentials pass through
  until you add them.
- Input is read in full before output, so streaming commands like `tail -f`
  never produce output.
- Clipboard mode handles text only.
- Clipboard managers may keep the unredacted original in their history.
- Selecting text also copies it to the primary selection (middle-click paste),
  which hush doesn't redact.
- `hush add` doesn't detect the file being edited at the same time; the last
  write wins.

## Upgrading to 0.2.0

0.2.0 replaces section headers with one `label: secret` line per secret.
Old files stop hush with
`Invalid line N ... Section headers are no longer supported`, and must be
converted by hand:

- Put `label: ` in front of each secret under a `[label]` header, then delete
  the header.
- Put `redacted: ` in front of secrets above the first header or under
  `[redacted]`.
- Remove `\` escapes: `\#hash` becomes `#hash`.

| 0.1.0 | 0.2.0 |
| --- | --- |
| `AKIAIOSFODNN7EXAMPLE` above any header | `redacted: AKIAIOSFODNN7EXAMPLE` |
| `[email]` then `john@example.com` | `email: john@example.com` |
| `[password]` then `\#hash` | `password: #hash` |

Check the result with `echo | hush`. Take care with secrets that contain a
colon: an unconverted `Note: abc` would be read as the label `note` with the
secret `abc`.

## Development

```bash
python3 -m unittest -v test_hush.py
```

The tests use temporary files and fake clipboard tools, so they never touch
your real clipboard or secrets file. After changing clipboard code, also check
by hand: copy text from a browser and a terminal, run `hush -c`, and paste.

## Uninstall

```bash
rm ~/.local/bin/hush
rm -rf ~/.config/hush        # also deletes your secrets files
```