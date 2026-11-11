# hush

Redact known secrets from terminal output and clipboard text before sharing it.

Getting help with a problem often means pasting command output, logs or
configuration into an AI chat, a forum post, an issue tracker or a Discord
channel. Ideally, that text would never contain sensitive values in the first
place. In practice, terminal sessions get messy: while debugging,
troubleshooting or learning a new tool, access keys, account IDs, email
addresses, hostnames and internal IP addresses end up on screen right next to
the output that matters. Removing them by hand, or copying the text in
several pieces to leave them out, is tedious and easy to get wrong,
especially when the same value appears many times.

hush turns this into a single step. Sensitive values are listed once in a
secrets file. After that, piping output through `hush`, or running `hush -c`
on the clipboard, replaces every occurrence with a placeholder such as
`<REDACTED>` or `<REDACTED-EMAIL>`, ready to paste.

Matching is exact and case-insensitive: hush never guesses what might be
sensitive, and it only reads the secrets files configured for it.

Changes between versions are listed in [CHANGELOG.md](CHANGELOG.md).

## Contents

- [Install](#install)
- [Secrets files](#secrets-files)
- [Usage](#usage)
- [Reference](#reference)
- [Matching rules](#matching-rules)
- [Limitations](#limitations)
- [Development](#development)
- [Uninstall](#uninstall)

## Install

Developed and tested on Ubuntu 26.04.1 with Python 3.14.4. Other Linux
distributions with a recent Python 3 and `wl-clipboard` or `xclip` will
likely work, but haven't been tested. macOS, Windows and WSL aren't
supported: their clipboards work differently.

hush uses only the Python standard library. Clipboard modes need
`wl-clipboard` on Wayland or `xclip` on X11. On Ubuntu:

```bash
sudo apt install wl-clipboard   # if `echo $XDG_SESSION_TYPE` prints wayland
sudo apt install xclip          # if it prints x11
```

Then clone the repository and run the installer:

```bash
git clone https://github.com/delwinj/hush.git ~/src/hush
cd ~/src/hush
./install.sh
```

The installer copies `hush.py` to `~/.local/bin/hush` and creates the global
secrets file, `~/.config/hush/secrets.txt` (or under `$XDG_CONFIG_HOME` if
set), from `secrets.example.txt` if it doesn't exist. The directory is set to
mode `700` and the file to `600`. `~/.local/bin` must be in `PATH`.

To update, pull, run the tests, then reinstall:

```bash
cd ~/src/hush && git pull && python3 -m unittest test_hush.py && ./install.sh
```

## Secrets files

### Global file

`~/.config/hush/secrets.txt` (or `$XDG_CONFIG_HOME/hush/secrets.txt`) is the
global secrets file. It's always loaded and must exist.

### Additional files

`HUSH_SECRETS_FILES` lists more files to load after the global one, separated
by colons:

```bash
export HUSH_SECRETS_FILES=~/.config/hush/aws.txt:~/.config/hush/lab.txt
```

- Each entry must be an absolute path or start with `~/`. hush expands `~`
  itself, so it works inside quotes too. `$HOME` works when the shell expands
  it (unquoted or in double quotes). Relative paths and empty entries (`::`,
  or a leading or trailing `:`) are errors.
- Every listed file must exist. A file may be empty, but the loaded files
  together must contain at least one secret.
- `--no-global` skips the global file and loads only the listed files.
- `hush --files` prints the files that will be loaded, one per line, in load
  order. It fails if any file is missing, so it also checks the configuration.

### Load order and duplicates

- The global file loads first, then each listed file in order. A file listed
  more than once loads once, at its first position. If the global file is
  listed, that entry is ignored, since the global file has already loaded.
  With `--no-global`, the global file loads only if it's listed, at its
  position in the list.
- When the same secret (ignoring case) is defined more than once, the last
  definition wins, whatever its label. List files from general to specific so
  the more specific labels take precedence.
- A duplicate within one file always produces a warning. Across files, a
  warning appears only when the labels differ, naming both files and lines;
  repeating a value with the same label is silent.

The secret is redacted either way; precedence only decides its placeholder.

### Format

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
  also information, so `redacted` is the better choice unless the distinction
  helps.
- Lines starting with `#` are comments. Blank lines are ignored.
- Whitespace around a line is ignored, so secrets can't start or end with
  spaces.
- Any other line is an error that stops hush. The error gives the file and
  line number, never the line's content.

Secrets files hold secrets in plain text. Keep them at mode `600`, out of
version control and out of shared backups. hush warns if other users can read
one.

## Usage

### Redact piped text

```bash
some-command | hush
some-command 2>&1 | hush               # also redact error output
hush < app.log > app.redacted.log      # redact a file
tail -f app.log | hush                 # follow a log as it grows
some-command | hush | wl-copy          # redact, then copy (X11: xclip -selection clipboard)
```

Text is redacted and written line by line as it arrives, so following
commands like `tail -f` or `kubectl logs -f` works. Redacted text goes to
stdout. A summary such as
`hush: redacted 3: 2 <REDACTED-EMAIL>, 1 <REDACTED-IP>` goes to stderr once
the input ends; `-q` hides it. When the output goes to a terminal, it ends
with a blank line and an `── end ──` rule before the summary, so it's clear
where the text stops.

If a secrets file is missing or invalid, hush exits with an error and writes
nothing to stdout, so text never passes through unredacted.

### Redact the clipboard or primary selection

Linux has two places that hold copied text: the **clipboard** (Ctrl+C,
Ctrl+V) and the **primary selection**, which holds the most recently selected
text and is pasted with a middle click. Copying selected text usually puts it
in both.

```bash
hush -c        # redact the clipboard
hush -p        # redact the primary selection
hush -cp       # redact both
hush -cn       # preview the redacted clipboard, changing nothing
hush -cpn      # preview both
```

- Each selection is read as text, redacted, written back and read again to
  confirm. A selection with nothing to redact isn't touched.
- With `-cp`, both are read and redacted before either is written. Messages
  are labelled with the selection they refer to.
- With only `-c` or only `-p`, hush checks the other selection without
  changing it, and warns if it also contains secrets.
- An empty clipboard is an error. An empty or unsupported primary selection is
  reported and skipped, since there's nothing to paste from it.

`-n` prints the redacted text and changes nothing. With both selections, each
block is labelled: in a terminal with a rule naming it, otherwise with a
`hush: clipboard:` line on stderr. To see only what would be redacted, discard
the text and keep the summary: `hush -cn > /dev/null`.

### Add secrets

`hush add` adds secrets to a secrets file without printing them. Avoid
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

# With a label, a dated comment, or into a specific file
printf '%s\n' "$EMAIL" | hush add -l email
printf '%s\n' "$SECRET" | hush add --note "SAA lab: alice access key"
printf '%s\n' "$TOKEN" | hush add --file ~/.config/hush/work.txt
```

Secrets go to the global file unless `--file` names another one.
`HUSH_SECRETS_FILES` never changes the destination. If the `--file` target
isn't loaded (it isn't the global file or listed in `HUSH_SECRETS_FILES`),
hush adds the secrets and prints a note, since they won't be redacted until
the file is listed.

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
- Secrets under 6 characters are rejected unless `--allow-short` is given.
  Short values get redacted inside unrelated words.
- Secrets with leading or trailing whitespace are rejected.
- Secrets already in the target file are skipped and reported.

New entries are appended to the end of the file. `--note` adds a blank line
and a comment such as `# 2026-11-11: SAA lab: alice access key` above them.
The note is visible in shell history, so never put a secret in it. The file is
replaced atomically, symlinks are followed, and the mode is set to `600`.

## Reference

```text
hush [-q] [--no-global]
hush [-c] [-p] [-n] [-q] [--no-global]
hush --files [--no-global]
hush add [-l LABEL] [--file PATH] [--note TEXT] [--allow-short] [--no-split]
hush --version
```

Short options can be combined in any order: `-cpn` is the same as
`-n -p -c`. For `hush add`, `add` must be the first argument.

| Option | Meaning |
| --- | --- |
| `-c`, `--clipboard` | Redact the clipboard. |
| `-p`, `--primary` | Redact the primary selection. |
| `-n`, `--preview` | With `-c` or `-p`: print the redacted text, changing nothing. |
| `-q`, `--quiet` | Hide the summary and informational messages. Errors, warnings and preview labels still print. |
| `--no-global` | Don't load the global file; use only `HUSH_SECRETS_FILES`. |
| `--files` | Print the files that would be loaded, one per line. |
| `--version` | Print the version. |
| `-h`, `--help` | Show help. `hush add --help` shows help for `add`. |
| `add -l`, `--label LABEL` | Label for new secrets. Default: `redacted`. |
| `add --file PATH` | File to add to. Default: the global file. |
| `add --note TEXT` | Dated comment written above the new secrets. |
| `add --allow-short` | Allow secrets shorter than 6 characters. |
| `add --no-split` | Don't split input lines on tabs. |

| Environment variable | Meaning |
| --- | --- |
| `HUSH_SECRETS_FILES` | Colon-separated list of additional secrets files, loaded after the global file. |
| `XDG_CONFIG_HOME` | Moves the global file to `$XDG_CONFIG_HOME/hush/secrets.txt`. |

| Exit code | Meaning |
| --- | --- |
| `0` | Success, including when nothing matched or nothing new was added. |
| `1` | Error: secrets file, input, clipboard or write failure. |
| `2` | Usage error: invalid options, or nothing piped in without `-c` or `-p`. |
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
  until they're added.
- Clipboard modes handle text only, and need a graphical session (Wayland or
  X11). In an SSH session there usually isn't one; pipe the remote output to
  hush locally instead: `ssh host 'command' | hush`.
- Clipboard managers may keep the unredacted original in their history.
- `hush add` doesn't detect the file being edited at the same time; the last
  write wins.

## Development

```bash
python3 -m unittest -v test_hush.py
```

The tests use temporary files and fake clipboard tools, so they never touch
the real clipboard, primary selection or secrets files. After changing
clipboard code, also check by hand: copy text from a browser and a terminal,
run `hush -c` and `hush -p`, and paste with Ctrl+V and a middle click.

## Uninstall

```bash
rm ~/.local/bin/hush
rm -rf ~/src/hush            # the cloned repository
rm -rf ~/.config/hush        # also deletes all secrets files
```
