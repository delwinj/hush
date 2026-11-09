# hush

Redact known secrets from terminal output or the clipboard before sharing it.

hush replaces strings you list in a secrets file with labels like
`<REDACTED-EMAIL>`. It does exact, case-insensitive matching only. It never
guesses what might be sensitive, and it never falls back to a different
secrets file than the one configured.

---

## Contents

- [Installation](#installation)
- [Secrets file](#secrets-file)
- [Matching rules](#matching-rules)
- [Command reference](#command-reference)
- [Clipboard usage](#clipboard-usage)
- [Pipe usage](#pipe-usage)
- [Files](#files)
- [Multiple secrets files](#multiple-secrets-files)
- [Keyboard shortcut](#keyboard-shortcut)
- [Shell aliases and functions](#shell-aliases-and-functions)
- [Scripting](#scripting)
- [Messages and errors](#messages-and-errors)
- [Limitations](#limitations)
- [Testing](#testing)
- [Uninstall](#uninstall)

---

## Installation

Requirements: Ubuntu (or similar Linux), the system `python3`, and a clipboard
tool for clipboard mode. hush uses only the Python standard library, so there
is no venv or pip install.

Repo layout:

```text
hush/
├── hush.py               # the tool
├── install.sh            # installer
├── secrets.example.txt   # template for a new secrets file
├── test_hush.py          # test suite
└── README.md
```

Install the clipboard tool for your session type:

```bash
echo "$XDG_SESSION_TYPE"

sudo apt install wl-clipboard   # if it printed: wayland
sudo apt install xclip          # if it printed: x11
```

Install hush from the repo:

```bash
git clone <repo-url> ~/src/hush
cd ~/src/hush
./install.sh
```

The installer:

- copies `hush.py` to `~/.local/bin/hush`
- creates `~/.config/hush/` with mode `700`
- creates `~/.config/hush/secrets.txt` from the example (mode `600`),
  or keeps and re-secures your existing one
- warns if `~/.local/bin` isn't in your `PATH` or the clipboard tool is missing

Update:

```bash
cd ~/src/hush
git pull
python3 -m unittest test_hush.py && ./install.sh
```

Verify:

```bash
hush --help
echo | hush        # checks that the secrets file loads
```

If `~/.local/bin` isn't in your `PATH`, add this to `~/.bashrc` and run
`source ~/.bashrc`:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

---

## Secrets file

Default location: `~/.config/hush/secrets.txt`
(or `$XDG_CONFIG_HOME/hush/secrets.txt` if `XDG_CONFIG_HOME` is set).

Edit it:

```bash
nano ~/.config/hush/secrets.txt
```

### Format

- One secret per line.
- Blank lines and lines starting with `#` are ignored.
- Leading and trailing whitespace on each line is ignored (but see the `\`
  prefix below).
- Secrets before any section header are replaced with `<REDACTED>`.
- A `[label]` header applies that label to every secret below it, until the
  next header. The replacement is `<REDACTED-LABEL>` (uppercased).
- `[redacted]` switches back to plain `<REDACTED>`.
- Labels may contain letters, digits, `-` and `_`.
- A line starting with `\` is taken literally, minus the backslash. Use this
  for secrets that start with `#`, `[` or spaces. Trailing spaces are still
  removed.
- Duplicate secrets (same text, ignoring case) are ignored with a warning;
  the first one wins.
- The file must be UTF-8. A byte-order mark added by some editors is ignored.

### Example

```text
# Unlabeled: replaced with <REDACTED>
AKIAIOSFODNN7EXAMPLE
my-secret-access-key

[email]
john@example.com
john.doe@gmail.com

[ip]
10.10.10.15
192.168.50.7

[hostname]
my-private-server
db-prod-01.internal

[domain]
company-internal-domain.com

[aws-account-id]
123456789012

[password]
my-database-password
dGVzdA==
pass=word
\#starts-with-hash
\[looks-like-a-header]

[redacted]
# Back to plain <REDACTED>
some-other-token
```

### Resulting replacements

| Line in secrets file | Under section | Replaced with |
| --- | --- | --- |
| `AKIAIOSFODNN7EXAMPLE` | none | `<REDACTED>` |
| `john@example.com` | `[email]` | `<REDACTED-EMAIL>` |
| `10.10.10.15` | `[ip]` | `<REDACTED-IP>` |
| `123456789012` | `[aws-account-id]` | `<REDACTED-AWS-ACCOUNT-ID>` |
| `dGVzdA==` | `[password]` | `<REDACTED-PASSWORD>` |
| `pass=word` | `[password]` | `<REDACTED-PASSWORD>` |
| `\#starts-with-hash` | `[password]` | `#starts-with-hash` → `<REDACTED-PASSWORD>` |
| `some-other-token` | `[redacted]` | `<REDACTED>` |

### Permissions

The file holds every secret you list, in plain text. Keep it private:

```bash
chmod 700 ~/.config/hush
chmod 600 ~/.config/hush/*.txt
```

hush warns on every run if the file is readable by other users. Keep it out of
Git repositories, dotfile repos and backups you share.

---

## Matching rules

- **Literal:** characters like `.`, `*` and `$` have no special meaning.
  `my.password` matches only `my.password`.
- **Case-insensitive:** `john@example.com` also matches `JOHN@Example.COM`.
- **Longest first:** if one secret contains another, the longer one wins.
- **Digit boundaries:** if a secret starts or ends with a digit, it won't
  match when another digit is directly next to it on that side. This stops
  `10.10.10.15` matching inside `10.10.10.150`.
- **No letter boundaries:** letters next to a secret never prevent a match.
  Escapes like `\n` and URL encoding like `%3D` put letters right before real
  secrets, and redacting a little too much is safer than leaking.

With `10.10.10.15` (under `[ip]`) and `mysecret` (unlabeled) configured:

| Input | Output |
| --- | --- |
| `10.10.10.15` | `<REDACTED-IP>` |
| `host=10.10.10.15:8080` | `host=<REDACTED-IP>:8080` |
| `10.10.10.150` | `10.10.10.150` (different IP, not touched) |
| `110.10.10.15` | `110.10.10.15` (different IP, not touched) |
| `MYSECRET` | `<REDACTED>` |
| `mysecret_backup` | `<REDACTED>_backup` |
| `mysecret-v2` | `<REDACTED>-v2` |
| `"mysecret"` | `"<REDACTED>"` |
| `mysecretABC` | `<REDACTED>ABC` |
| `xmysecret` | `x<REDACTED>` |
| `token%3Dmysecret%26` | `token%3D<REDACTED>%26` |
| `"line\nmysecret"` | `"line\n<REDACTED>"` |

---

## Command reference

```text
hush [-c] [-p] [-q]
```

| Option | Meaning |
| --- | --- |
| *(none)* | Read stdin, write redacted text to stdout. |
| `-c`, `--clipboard` | Redact the clipboard in place. |
| `-p`, `--preview` | With `-c`: print the redacted clipboard, don't modify it. |
| `-q`, `--quiet` | Don't print the summary or informational messages. Errors and warnings still print. |
| `-h`, `--help` | Show help, including which secrets file applies. |

| Environment variable | Meaning |
| --- | --- |
| `HUSH_SECRETS_FILE` | Use this secrets file instead of the default. Must exist. |

| Exit code | Meaning |
| --- | --- |
| `0` | Success (including when nothing matched). |
| `1` | Error: configuration, clipboard, or verification failure. |
| `2` | Usage error (bad options, or nothing piped in without `-c`). |
| `130` | Cancelled with Ctrl+C. |

Messages always go to stderr; only the redacted text goes to stdout.

---

## Clipboard usage

### Redact the clipboard in place

```bash
hush -c
```

1. Reads the clipboard as text.
2. Redacts it.
3. Writes the result back, if anything matched.
4. Reads the clipboard again, retrying for up to about half a second, and
   confirms it holds the redacted text.

Then paste as usual.

```text
hush: redacted 3: 2 <REDACTED-EMAIL>, 1 <REDACTED-IP>
```

If nothing matched, the clipboard isn't touched:

```text
hush: no configured secrets found; text unchanged.
```

### Preview first

```bash
hush -c -p
```

Prints the redacted text to the terminal and leaves the clipboard unchanged.
Run `hush -c` afterwards if it looks right.

### Preview through a pager

```bash
hush -c -p | less
```

### Redact silently

```bash
hush -c -q
```

### Typical flow

```bash
# 1. Copy text from a terminal, browser, log viewer, etc.
# 2. Check it:
hush -c -p
# 3. Redact it:
hush -c
# 4. Paste into a chat, issue tracker, forum or search engine.
```

---

## Pipe usage

Without `-c`, hush is a filter: text in, redacted text out.

Most CLI tools write errors to stderr, which a plain `|` doesn't pass along.
Add `2>&1` when you want error output redacted too:

```bash
some-command 2>&1 | hush
```

### Redact and copy to the clipboard in one step

```bash
some-command 2>&1 | hush | wl-copy                      # Wayland
some-command 2>&1 | hush | xclip -selection clipboard   # X11
```

### View on screen

```bash
some-command | hush | less
```

### Environment and shell

```bash
env | hush
printenv | hush
set | hush
cat ~/.bashrc | hush
history | hush
```

### AWS

```bash
aws sts get-caller-identity | hush
aws configure list | hush
aws configure list-profiles | hush
cat ~/.aws/config | hush
aws ec2 describe-instances --output table | hush
aws ec2 describe-security-groups | hush
aws s3 ls 2>&1 | hush
aws iam list-roles | hush
aws logs tail /aws/lambda/my-function --since 1h | hush
aws cloudformation describe-stack-events --stack-name my-stack | hush
```

### Kubernetes

```bash
kubectl get pods -o wide | hush
kubectl describe pod my-pod | hush
kubectl logs my-pod --tail=200 | hush
kubectl get events --sort-by=.lastTimestamp | hush
kubectl get configmap my-config -o yaml | hush
kubectl get ingress -A | hush
kubectl config view | hush
```

### Docker

```bash
docker ps | hush
docker inspect my-container | hush
docker logs my-container 2>&1 | hush
docker compose config | hush      # shows resolved env values: redact before sharing
docker compose logs --tail=200 2>&1 | hush
```

### Terraform

```bash
terraform plan -no-color 2>&1 | hush
terraform output | hush
terraform show -no-color | hush
```

### Git

```bash
git remote -v | hush
git log -5 | hush
git diff | hush
git config --list | hush
```

### System logs and services

```bash
journalctl -u nginx --since today | hush
journalctl -b -p err | hush
systemctl status my-service 2>&1 | hush
dmesg | tail -50 | hush
```

### Networking

```bash
ip addr | hush
ss -tlnp 2>&1 | hush
cat /etc/hosts | hush
cat ~/.ssh/config | hush
curl -sv https://internal.example.com 2>&1 | hush
dig my-private-server.internal | hush
```

### Remote output

The command runs on the remote host; redaction happens locally.

```bash
ssh my-private-server 'journalctl -u app --since "1 hour ago"' | hush
ssh my-private-server 'cat /etc/app/config.yml' | hush
```

### Here-strings and quick tests

```bash
echo "Contact JOHN@example.com at 10.10.10.15" | hush
hush <<< "password is my-database-password"
```

---

## Files

hush reads stdin, so use shell redirection for files.

### Print a redacted file

```bash
hush < application.log
```

### Write a redacted copy

```bash
hush < application.log > application.redacted.log
```

Never redirect output to the input file (`hush < a.log > a.log`); the shell
empties the file before hush reads it.

### Several files

```bash
cat app.log worker.log | hush > combined.redacted.log
```

### Each file separately

```bash
for f in logs/*.log; do
    hush -q < "$f" > "${f%.log}.redacted.log"
done
```

### Compressed logs

```bash
zcat app.log.1.gz | hush
```

### Part of a large log

```bash
tail -n 500 application.log | hush
grep -i error application.log | hush
```

---

## Multiple secrets files

Keep one file per environment, all outside your repositories:

```text
~/.config/hush/
├── secrets.txt            # default
├── company-project-a.txt
├── company-project-b.txt
└── personal-project.txt
```

### For a single command

```bash
HUSH_SECRETS_FILE=~/.config/hush/company-project-a.txt hush -c
kubectl describe pod x | HUSH_SECRETS_FILE=~/.config/hush/company-project-a.txt hush
```

The variable goes right before `hush`, not before the first command in the
pipeline.

### For the current terminal session

```bash
export HUSH_SECRETS_FILE="$HOME/.config/hush/company-project-a.txt"
hush -c
env | hush
```

### Back to the default file

```bash
unset HUSH_SECRETS_FILE
```

### Check which file applies

```bash
echo "${HUSH_SECRETS_FILE:-default}"
hush --help | tail -2
```

### New secrets file

```bash
install -m600 /dev/null ~/.config/hush/company-project-c.txt
nano ~/.config/hush/company-project-c.txt
```

Only one secrets file is used per run. To cover shared entries, repeat them in
each file.

---

## Keyboard shortcut

Bind `hush -c` to a key so you can redact the clipboard without opening a
terminal.

GNOME: **Settings → Keyboard → View and Customize Shortcuts → Custom
Shortcuts → +**

- Name: `hush clipboard`
- Command:

  ```text
  sh -c '"$HOME/.local/bin/hush" -c -q || notify-send -u critical "hush" "Clipboard redaction FAILED. Do not paste."'
  ```

- Shortcut: for example `Super+Shift+H`

Shortcuts don't read `~/.bashrc`, so use the full path. The `notify-send`
fallback matters because there's no terminal to show errors.

For a separate secrets file:

```text
sh -c 'HUSH_SECRETS_FILE="$HOME/.config/hush/company-project-a.txt" "$HOME/.local/bin/hush" -c -q || notify-send -u critical "hush" "Clipboard redaction FAILED. Do not paste."'
```

On GNOME Wayland, the clipboard tools may briefly flash a small window while
reading or writing. That's expected.

---

## Shell aliases and functions

Add to `~/.bashrc`:

```bash
# Short forms
alias hc='hush -c'
alias hp='hush -c -p'

# Per-project
alias hush-a='HUSH_SECRETS_FILE="$HOME/.config/hush/company-project-a.txt" hush'
alias hush-b='HUSH_SECRETS_FILE="$HOME/.config/hush/company-project-b.txt" hush'

# Run a command, redact stdout and stderr, and copy the result
hcopy() {
    "$@" 2>&1 | hush | wl-copy     # use: xclip -selection clipboard on X11
}

# Switch the session's secrets file by name
hush-use() {
    if [ -z "${1:-}" ]; then
        unset HUSH_SECRETS_FILE
        echo "hush: using default secrets file"
    else
        export HUSH_SECRETS_FILE="$HOME/.config/hush/$1.txt"
        echo "hush: using $HUSH_SECRETS_FILE"
    fi
}

# Edit the secrets file currently in effect
hush-edit() {
    "${EDITOR:-nano}" "${HUSH_SECRETS_FILE:-$HOME/.config/hush/secrets.txt}"
}
```

Usage:

```bash
hcopy kubectl describe pod my-pod
hcopy aws sts get-caller-identity
hush-use company-project-a
hush-use                 # back to default
hush-a -c
hush-edit
```

---

## Scripting

### Stop a pipeline when hush fails

By default a pipeline's exit status is the last command's. Use `pipefail` so
a failure anywhere is reported:

```bash
set -o pipefail
aws sts get-caller-identity | hush > identity.txt || echo "failed"
```

### Never write unredacted output

If hush fails, it writes nothing to stdout. Guard the output file so a
failure doesn't leave a misleading empty file:

```bash
set -o pipefail
if kubectl logs my-pod 2>&1 | hush -q > pod.redacted.log; then
    echo "saved pod.redacted.log"
else
    rm -f pod.redacted.log
    echo "redaction failed" >&2
fi
```

### Check the configuration

```bash
echo | hush && echo "config OK"
```

---

## Messages and errors

All messages go to stderr, prefixed with `hush:`.

### Informational

| Message | Meaning |
| --- | --- |
| `redacted N: ...` | Summary of replacements made. |
| `no configured secrets found; text unchanged.` | Nothing matched. If you expected matches, check you're using the right secrets file. |
| `preview only; clipboard was NOT modified.` | Shown after `-c -p`. |

### Warnings (hush continues)

| Message | Fix |
| --- | --- |
| `WARNING: <file> is accessible by other users.` | `chmod 600 <file>` |
| `WARNING: duplicate secret on line N ignored` | Remove the duplicate line. |

### Errors (hush stops; nothing is output or changed)

| Message | Cause and fix |
| --- | --- |
| `Secrets file not found (HUSH_SECRETS_FILE): <path>` | The file named in the variable doesn't exist. Fix the path or `unset HUSH_SECRETS_FILE`. |
| `Secrets file not found (default location): <path>` | Run `./install.sh` or create the file. |
| `HUSH_SECRETS_FILE is set but empty.` | `unset HUSH_SECRETS_FILE` or set a path. |
| `Unable to access secrets file (...): <path>` | A directory on the path can't be read. Check its permissions. |
| `Secrets path is not a regular file` | The path is a directory or special file. |
| `Unable to read secrets file <path>` | The file's permissions block reading, or it isn't valid UTF-8. |
| `No secrets defined in <path>` | The file has only comments or blank lines. Add secrets. |
| `Invalid section header on line N` | Fix the label (letters, digits, `-`, `_`), or prefix the line with `\` if it's a secret. |
| `Wayland session detected but wl-clipboard is not installed.` | `sudo apt install wl-clipboard` |
| `X11 session detected but xclip is not installed.` | `sudo apt install xclip` |
| `No graphical session found` | Clipboard mode needs a desktop session. Over SSH, use pipe mode. |
| `Unable to read clipboard as text` | The clipboard is empty or holds an image or file. |
| `Timed out reading the clipboard.` | Retry; check the clipboard tool works with `wl-paste` or `xclip -o -selection clipboard`. |
| `Unable to write the clipboard. Do NOT paste.` | The clipboard still holds the original text. |
| `Clipboard verification failed. Do NOT paste` | Something else changed the clipboard, or the write failed. Check before pasting. |
| `no input piped` (exit 2) | You ran `hush` alone. Pipe something in or use `-c`. |

---

## Limitations

- Only secrets you list are redacted. Anything else, including new or rotated
  credentials, passes through.
- A secret that starts or ends with a digit isn't matched when another digit
  is directly next to it on that side (see [Matching rules](#matching-rules)).
- Only one secrets file is used per run.
- Input is read in full before output, so streaming commands like
  `tail -f` or `kubectl logs -f` never produce output. Use a bounded
  version (`tail -n 500`, `kubectl logs --tail=500`).
- Clipboard mode handles text only, not images or files.
- Clipboard managers may keep the original unredacted copy in their history.
  Clear it there if needed.
- Selecting text with the mouse also copies it to the primary selection
  (pasted with a middle click). hush only redacts the regular clipboard, so
  paste with Ctrl+V after running `hush -c`.
- Trailing whitespace in a secret can't be represented. Leading whitespace
  can, with a `\` prefix.

---

## Testing

Run the test suite from the repo:

```bash
cd ~/src/hush
python3 -m unittest -v test_hush.py
```

The suite covers parsing, matching, secrets file lookup and errors, pipe
mode, and clipboard mode. Clipboard tests use fake `wl-paste`, `wl-copy` and
`xclip` scripts in a temporary directory, so they run without a desktop and
never touch your real clipboard or secrets files.

Run it after any change to `hush.py`, before `./install.sh`.

The tests can't reproduce real clipboard behavior, so after changes to
clipboard code also check by hand:

- Copy text from a browser, a terminal and an editor; run `hush -c` and paste.
- Copy an image; `hush -c` should refuse with a clear error.
- Copy text with non-English characters; it should survive intact.
- Trigger the keyboard shortcut with a missing secrets file; the failure
  notification should appear.

---

## Uninstall

```bash
rm ~/.local/bin/hush
rm -rf ~/.config/hush        # deletes your secrets files too
```
