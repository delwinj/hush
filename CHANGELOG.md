# Changelog

All notable changes to hush are documented here. Versions follow
[Semantic Versioning](https://semver.org); while hush is below 1.0.0, minor
versions may contain breaking changes.

## [0.4.1] - 2026-11-12

### Changed

- When redacted text is printed to a terminal, each block now ends with a
  blank line and a separator rule, replacing the single blank line, so the
  end of the text is clear even when it contains blank lines. Previews of
  both selections start each block with a rule naming it. Rules fit the
  terminal width, up to 80 characters. Redirected output, in-place redaction
  without a preview, and empty input get no rules.

## [0.4.0] - 2026-11-12

### Changed

- **Breaking:** `-p` now means `--primary`. The short form of `--preview` is
  `-n`.
- `--preview` works with the clipboard, the primary selection or both. With
  both, each block is labelled. It ends with "preview only; nothing was
  modified."
- Piped text is redacted and written line by line as it arrives, so
  following commands like `tail -f` works. The output itself is unchanged.
- Invalid lines no longer get a special hint about 0.1.0 section headers.

### Added

- `-p`/`--primary` to redact the primary selection (select, then middle-click
  paste), alone or together with `-c`.
- With only `-c` or only `-p`, a warning when the other selection also
  contains secrets. The other selection is never changed.

## [0.3.0] - 2026-11-12

### Changed

- **Breaking:** the global secrets file (`~/.config/hush/secrets.txt`) is now
  always loaded. `HUSH_SECRETS_FILE` is no longer read; use
  `HUSH_SECRETS_FILES` to load additional files on top of the global one, or
  add `--no-global` to use only the listed files. Secrets in a file that was
  set through `HUSH_SECRETS_FILE` aren't redacted until that file is listed in
  `HUSH_SECRETS_FILES`.
- **Breaking:** `hush add` writes to the global file by default, instead of
  the file named by `HUSH_SECRETS_FILE`. Use `--file` to add to another file.
- When a secret is defined more than once, the last definition now wins
  instead of the first. Duplicates within a file always produce a warning;
  across files, only when the labels differ.
- When output goes to a terminal, a blank line now separates it from hush's
  messages, so a preview's end is easy to see.

### Added

- `HUSH_SECRETS_FILES`: a colon-separated list of additional secrets files,
  each absolute or starting with `~/`.
- `--no-global` to skip the global secrets file.
- `--files` to print the secrets files that would be loaded, one per line.
- `hush add --file PATH`, with a note when the file isn't currently loaded.

## [0.2.0] - 2026-11-11

### Changed

- **Breaking:** the secrets file format is now one `label: secret` line per
  secret. Unlabeled secrets use the `redacted` label. Section headers
  (`[label]`) and `\` escapes are no longer supported; files from 0.1.0 must
  be converted by hand.
- Secrets may contain any characters, including `:`, `=`, `#` and `[`,
  without escaping.

### Added

- `hush add` adds secrets to the secrets file without printing them, from
  stdin or a hidden prompt. Options: `--label`, `--note` (a dated comment
  above the new entries), `--allow-short` and `--no-split`. Tab-separated
  values on one line are added as separate secrets.
- `--version`.

## [0.1.0] - 2026-11-11

First release.

### Added

- Redaction of piped text (`hush`) and of the clipboard in place
  (`hush -c`), with `--preview` and `--quiet`.
- Secrets file with `[label]` sections, giving placeholders such as
  `<REDACTED-EMAIL>`, and `\` escapes for secrets starting with `#` or `[`.
- Exact, case-insensitive matching; longer secrets take precedence; digit
  boundaries, so `10.10.10.15` doesn't match inside `10.10.10.150`.
- `HUSH_SECRETS_FILE` to use a different secrets file. The file must exist,
  and hush never falls back to another one.
- Clipboard support through `wl-clipboard` (Wayland) or `xclip` (X11), with
  a read-back check after writing.
- Fails closed: on any configuration error, nothing is output and the
  clipboard isn't changed.
- Warnings for duplicate secrets and for secrets files readable by other
  users.
- `install.sh` and a test suite.
