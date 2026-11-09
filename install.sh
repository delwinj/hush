#!/bin/sh
set -eu

cd "$(dirname "$0")"

BIN_DIR="$HOME/.local/bin"
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/hush"
SECRETS="$CONFIG_DIR/secrets.txt"

install -Dm755 hush.py "$BIN_DIR/hush"
echo "Installed $BIN_DIR/hush"

install -d -m700 "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

if [ -e "$SECRETS" ]; then
    chmod 600 "$SECRETS"
    echo "Kept existing $SECRETS"
else
    install -m600 secrets.example.txt "$SECRETS"
    echo "Created $SECRETS from the example. Add your secrets before use."
fi

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "Note: $BIN_DIR is not in your PATH. Add to ~/.bashrc:"
       echo "  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

case "${XDG_SESSION_TYPE:-}" in
    wayland) command -v wl-copy >/dev/null ||
        echo "Note: run 'sudo apt install wl-clipboard' for clipboard mode." ;;
    x11) command -v xclip >/dev/null ||
        echo "Note: run 'sudo apt install xclip' for clipboard mode." ;;
esac

