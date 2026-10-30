#!/usr/bin/env bash
set -e

echo -e "\033[1;36m[*] Installing BugScanX-Go...\033[0m"

ARCH=$(uname -m)
if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    BIN_NAME="bugscanx-android-arm64"
elif [[ "$ARCH" == "x86_64" || "$ARCH" == "amd64" ]]; then
    BIN_NAME="bugscanx-linux-amd64"
else
    echo -e "\033[1;33m[!] Architecture $ARCH not pre-built. Building from source with Go...\033[0m"
    go build -ldflags="-s -w" -o bugscanx .
    BIN_PATH="./bugscanx"
fi

if [[ -z "$BIN_PATH" ]]; then
    if [[ -f "./dist/$BIN_NAME" ]]; then
        BIN_PATH="./dist/$BIN_NAME"
    else
        echo -e "\033[1;36m[*] Downloading pre-built binary ($BIN_NAME) from GitHub...\033[0m"
        curl -fL "https://raw.githubusercontent.com/HMACreations/bugscanx-go/main/dist/$BIN_NAME" -o "./$BIN_NAME" && BIN_PATH="./$BIN_NAME"
    fi
fi

if [[ -z "$BIN_PATH" || ! -f "$BIN_PATH" ]]; then
    echo -e "\033[1;33m[*] Building from Go source...\033[0m"
    go build -ldflags="-s -w" -o bugscanx .
    BIN_PATH="./bugscanx"
fi

chmod +x "$BIN_PATH"

# Detect Android Termux ($PREFIX/bin) vs Standard Linux (/usr/local/bin or ~/.local/bin)
if [[ -n "$PREFIX" && -d "$PREFIX/bin" ]]; then
    cp "$BIN_PATH" "$PREFIX/bin/bugscanx"
    cp "$BIN_PATH" "$PREFIX/bin/bx"
    chmod +x "$PREFIX/bin/bugscanx" "$PREFIX/bin/bx"
    echo -e "\033[1;32m[✓] Installed to Termux: Run 'bugscanx' or 'bx' from anywhere!\033[0m"
elif [[ -w "/usr/local/bin" ]]; then
    cp "$BIN_PATH" "/usr/local/bin/bugscanx"
    cp "$BIN_PATH" "/usr/local/bin/bx"
    chmod +x "/usr/local/bin/bugscanx" "/usr/local/bin/bx"
    echo -e "\033[1;32m[✓] Installed to /usr/local/bin: Run 'bugscanx' or 'bx' from anywhere!\033[0m"
else
    cp "$BIN_PATH" "./bugscanx"
    chmod +x "./bugscanx"
    echo -e "\033[1;32m[✓] Ready! Run './bugscanx' to start.\033[0m"
fi
