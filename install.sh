#!/usr/bin/env bash
set -e

echo -e "\033[1;36m[*] Installing BugScanX-Go Global Terminal Commands (scan, bugscanxgo, bugscanx-go, bugscanx, bx)...\033[0m"

ARCH=$(uname -m)
if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    BIN_NAME="bugscanx-android-arm64"
elif [[ "$ARCH" == "x86_64" || "$ARCH" == "amd64" ]]; then
    BIN_NAME="bugscanx-linux-amd64"
else
    BIN_NAME=""
fi

if [[ -n "$BIN_NAME" && -f "./dist/$BIN_NAME" ]]; then
    BIN_PATH="./dist/$BIN_NAME"
elif [[ -n "$BIN_NAME" ]]; then
    echo -e "\033[1;36m[*] Downloading pre-built binary ($BIN_NAME) from GitHub...\033[0m"
    curl -fL "https://raw.githubusercontent.com/HMACreations/bugscanx-go/main/dist/$BIN_NAME" -o "./$BIN_NAME" && BIN_PATH="./$BIN_NAME"
fi

if [[ -z "$BIN_PATH" || ! -f "$BIN_PATH" ]]; then
    echo -e "\033[1;33m[*] Building from Go source...\033[0m"
    go build -ldflags="-s -w" -o bugscanx .
    BIN_PATH="./bugscanx"
fi

chmod +x "$BIN_PATH"

COMMANDS=("scan" "bugscanxgo" "bugscanx-go" "bugscanx" "bx")

# 1. Android Termux ($PREFIX/bin)
if [[ -n "$PREFIX" && -d "$PREFIX/bin" ]]; then
    INSTALL_DIR="$PREFIX/bin"
# 2. Root / Writable /usr/local/bin
elif [[ -w "/usr/local/bin" ]]; then
    INSTALL_DIR="/usr/local/bin"
# 3. User-level ~/.local/bin (Termius Local Shell / Non-root Linux)
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

for cmd in "${COMMANDS[@]}"; do
    cp -f "$BIN_PATH" "$INSTALL_DIR/$cmd"
    chmod +x "$INSTALL_DIR/$cmd"
done

# Ensure ~/.local/bin and aliases are in shell profiles (.bashrc, .zshrc, .profile)
for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [[ -f "$rc" ]] || [[ "$rc" == "$HOME/.bashrc" ]]; then
        touch "$rc"
        if ! grep -q "$INSTALL_DIR" "$rc" 2>/dev/null; then
            echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$rc"
        fi
    fi
done

echo -e "\033[1;32m[✓] Installed successfully into: $INSTALL_DIR\033[0m"
echo -e "\033[1;32m[✓] You can now open the tool from anywhere by typing:\033[0m"
echo -e "    \033[1;36mscan\033[0m  OR  \033[1;36mbugscanxgo\033[0m  OR  \033[1;36mbugscanx-go\033[0m  OR  \033[1;36mbx\033[0m"
