#!/usr/bin/env bash
# ⚡ Thunder Node — Install Script
# ════════════════════════════════
# One-line install (Linux and macOS):
#   curl -fsSL https://raw.githubusercontent.com/S6dative/vusd-protocol/main/install/install.sh | bash
#
# What it does:
#   1. Detects your OS and CPU architecture
#   2. Downloads the correct binary from the latest GitHub release
#   3. Verifies the SHA256 checksum
#   4. Installs to /usr/local/bin/thunder (or ~/bin/thunder if no sudo)
#   5. Prints a quick-start guide
#
# Supports:
#   Linux  x86_64   (most servers, desktops)
#   Linux  aarch64  (Raspberry Pi 4/5, AWS Graviton, etc.)
#   macOS  x86_64   (Intel Mac)
#   macOS  arm64    (Apple Silicon: M1/M2/M3/M4)
#
# To install a specific version:
#   THUNDER_VERSION=v0.2.0 curl -fsSL .../install.sh | bash

set -euo pipefail

REPO="S6dative/vusd-protocol"
BINARY="thunder"
INSTALL_DIR="/usr/local/bin"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
BOLD='\033[1m'; RESET='\033[0m'
info()  { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $*"; }
error() { echo -e "${RED}[✗]${RESET} $*" >&2; exit 1; }

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  ⚡ Thunder Node Installer${RESET}"
echo    "  \"You can't see thunder.\""
echo    "  ─────────────────────────────────────────────────────────"
echo ""

# ── Detect OS ─────────────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux*)  PLATFORM="linux"  ;;
  Darwin*) PLATFORM="macos"  ;;
  *)       error "Unsupported OS: $OS. Use the Windows installer from GitHub Releases." ;;
esac

case "$ARCH" in
  x86_64)          CPU="x86_64"  ;;
  aarch64|arm64)   CPU="aarch64" ;;
  *)               error "Unsupported architecture: $ARCH" ;;
esac

# macOS ARM is aarch64 in Rust targets
if [[ "$PLATFORM" == "macos" && "$CPU" == "aarch64" ]]; then
  TARGET="${PLATFORM}-aarch64"
else
  TARGET="${PLATFORM}-${CPU}"
fi

info "Detected: ${PLATFORM} / ${CPU}"

# ── Resolve version ───────────────────────────────────────────────────────────
if [[ -n "${THUNDER_VERSION:-}" ]]; then
  VERSION="$THUNDER_VERSION"
  info "Installing requested version: $VERSION"
else
  info "Fetching latest release version..."
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  [[ -z "$VERSION" ]] && error "Could not determine latest version. Check your internet connection."
  info "Latest version: $VERSION"
fi

# ── Download ──────────────────────────────────────────────────────────────────
FILENAME="${BINARY}-${VERSION}-${TARGET}"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

info "Downloading ${FILENAME}..."
curl -fsSL --progress-bar "${BASE_URL}/${FILENAME}" -o "${TMP_DIR}/${BINARY}"

info "Downloading checksum..."
curl -fsSL "${BASE_URL}/${FILENAME}.sha256" -o "${TMP_DIR}/${FILENAME}.sha256"

# ── Verify checksum ───────────────────────────────────────────────────────────
info "Verifying SHA256 checksum..."

EXPECTED=$(awk '{print $1}' "${TMP_DIR}/${FILENAME}.sha256")
if command -v sha256sum &>/dev/null; then
  ACTUAL=$(sha256sum "${TMP_DIR}/${BINARY}" | awk '{print $1}')
elif command -v shasum &>/dev/null; then
  ACTUAL=$(shasum -a 256 "${TMP_DIR}/${BINARY}" | awk '{print $1}')
else
  warn "Cannot verify checksum: neither sha256sum nor shasum found."
  warn "Proceeding without verification. Install sha256sum for security."
  ACTUAL="$EXPECTED"
fi

if [[ "$ACTUAL" != "$EXPECTED" ]]; then
  error "Checksum mismatch! Expected: $EXPECTED  Got: $ACTUAL\n  The download may be corrupted or tampered with. Aborting."
fi
info "Checksum verified ✓"

# ── Install ───────────────────────────────────────────────────────────────────
chmod +x "${TMP_DIR}/${BINARY}"

# Try system-wide install first; fall back to ~/bin if no sudo
if [[ -w "$INSTALL_DIR" ]] || sudo -n true 2>/dev/null; then
  if [[ -w "$INSTALL_DIR" ]]; then
    cp "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  else
    sudo cp "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  fi
  info "Installed to ${INSTALL_DIR}/${BINARY}"
else
  warn "No write access to ${INSTALL_DIR} and no sudo available."
  warn "Installing to ~/bin instead..."
  mkdir -p "$HOME/bin"
  cp "${TMP_DIR}/${BINARY}" "$HOME/bin/${BINARY}"
  INSTALL_DIR="$HOME/bin"
  info "Installed to ${INSTALL_DIR}/${BINARY}"

  # Check if ~/bin is in PATH
  if [[ ":$PATH:" != *":$HOME/bin:"* ]]; then
    warn "Add this to your shell profile (~/.bashrc, ~/.zshrc):"
    warn "  export PATH=\"\$HOME/bin:\$PATH\""
  fi
fi

# ── Verify ────────────────────────────────────────────────────────────────────
if command -v thunder &>/dev/null; then
  INSTALLED_VERSION=$(thunder --version 2>/dev/null || echo "unknown")
  info "thunder is ready: $INSTALLED_VERSION"
else
  warn "thunder was installed but is not yet in PATH."
  warn "Open a new terminal or run: export PATH=\"${INSTALL_DIR}:\$PATH\""
fi

# ── Quick start ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  Next steps:${RESET}"
echo ""
echo "  1. Generate configuration:"
echo "       thunder setup"
echo ""
echo "  2. Review the 25-threat security matrix:"
echo "       thunder threats"
echo ""
echo "  3. Preview fees for a 1000 VUSD transfer:"
echo "       thunder fees 1000"
echo ""
echo "  4. After configuring Tor + LND:"
echo "       thunder start"
echo ""
echo -e "  ${BOLD}Documentation:${RESET} https://github.com/${REPO}"
echo ""
