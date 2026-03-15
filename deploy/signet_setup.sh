#!/usr/bin/env bash
# deploy/signet_setup.sh
#
# VUSD Protocol — Signet Node Setup
#
# Installs and configures:
#   - Bitcoin Core (signet)
#   - LND (with Tor)
#   - Tor
#   - VUSD vault CLI
#
# Run as a non-root user with sudo access.
# Tested on Ubuntu 22.04 / 24.04.
#
# Usage:
#   chmod +x signet_setup.sh
#   ./signet_setup.sh

set -euo pipefail

BITCOIN_VERSION="26.0"
LND_VERSION="0.18.3-beta"
VUSD_DIR="$HOME/.vusd"
BITCOIN_DIR="$HOME/.bitcoin"
LND_DIR="$HOME/.lnd"

echo "⚡ VUSD Signet Node Setup"
echo "═══════════════════════════════════════"

# ── Dependencies ──────────────────────────────────────────────────────────────
echo ""
echo "[ 1/7 ] Installing dependencies..."
sudo apt-get update -qq
sudo apt-get install -y tor curl wget jq build-essential pkg-config \
    libssl-dev git unzip

# ── Rust ─────────────────────────────────────────────────────────────────────
if ! command -v cargo &>/dev/null; then
    echo "[ 2/7 ] Installing Rust..."
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
    source "$HOME/.cargo/env"
else
    echo "[ 2/7 ] Rust already installed: $(rustc --version)"
fi

# ── Bitcoin Core ─────────────────────────────────────────────────────────────
if ! command -v bitcoind &>/dev/null; then
    echo "[ 3/7 ] Installing Bitcoin Core ${BITCOIN_VERSION}..."
    cd /tmp
    wget -q "https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz"
    tar -xzf "bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz"
    sudo install -m 0755 -t /usr/local/bin "bitcoin-${BITCOIN_VERSION}/bin/bitcoind" "bitcoin-${BITCOIN_VERSION}/bin/bitcoin-cli"
    rm -rf bitcoin-${BITCOIN_VERSION}*
else
    echo "[ 3/7 ] bitcoind already installed: $(bitcoind --version | head -1)"
fi

mkdir -p "$BITCOIN_DIR"
cp "$(dirname "$0")/bitcoin.conf" "$BITCOIN_DIR/bitcoin.conf"
echo "  ✓ bitcoin.conf installed to $BITCOIN_DIR"

# ── LND ──────────────────────────────────────────────────────────────────────
if ! command -v lnd &>/dev/null; then
    echo "[ 4/7 ] Installing LND ${LND_VERSION}..."
    cd /tmp
    wget -q "https://github.com/lightningnetwork/lnd/releases/download/v${LND_VERSION}/lnd-linux-amd64-v${LND_VERSION}.tar.gz"
    tar -xzf "lnd-linux-amd64-v${LND_VERSION}.tar.gz"
    sudo install -m 0755 -t /usr/local/bin "lnd-linux-amd64-v${LND_VERSION}/lnd" "lnd-linux-amd64-v${LND_VERSION}/lncli"
    rm -rf lnd-linux-amd64*
else
    echo "[ 4/7 ] lnd already installed: $(lnd --version)"
fi

mkdir -p "$LND_DIR"
cp "$(dirname "$0")/lnd.conf" "$LND_DIR/lnd.conf"
echo "  ✓ lnd.conf installed to $LND_DIR"

# ── Tor ───────────────────────────────────────────────────────────────────────
echo "[ 5/7 ] Configuring Tor..."
sudo systemctl enable tor
sudo systemctl start tor
echo "  ✓ Tor started"

# ── Build VUSD ────────────────────────────────────────────────────────────────
echo "[ 6/7 ] Building VUSD Protocol..."
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"
cargo build --release --bin vusd --bin vusd-testnet 2>&1 | tail -5
echo "  ✓ VUSD built: target/release/vusd"

# ── Start bitcoind ────────────────────────────────────────────────────────────
echo "[ 7/7 ] Starting bitcoind on signet..."
bitcoind -signet -daemon
echo "  ✓ bitcoind starting — sync will take a few minutes"
echo "  Monitor: bitcoin-cli -signet getblockchaininfo"

echo ""
echo "═══════════════════════════════════════"
echo "  ✅ Setup complete!"
echo ""
echo "  Next steps:"
echo "  1. Wait for bitcoind to sync:  bitcoin-cli -signet getblockchaininfo"
echo "  2. Start LND:                  lnd --configfile=$LND_DIR/lnd.conf"
echo "  3. Create LND wallet:          lncli --network=signet create"
echo "  4. Get signet BTC:             https://signetfaucet.com"
echo "  5. Check your .onion address:  cat /var/lib/tor/hidden_service/hostname"
echo "  6. Run VUSD checklist:         ./target/release/vusd-testnet checklist"
echo "  7. Open your first vault:      ./target/release/vusd open-vault --collateral 0.1"
echo ""
