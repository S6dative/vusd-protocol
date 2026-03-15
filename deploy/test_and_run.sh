#!/usr/bin/env bash
# VUSD Protocol — local test + run script
# Run this on any machine with Rust installed.
# No network connectivity, no Bitcoin node, no LND required.

set -euo pipefail

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

step() { echo -e "${YELLOW}==> $1${NC}"; }
ok()   { echo -e "${GREEN}✓ $1${NC}"; }
fail() { echo -e "${RED}✗ $1${NC}"; exit 1; }

step "Checking Rust toolchain"
rustc --version || fail "Rust not installed. Run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
cargo --version
ok "Rust toolchain OK"

step "cargo fmt check"
cargo fmt --all -- --check && ok "Formatting OK" || echo "Warning: formatting issues (non-fatal)"

step "cargo build (debug)"
cargo build --workspace 2>&1 | tail -5
ok "Build OK"

step "Unit tests — vscx-core"
cargo test -p vscx-core --lib -- --test-threads=4
ok "vscx-core tests passed"

step "Unit tests — oracle (BIP-340 Schnorr)"
cargo test -p oracle --lib -- --test-threads=4
ok "oracle tests passed"

step "Unit tests — privacy (ring sigs, Bulletproofs, stealth addrs)"
cargo test -p privacy --lib -- --test-threads=4
ok "privacy tests passed"

step "Unit tests — lightning"
cargo test -p lightning --lib -- --test-threads=4
ok "lightning tests passed"

step "Unit tests — taproot-vault (Bitcoin tx building)"
cargo test -p taproot-vault --lib -- --test-threads=4
ok "taproot-vault tests passed"

step "Unit tests — keeper"
cargo test -p keeper --lib -- --test-threads=4
ok "keeper tests passed"

step "Integration tests (full protocol)"
cargo test --test full_protocol_test -- --test-threads=2
ok "Integration tests passed"

step "cargo demo (full system walkthrough)"
cargo run -p vusd-cli -- demo
ok "Demo ran successfully"

echo ""
echo -e "${GREEN}All tests passed. VUSD Protocol is ready for testnet.${NC}"
echo ""
echo "Next steps:"
echo "  1. cp deploy/.env.example deploy/.env && edit with real keys"
echo "  2. docker compose -f deploy/docker-compose.yml up bitcoind"
echo "  3. docker compose -f deploy/docker-compose.yml up"
echo "  4. cargo run -p testnet -- checklist"
