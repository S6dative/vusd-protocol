# Contributing to VUSD Protocol

Thank you for your interest in contributing. VUSD is a security-critical
financial protocol. Contributions are welcome but held to a high standard.

---

## Before You Start

- Read `docs/SECURITY_AUDIT.md` — understand the known limitations and tradeoffs
- Read `SECURITY.md` — security vulnerabilities must be reported privately
- Run `cargo test --workspace` and confirm everything passes before making changes

---

## Development Setup

```bash
# Rust nightly is required (pinned in rust-toolchain.toml)
rustup update nightly

# Clone and build
git clone https://github.com/vusd-protocol/vusd
cd vusd
cargo build --workspace

# Run full test suite
cargo test --workspace

# Lint
cargo clippy --all-targets -- -D warnings

# Format (required before any PR)
cargo fmt --all
```

---

## What We're Looking For

**High priority:**
- Cryptographic improvements (CLSAG ring sigs, full gamma CDF decoy selection)
- Wiring tasks: connecting mock layers to real Bitcoin/LND (see `docs/TESTNET_DEPLOYMENT.md`)
- Test coverage improvements
- Performance optimizations in the privacy layer

**Out of scope (for now):**
- Changing protocol parameters (min CR, liquidation threshold, etc.)
- Adding new collateral types — BTC-only is intentional
- Yield mechanisms on vaults — VUSD is a pure stablecoin
- Governance tokens

---

## Pull Request Process

1. Fork the repo, create a branch: `git checkout -b fix/your-description`
2. Make your changes with clear, focused commits
3. Add or update tests — PRs touching cryptographic code require new tests
4. Run `cargo fmt --all && cargo clippy --all-targets -- -D warnings`
5. Open a PR against `main` with:
   - A clear description of what changed and why
   - Reference to any related issues
   - Test output showing your changes pass

**Cryptographic PRs** (anything in `crates/privacy`, `crates/oracle`, key handling
in `crates/lightning`) require a description of the security properties being
maintained or changed. These PRs will be reviewed more carefully and may take longer.

---

## Code Style

- Standard Rust formatting via `rustfmt` — no exceptions
- No `unwrap()` in production paths — use `?` or explicit error handling
- No `unsafe` without a documented safety comment explaining the invariant
- Domain-separation tags on all hash operations: `SHA256("VUSD_TAG_V1" || data)`
- Constants in `types.rs`, never magic numbers in logic
- Every public function needs a doc comment

---

## Commit Messages

```
component: short imperative description (50 chars max)

Longer explanation if needed. What changed, why it changed,
what invariant is maintained. Reference issues with "Fixes #123".
```

Examples:
- `privacy: randomize ring real_index via OsRng`
- `oracle: add exponential backoff to circuit breaker`
- `engine: reject stale oracle prices at process_price_update entry`

---

## License

By contributing, you agree your contributions are licensed under the MIT License.
