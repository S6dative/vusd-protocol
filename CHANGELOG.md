# Changelog

All notable changes to VUSD Protocol are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

---

## [Unreleased] — Pre-testnet

### Added
- Complete vault state machine: 7 states, all transitions enforced (`vscx-core`)
- 5-of-7 Schnorr oracle quorum with 5 live exchange feeds (`oracle`)
- Oracle staleness gate on `process_price_update()` — rejects prices older than 10 min
- Per-feed circuit breaker with exponential backoff (5s → 300s) (`oracle`)
- Docker secrets overlay for oracle private keys (`deploy/docker-compose.secrets.yml`)
- Keeper bot with permissionless liquidation and 6-hour Dutch auction (`keeper`)
- Taproot MAST with 3 spend paths: repay / liquidation / emergency CSV (`taproot-vault`)
- Real rust-bitcoin 0.31 Taproot transaction building for all vault operations
- Stealth address derivation — dual-key Monero-style OTA = H_s(r·V)·G + S (`privacy`)
- Borromean ring signatures — 11-member ring, full closure check (`privacy`)
- Pedersen commitments unified with bulletproofs PedersenGens — commitments interchangeable
- Bulletproof range proofs — proves v ∈ [0, 2^64) without revealing v (`privacy`)
- RingCT balance check — `verify_commitment_sum()` on Ristretto255 points
- Key images — double-spend prevention via I = x·H_p(P) (`privacy`)
- Gamma-distributed decoy selection — power-law recency bias (Monero-style) (`privacy`)
- Sender-side ECDH — `derive_shared_secret_sender(ephemeral_seed, view_pubkey)` computes r·V
- ECDH symmetry verified: sender r·V = recipient v·R, tests added
- Real Ristretto255 ECDH in Lightning — replaces hash-based fake ECDH (`lightning`)
- Lightning VUSD wallet — keysend TLV transfer protocol, amount encryption (`lightning`)
- LND gRPC client structure — TLS + macaroon auth, keysend TLV type 5_482_373_486 (`lightning`)
- Vault CLI with full operator dashboard: open, mint, health, repay, close, keeper (`cli`)
- Testnet harness: 24-item checklist, 4 chaos scenarios, benchmarks (`testnet`)
- GitHub Actions CI: fmt, clippy, test, build, cargo-audit, cargo-deny
- `rust-toolchain.toml` pinning nightly (required for curve25519-dalek v3)

### Fixed
- `apply_transaction()` ring sig verification — was reconstructing message from zero amounts
- `create_transfer()` real signer position — was always 0, now randomized via OsRng
- Sender ECDH key material — was passing blinding scalar; now uses correct `r·V` derivation
- `derive_one_time_address` missing `&` borrow at call site
- `verify_commitment_sum` try_fold type ambiguity — refactored to explicit closure
- Ephemeral seeds internalized — removed from all public APIs, generated from OsRng
- Pedersen generator inconsistency — unified both paths to `PedersenGens::default()`
- `u128 → u64` overflow guard added in `commit()` and `prove()`
- Watch-only wallet silent skip — now explicitly logged at `debug!` level

### Security
- Oracle private key seeds moved to Docker secrets (VUSD_PRIVKEY_SEED_FILE)
- Domain-separated hash tags on all key derivations and ring hash operations
- All ephemeral seeds generated from `OsRng` — never accepted from callers

---

*Pre-release — no stable API yet.*
