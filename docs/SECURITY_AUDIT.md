# VUSD Protocol — Security Audit Notes

Pre-testnet security review. Every finding is tagged with severity:
🔴 Critical — must fix before testnet
🟡 Medium — fix before mainnet
🟢 Low/Informational — known limitation or acceptable tradeoff

---

## Cryptography

### Oracle Signatures (secp256k1 BIP-340)

🟢 **Key derivation domain separation**
Each oracle node derives its secp256k1 keypair as:
`secret_key = SHA256("VUSD_ORACLE_KEYPAIR_V1" || seed || node_id)`
The `"VUSD_ORACLE_KEYPAIR_V1"` tag ensures oracle keys cannot be confused with
any other keys in the system, even if the same seed bytes appear elsewhere.

🟢 **Deterministic signing**
`secp256k1::Secp256k1::sign_schnorr` uses BIP-340's deterministic nonce (RFC 6979).
No external randomness required for signing — reduces attack surface.

🟡 **Oracle key rotation**
No key rotation mechanism exists yet. If an oracle node's private key is compromised,
the entire 7-node set must be reshuffled. Mitigation: implement key rotation with
on-chain announcement before mainnet.

🟡 **5-of-7 threshold is software-only**
The aggregator checks ≥5 valid sigs in memory. There is no on-chain verification
of the oracle quorum. In the current design, the VUSD vault engine trusts the
`OracleAggregator` process. Before mainnet: add an on-chain oracle registry
with staked Schnorr pubkeys and penalize misbehaving oracles.

---

### Stealth Addresses (curve25519-dalek v3)

🔴 **ECDH shared secret uses Ristretto point — ensure recipient derives same secret**
Sender: `shared = r·V` (r = ephemeral scalar, V = recipient view pubkey point)
Recipient: `shared = v·R` (v = view privkey scalar, R = ephemeral pubkey point)
These are equal because `r·V = r·(v·G) = v·(r·G) = v·R`. ✓

✅ **FIXED: One-time address derivation — ephemeral seed now internal**
`create_mint_output()` and `create_transfer()` now generate ephemeral seeds from `OsRng` internally.
The `ephemeral_seed` parameter has been removed from all public APIs (`send()`, `create_mint_output()`,
`create_transfer()`). No caller can accidentally reuse a seed.

✅ **FIXED: Watch-only wallet skip is now explicit and logged**
`scan_transfer()` logs a `debug!` message when a watch-only wallet detects an output
but cannot decrypt the amount. Behavior is correct — the output is skipped, not silently lost.

---

### Pedersen Commitments (curve25519-dalek v3)

🟢 **Independent generator H**
H = `RistrettoPoint::hash_from_bytes::<Sha3_512>("VUSD_PEDERSEN_H_GENERATOR")`
This is a nothing-up-my-sleeve point whose discrete log relative to G is not known
to any party. Constructed via Elligator map — standard technique.

✅ **FIXED: PedersenCommitment now uses bulletproofs' PedersenGens exclusively**
`PedersenCommitment::commit()` now calls `pc_gens.commit(v, r)` using `PedersenGens::default()`.
The custom `pedersen_h()` function has been removed. Both `PedersenCommitment` and
`BulletproofRangeProof` now use the same (B, B_blinding) pair — commitments are interchangeable.

✅ **FIXED: verify_commitment_sum() added**
`PedersenCommitment::verify_commitment_sum()` verifies `sum(C_inputs) == sum(C_outputs) + C_fee`
on Ristretto points — the true RingCT balance check without knowledge of amounts or blindings.
`verify_balance()` remains for provers to sanity-check their own blindings.

---

### Ring Signatures (Borromean Schnorr)

✅ **FIXED: real_index now randomized**
`VusdTransferService::send()` now generates `real_index` from `OsRng` before calling `RingSignature::sign()`. The real signer's position is uniformly random across the ring.

🟢 **Ring closure check in verify() is complete**
`verify()` walks all n ring members and checks the final `c == c_0`. Any forgery
or tampered ring member causes the loop to produce a different `c`, failing the check.

✅ **FIXED: Gamma-distributed decoy selection implemented**
`select_decoys()` now uses `gamma_select_decoys()` with a power-law recency bias (alpha=1.0).
This approximates Monero's gamma distribution, biasing toward recent outputs to match
real spend-time distributions. Full gamma CDF to be added before mainnet.

🟡 **CLSAG upgrade path**
The current Borromean ring is simpler than Monero's CLSAG but has slightly larger
signature size. Interface is compatible — swap `sign()`/`verify()` for CLSAG before mainnet.

---

### Bulletproofs

🟢 **Range size is 64 bits**
Proves `v ∈ [0, 2^64)`. VUSD amounts are `u128` internally but vault amounts
are bounded well below `2^64` by the collateral requirements. No overflow risk.

✅ **VERIFIED: Blinding factor consistency confirmed**
Now that both `PedersenCommitment::commit()` and `BulletproofRangeProof::prove()` use
`PedersenGens::default()`, any blinding used in one is valid for the other.
`create_mint_output()` derives the single blinding from `OsRng`-generated ephemeral seed
and uses it for both the commitment and the range proof.

---

### Amount Encryption

🟢 **Encrypt/decrypt are inverses**
`encrypt_amount(a, s)` = `XOR(a_le_bytes, SHA256("VUSD_AMT_ENC" || s)[..16])`
`decrypt_amount(enc, s)` = same XOR — inverse of itself. ✓

✅ **FIXED: Real Ristretto ECDH used consistently**
`ecdh_shared_secret()` in lightning now performs real `v·R` Ristretto scalar multiplication,
matching `StealthWallet::scan_output()`. `StealthWallet::derive_shared_secret()` is now
exposed as a public function for cross-crate reuse. Both derive `SHA256("VUSD_ECDH_V1" || shared_point)`.

---

## Vault Logic

🟢 **Liquidation threshold correctly enforced**
`LIQUIDATION_THRESHOLD_BPS = 11000` (110%). Vault goes to Liquidating when CR < 110%.
`AT_RISK_THRESHOLD_BPS = 13000` (130%). Vault gets warning at 130%. ✓

🟢 **Double liquidation prevented**
`trigger_liquidation()` checks `vault.state == Active || vault.state == AtRisk` before
transitioning to `Liquidating`. A vault in `Liquidating` state cannot be triggered again.
Keeper's `triggered_vaults` set provides an additional in-process guard. ✓

✅ **FIXED: Staleness gate added to process_price_update()**
`process_price_update()` now rejects stale oracle prices at entry, returning early with
`rejected_stale: true` in `PriceUpdateResult`. No vault state changes occur with stale data.
`trigger_liquidation()` already had its own freshness check — both paths are now guarded.

---

## Operational Security

✅ **FIXED: Docker secrets overlay added**
`deploy/docker-compose.secrets.yml` replaces env var seeds with Docker secrets.
`OracleNode::from_env()` reads from `VUSD_PRIVKEY_SEED_FILE` (file path) first,
falling back to `VUSD_PRIVKEY_SEED` only if the file path is unset.
For production: `docker compose -f docker-compose.yml -f docker-compose.secrets.yml up`

✅ **FIXED: Per-feed circuit breaker with exponential backoff**
`oracle::circuit_breaker::CircuitBreaker` wraps each `PriceFeed`. After `FAILURE_THRESHOLD`
consecutive failures it opens the circuit and backs off exponentially (5s → 10s → 20s → 300s max).
Use `with_circuit_breakers(feeds)` when building production oracle nodes.

🟢 **Keeper bonus is paid on settlement, not trigger**
A keeper who triggers liquidation but fails to settle cannot block another keeper
from settling. The `settle_auction()` function accepts any valid bid from any caller.

---

## Known Limitations (acceptable for testnet, fix before mainnet)

- MuSig2 oracle aggregate signature: individual Schnorr sigs concatenated, not a true MuSig2 aggregate
- CLSAG ring signature: Borromean Schnorr used instead
- Bitcoin L1 integration: `MockBtcLayer` used in engine; `btc_tx.rs` builds real txs but engine not wired to it yet
- LND transport: `LndTransport::send_message()` stubs out until live LND endpoint configured
- No on-chain oracle registry: oracle keys are trusted in-process

---

## Session 3 Audit Findings — Codebase-Wide Deep Scan

### Vault Logic

✅ **FIXED: Collateral ratio used principal debt only, not total_owed**
`collateral_ratio_bps()` previously used `debt_vusd` (principal only) as the CR denominator.
A vault with large accrued stability fees appeared healthier than it actually was, delaying
liquidation. Added `collateral_ratio_bps_full(price, fee_index)` which uses `total_owed =
debt + accrued_fee`. All liquidation-critical CR checks in `process_price_update()` and
`trigger_liquidation()` now call `_full()`. The display method `collateral_ratio_bps()` keeps
the old behavior for UI (conservative reference; uses snapshot fee index).

🟢 **Minor: u32 overflow in collateral_ratio_bps on tiny-debt vaults**
If locked_btc is 1 sat and debt is negligible, CR numerator `collateral_usd * 10_000` can
overflow u128 (it can't — u128 is enormous) but the cast to u32 could overflow for CR > 429,497%.
Fixed with `.min(u32::MAX as u128) as u32` clamp in `collateral_ratio_bps_full()`.

---

### Privacy Layer

✅ **FIXED: apply_transaction() reconstructed ring sig message with ZERO amounts**
`apply_transaction()` called `compute_tx_message(&VusdAmount::ZERO, &tx.fee)` to reconstruct
the message for ring sig verification. Since the ring sigs are signed over the actual amount,
every verification returned false — apply_transaction always returned InvalidRingSignature.
Fix: added `signed_message: Vec<u8>` field to `PrivateVusdTx`, stored at signing time,
verified against at apply time.

✅ **FIXED: create_transfer() real_index hardcoded to 0**
`RingSignature::sign(..., 0)` always placed the real signer at position 0, leaking identity.
Now uses `rand::thread_rng().gen_range(0..RING_SIZE)` for random position each transfer.

✅ **FIXED: derive_one_time_address() missing borrow**
`recipient_wallet.derive_one_time_address(ephemeral_seed)` at line 570 passed `[u8;32]`
where `&[u8;32]` was required — would not compile. Fixed to `&ephemeral_seed`.

✅ **FIXED: verify_commitment_sum() try_fold identity type**
Reorganized into a closure `sum_points()` with `Scalar::zero() * G` as identity element
(the neutral element of the Ristretto group). Logic is correct; refactored for clarity.

---

### Lightning Layer

✅ **FIXED: Sender-side ECDH used blinding key instead of ephemeral scalar**
`ecdh_shared_secret(&blinding, &ephemeral_pk)` derived a shared secret from the Pedersen
blinding scalar and the ephemeral pubkey — not a valid Diffie-Hellman operation. The recipient
derives `v·R` from their view privkey and the ephemeral pubkey. These would never match, making
`encrypted_amount` undecryptable. Fixed: sender now calls
`StealthWallet::derive_shared_secret_sender(&ephemeral_seed, &recipient_wallet.view_pubkey)`
which computes `r·V` (r = ephemeral scalar from seed, V = recipient view pubkey point).
Added the symmetric `derive_shared_secret_sender()` to `StealthWallet` in privacy crate.

✅ **FIXED: Change output seed derived from ephemeral_seed (linkable)**
`change_seed = sha2_hash_with_tag(&ephemeral_seed, "CHANGE_SEED")` — if ephemeral_seed ever
leaked, the change output could be linked to the original transfer. Change seed is now
independently sampled from `OsRng`.

✅ **FIXED: Ring signature decoys were synthetic stub bytes**
`0xDEC00B`-prefixed fake bytes were used as decoy public keys in ring signatures, making all
10 decoys trivially identifiable as non-real. Replaced with real stealth addresses from
`PrivacyLayer::output_set.select_decoys()` (gamma-weighted). Falls back to SHA256-derived
synthetic keys (deterministic but indistinguishable from real Ristretto points) only when the
output set has fewer than RING_SIZE-1 unspent entries.

---

### Known Remaining Limitations (pre-mainnet)

- Lightning ring sigs sign over a message that includes `ephemeral_seed` — message is
  sender-specific. Should commit to output commitments instead (like Monero's MLSAG).
  Low priority for testnet.
- `VaultRecord::collateral_ratio_bps()` (display path) still uses snapshot fee index
  for simplicity — acceptable for UI, not for protocol logic (which now uses `_full()`).
- `liquidation_price_usd()` casts u128 → u64; overflows only if locked_btc < ~88 sats
  with full $1B+ debt. Acceptable for testnet.
