// crates/vscx-core/src/oracle_feed.rs
//
// OracleFeed — the single trait the VaultEngine uses to obtain a price.
//
// This decouples the engine from the concrete oracle implementation:
//
//   Phase I  (test):    MockOracle    — in-memory price, no sig verification
//   Phase II (testnet): OracleAggregator — 5-of-7 Schnorr, HTTP feeds, sig verified
//
// The engine calls `get_price()` on every vault operation that needs a price.
// Implementations are responsible for:
//   - Returning None if the oracle is offline / cannot reach quorum
//   - Populating OraclePrice.aggregate_sig with verifiable bytes
//   - Setting OraclePrice.oracle_ids with the IDs of signing nodes
//
// Signature verification (T2) is enforced inside `VaultEngine::fresh_price()`
// using the `verify_signatures` flag set at construction time.
// MockOracle sets it false — so test suites don't need real keypairs.
// OracleAggregator sets it true — the engine rejects prices with bad sigs.

use crate::OraclePrice;

/// Abstraction over oracle price sources.
///
/// Implement this for any price source you want to plug into the engine.
pub trait OracleFeed: Send + Sync {
    /// Return the latest price, or None if the oracle is unavailable.
    fn get_price(&self) -> Option<OraclePrice>;

    /// Whether prices from this feed carry real Schnorr signatures that
    /// the engine should verify before accepting.
    ///
    /// - MockOracle returns false: no sig bytes, skip verification.
    /// - OracleAggregator returns true: engine verifies per-node sigs.
    fn requires_sig_verification(&self) -> bool;

    /// Verify the signatures in a price report produced by this feed.
    ///
    /// Called by the engine only when `requires_sig_verification()` is true.
    /// Returns true if the price carries a valid quorum of signatures.
    ///
    /// The default implementation returns true (no-op) — override in
    /// implementations that carry real sig data.
    fn verify_price_sigs(&self, price: &OraclePrice) -> bool {
        let _ = price;
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MockOracle impl
// ─────────────────────────────────────────────────────────────────────────────

use crate::mock::MockOracle;

impl OracleFeed for MockOracle {
    fn get_price(&self) -> Option<OraclePrice> {
        MockOracle::get_price(self)
    }

    fn requires_sig_verification(&self) -> bool {
        false // test oracle — no real sigs
    }
}
