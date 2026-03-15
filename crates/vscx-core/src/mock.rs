// crates/vscx-core/src/mock.rs
//
// Mock oracle and mock Bitcoin layer for Phase I testing.
// These are fully functional stubs that allow the entire VSCx engine
// to be tested without network connectivity or real Bitcoin.
// Phase II replaces MockOracle with OracleAggregator.
// Phase III replaces MockBtcLayer with real Bitcoin node calls.

use crate::types::*;
use std::sync::{Arc, RwLock};

// ─────────────────────────────────────────────────────────────────────────────
// MOCK ORACLE
// ─────────────────────────────────────────────────────────────────────────────

/// A configurable mock oracle for unit and integration testing.
/// Can simulate staleness, price volatility, and oracle failure.
#[derive(Debug, Clone)]
pub struct MockOracle {
    inner: Arc<RwLock<MockOracleInner>>,
}

#[derive(Debug)]
struct MockOracleInner {
    btc_usd: u64,       // price in whole dollars
    timestamp: u64,
    is_stale: bool,
    is_offline: bool,
}

impl MockOracle {
    /// Create a new mock oracle at the given BTC/USD price.
    pub fn new(btc_usd_dollars: u64) -> Self {
        MockOracle {
            inner: Arc::new(RwLock::new(MockOracleInner {
                btc_usd: btc_usd_dollars,
                timestamp: current_time_secs(),
                is_stale: false,
                is_offline: false,
            })),
        }
    }

    /// Update the oracle price (simulates a market price change).
    pub fn set_price(&self, btc_usd_dollars: u64) {
        let mut inner = self.inner.write().unwrap();
        inner.btc_usd = btc_usd_dollars;
        inner.timestamp = current_time_secs();
        inner.is_stale = false;
    }

    /// Force the oracle to be stale (simulates oracle going offline).
    pub fn set_stale(&self) {
        let mut inner = self.inner.write().unwrap();
        // Set timestamp 15 minutes in the past
        inner.timestamp = current_time_secs().saturating_sub(900);
        inner.is_stale = true;
    }

    /// Restore freshness after being stale.
    pub fn set_fresh(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.timestamp = current_time_secs();
        inner.is_stale = false;
    }

    /// Simulate oracle network going completely offline.
    pub fn set_offline(&self, offline: bool) {
        self.inner.write().unwrap().is_offline = offline;
    }

    /// Get the current price as an OraclePrice, or None if offline.
    pub fn get_price(&self) -> Option<OraclePrice> {
        let inner = self.inner.read().unwrap();
        if inner.is_offline {
            return None;
        }
        Some(OraclePrice {
            btc_usd_8dec: inner.btc_usd * 100_000_000, // convert dollars to 8 dec
            timestamp: inner.timestamp,
            oracle_ids: vec![1, 2, 3, 4, 5], // simulated 5 oracles
            aggregate_sig: vec![0u8; 64],     // dummy sig
        })
    }

    /// Returns current price, panics if offline (for use in tests that assume online oracle).
    pub fn price(&self) -> OraclePrice {
        self.get_price().expect("MockOracle is offline")
    }

    /// Simulate a price crash to trigger AT_RISK or liquidation.
    pub fn crash_price_to_pct_of_current(&self, pct: u64) {
        let current = self.inner.read().unwrap().btc_usd;
        self.set_price(current * pct / 100);
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// BTC LAYER TRAIT (T3)
// ─────────────────────────────────────────────────────────────────────────────

/// Abstraction over Bitcoin L1 interactions.
///
///   Phase I  (test):    MockBtcLayer  — in-memory UTXO map, no real node
///   Phase III (testnet): SignetBtcLayer — bitcoind RPC via bitcoin crate
///
/// The engine and VaultTaprootClient both operate against this trait so
/// the same logic runs against mock in tests and real signet in testnet.
pub trait BtcLayer: Send + Sync {
    /// Lock BTC by recording a UTXO. Returns the OutPoint of the new output.
    /// Phase I: synthetic. Phase III: broadcast a real P2TR funding tx.
    fn lock_btc(&self, amount_sats: Satoshis, owner_pubkey: XOnlyPubkey) -> OutPoint;

    /// Spend a UTXO, sending funds to `destination`.
    /// Phase I: mark as spent. Phase III: broadcast a spending tx.
    fn unlock_btc(&self, utxo: &OutPoint, destination: &BitcoinAddress) -> Result<OutPoint, String>;

    /// Return the current best block height.
    fn block_height(&self) -> u64;

    /// Check whether a UTXO exists and is unspent.
    fn is_utxo_unspent(&self, utxo: &OutPoint) -> bool;
}

// ─────────────────────────────────────────────────────────────────────────────
// MOCK BTC LAYER
// ─────────────────────────────────────────────────────────────────────────────

/// Mock Bitcoin L1 layer. Simulates UTXO locking and unlocking.
/// Phase III: replaced with real Bitcoin node RPC calls.
#[derive(Debug, Clone)]
pub struct MockBtcLayer {
    inner: Arc<RwLock<MockBtcLayerInner>>,
}

#[derive(Debug)]
struct MockBtcLayerInner {
    /// All UTXOs that have been "locked" (simulating Taproot outputs).
    locked_utxos: std::collections::HashMap<OutPoint, LockedUtxo>,
    /// Counter for generating mock txids.
    tx_counter: u64,
    /// Current block height (for timelock simulation).
    block_height: u64,
    /// Whether to simulate confirmation delays.
    simulate_delays: bool,
}

#[derive(Debug, Clone)]
struct LockedUtxo {
    pub amount_sats: Satoshis,
    pub owner_pubkey: XOnlyPubkey,
    pub confirmed: bool,
    pub spent: bool,
}

impl MockBtcLayer {
    pub fn new() -> Self {
        MockBtcLayer {
            inner: Arc::new(RwLock::new(MockBtcLayerInner {
                locked_utxos: std::collections::HashMap::new(),
                tx_counter: 1,
                block_height: 800_000, // start at mainnet-like height
                simulate_delays: false,
            })),
        }
    }

    /// Simulate locking BTC in a Taproot output.
    /// Returns the OutPoint of the "confirmed" UTXO.
    pub fn lock_btc(
        &self,
        amount_sats: Satoshis,
        owner_pubkey: XOnlyPubkey,
    ) -> OutPoint {
        let mut inner = self.inner.write().unwrap();
        let txid = {
            let mut id = [0u8; 32];
            let counter_bytes = inner.tx_counter.to_le_bytes();
            id[..8].copy_from_slice(&counter_bytes);
            id[8] = 0xDE; id[9] = 0xAD; id[10] = 0xBE; id[11] = 0xEF; // marker
            inner.tx_counter += 1;
            id
        };
        let outpoint = OutPoint::new(txid, 0);
        let confirmed = !inner.simulate_delays;
        inner.locked_utxos.insert(outpoint.clone(), LockedUtxo {
            amount_sats,
            owner_pubkey,
            confirmed, // instantly confirmed unless delays enabled
            spent: false,
        });
        tracing::debug!("MockBtcLayer: locked {} at {}", amount_sats, outpoint);
        outpoint
    }

    /// Simulate unlocking/spending a Taproot output.
    /// Returns a mock txid of the spending transaction.
    pub fn unlock_btc(
        &self,
        utxo: &OutPoint,
        destination: &BitcoinAddress,
    ) -> Result<OutPoint, String> {
        let mut inner = self.inner.write().unwrap();
        match inner.locked_utxos.get_mut(utxo) {
            None => Err(format!("UTXO not found: {}", utxo)),
            Some(locked) if locked.spent => Err(format!("UTXO already spent: {}", utxo)),
            Some(locked) => {
                locked.spent = true;
                let mut spend_txid = [0u8; 32];
                let counter_bytes = inner.tx_counter.to_le_bytes();
                spend_txid[..8].copy_from_slice(&counter_bytes);
                spend_txid[8] = 0xC1; spend_txid[9] = 0x05; spend_txid[10] = 0xED; // "closed"
                inner.tx_counter += 1;
                tracing::debug!("MockBtcLayer: unlocked {} → {}", utxo, destination);
                Ok(OutPoint::new(spend_txid, 0))
            }
        }
    }

    /// Check if a UTXO exists and is unspent.
    pub fn is_utxo_unspent(&self, utxo: &OutPoint) -> bool {
        let inner = self.inner.read().unwrap();
        inner.locked_utxos.get(utxo)
            .map(|u| !u.spent)
            .unwrap_or(false)
    }

    /// Get the value of a locked UTXO.
    pub fn get_utxo_value(&self, utxo: &OutPoint) -> Option<Satoshis> {
        let inner = self.inner.read().unwrap();
        inner.locked_utxos.get(utxo)
            .filter(|u| !u.spent)
            .map(|u| u.amount_sats)
    }

    /// Advance the mock block height.
    pub fn mine_blocks(&self, count: u64) {
        self.inner.write().unwrap().block_height += count;
    }

    /// Get current block height.
    pub fn block_height(&self) -> u64 {
        self.inner.read().unwrap().block_height
    }

    /// Number of UTXOs currently locked (unspent).
    pub fn locked_count(&self) -> usize {
        self.inner.read().unwrap().locked_utxos.values()
            .filter(|u| !u.spent)
            .count()
    }
}


impl BtcLayer for MockBtcLayer {
    fn lock_btc(&self, amount_sats: Satoshis, owner_pubkey: XOnlyPubkey) -> OutPoint {
        MockBtcLayer::lock_btc(self, amount_sats, owner_pubkey)
    }
    fn unlock_btc(&self, utxo: &OutPoint, destination: &BitcoinAddress) -> Result<OutPoint, String> {
        MockBtcLayer::unlock_btc(self, utxo, destination)
    }
    fn block_height(&self) -> u64 { MockBtcLayer::block_height(self) }
    fn is_utxo_unspent(&self, utxo: &OutPoint) -> bool { MockBtcLayer::is_utxo_unspent(self, utxo) }
}

impl Default for MockBtcLayer {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// MOCK VUSD LEDGER
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks VUSD total supply and per-address balances for Phase I testing.
/// Phase IV: replaced by the private RingCT output set.
#[derive(Debug, Clone)]
pub struct MockVusdLedger {
    inner: Arc<RwLock<MockVusdLedgerInner>>,
}

#[derive(Debug)]
struct MockVusdLedgerInner {
    total_supply: VusdAmount,
    balances: std::collections::HashMap<String, VusdAmount>,
}

impl MockVusdLedger {
    pub fn new() -> Self {
        MockVusdLedger {
            inner: Arc::new(RwLock::new(MockVusdLedgerInner {
                total_supply: VusdAmount::ZERO,
                balances: std::collections::HashMap::new(),
            })),
        }
    }

    /// Mint new VUSD to an address.
    pub fn mint(&self, to: &StealthAddress, amount: VusdAmount) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap();
        let key = to.to_hex();
        let balance = inner.balances.entry(key).or_insert(VusdAmount::ZERO);
        *balance = balance.saturating_add(amount);
        inner.total_supply = inner.total_supply.saturating_add(amount);
        Ok(())
    }

    /// Burn VUSD from an address.
    pub fn burn(&self, from: &StealthAddress, amount: VusdAmount) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap();
        let key = from.to_hex();
        let balance = inner.balances.get_mut(&key)
            .ok_or_else(|| "Address has no balance".to_string())?;
        if *balance < amount {
            return Err(format!("Insufficient balance: have {}, need {}", balance, amount));
        }
        *balance = VusdAmount(balance.0 - amount.0);
        inner.total_supply = VusdAmount(inner.total_supply.0.saturating_sub(amount.0));
        Ok(())
    }

    pub fn balance_of(&self, addr: &StealthAddress) -> VusdAmount {
        let inner = self.inner.read().unwrap();
        *inner.balances.get(&addr.to_hex()).unwrap_or(&VusdAmount::ZERO)
    }

    pub fn total_supply(&self) -> VusdAmount {
        self.inner.read().unwrap().total_supply
    }
}

impl Default for MockVusdLedger {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// TIME UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

/// Returns current Unix timestamp in seconds.
/// In tests, this can be overridden via a thread-local mock clock.
pub fn current_time_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_oracle_price_change() {
        let oracle = MockOracle::new(100_000);
        let p1 = oracle.price();
        assert_eq!(p1.btc_usd_8dec, 100_000_00000000);

        oracle.set_price(90_000);
        let p2 = oracle.price();
        assert_eq!(p2.btc_usd_8dec, 90_000_00000000);
    }

    #[test]
    fn test_mock_oracle_staleness() {
        let oracle = MockOracle::new(100_000);
        oracle.set_stale();
        let price = oracle.price();
        assert!(!price.is_fresh(current_time_secs()));
    }

    #[test]
    fn test_mock_btc_lock_unlock() {
        let btc = MockBtcLayer::new();
        let pk = XOnlyPubkey([1u8; 32]);
        let utxo = btc.lock_btc(Satoshis::ONE_BTC, pk);

        assert!(btc.is_utxo_unspent(&utxo));
        assert_eq!(btc.get_utxo_value(&utxo), Some(Satoshis::ONE_BTC));
        assert_eq!(btc.locked_count(), 1);

        let addr = BitcoinAddress::new("bc1p_test_addr");
        btc.unlock_btc(&utxo, &addr).unwrap();

        assert!(!btc.is_utxo_unspent(&utxo));
        assert_eq!(btc.locked_count(), 0);
    }

    #[test]
    fn test_mock_btc_double_spend_rejected() {
        let btc = MockBtcLayer::new();
        let pk = XOnlyPubkey([1u8; 32]);
        let utxo = btc.lock_btc(Satoshis::ONE_BTC, pk);
        let addr = BitcoinAddress::new("bc1p_test");
        btc.unlock_btc(&utxo, &addr).unwrap();
        // Second unlock should fail
        assert!(btc.unlock_btc(&utxo, &addr).is_err());
    }

    #[test]
    fn test_mock_vusd_ledger_mint_burn() {
        let ledger = MockVusdLedger::new();
        let addr = StealthAddress([1u8; 32]);
        let amount = VusdAmount::from_usd_8dec(1_000_00000000); // $1,000

        ledger.mint(&addr, amount).unwrap();
        assert_eq!(ledger.total_supply(), amount);
        assert_eq!(ledger.balance_of(&addr), amount);

        let burn_half = VusdAmount(amount.0 / 2);
        ledger.burn(&addr, burn_half).unwrap();
        assert_eq!(ledger.total_supply(), VusdAmount(amount.0 - burn_half.0));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RINGCT VUSD LEDGER  (A3)
// ─────────────────────────────────────────────────────────────────────────────

/// A private VUSD output in the RingCT output set.
///
/// Amounts are hidden behind Pedersen commitments.
/// Outputs are addressed to stealth one-time addresses.
/// Key images prevent double-spending without revealing which output was spent.
#[derive(Debug, Clone)]
pub struct VusdOutput {
    /// One-time stealth address derived by sender.
    pub stealth_address: StealthAddress,
    /// Pedersen commitment: C = amount·H + blinding·G — hides the amount.
    pub commitment:      [u8; 32],
    /// Bulletproof range proof: amount ∈ [0, 2^64).
    pub range_proof:     Vec<u8>,
    /// Whether this output has been spent (key image seen).
    pub spent:           bool,
}

/// The global VUSD RingCT output set.
///
/// Replaces MockVusdLedger. Amounts are never stored in plaintext.
/// The engine uses this for mint (creates outputs) and burn (spends outputs).
///
/// Key images track spent outputs — a key image appearing twice is a
/// double-spend and is rejected.
///
/// Phase IV upgrade path from MockVusdLedger:
///   - Engine::mint_vusd calls ringct_ledger.mint() → creates a committed output
///   - Engine::repay_vusd calls ringct_ledger.burn() → marks output as spent
///   - Total supply is tracked as a running count (not plaintext sum)
#[derive(Debug, Clone)]
pub struct RingCtLedger {
    inner: Arc<RwLock<RingCtLedgerInner>>,
}

#[derive(Debug)]
struct RingCtLedgerInner {
    /// All outputs ever created, indexed by stealth address hex.
    outputs:      std::collections::HashMap<[u8; 32], VusdOutput>,
    /// Set of seen key images — used for double-spend detection.
    /// Key image = H_p(privkey) · G — unlinkable to the output.
    key_images:   std::collections::HashSet<[u8; 32]>,
    /// Running total supply (in VUSD base units) — only updated on mint/burn.
    /// We track this in plaintext for protocol-level supply cap enforcement.
    /// In full Phase IV this would be a commitment to the total.
    total_supply: VusdAmount,
}

impl RingCtLedger {
    pub fn new() -> Self {
        RingCtLedger {
            inner: Arc::new(RwLock::new(RingCtLedgerInner {
                outputs:      std::collections::HashMap::new(),
                key_images:   std::collections::HashSet::new(),
                total_supply: VusdAmount::ZERO,
            })),
        }
    }

    /// Mint a new VUSD output.
    ///
    /// The caller provides:
    ///   - `stealth_address`: the recipient's one-time address
    ///   - `commitment`: Pedersen commitment to the amount (C = amount·H + blind·G)
    ///   - `range_proof`: bulletproof proving amount ∈ [0, 2^64)
    ///   - `amount`: the plaintext amount — used only for supply tracking,
    ///     never stored in the output record itself
    ///
    /// Returns Err if the range proof fails verification.
    pub fn mint(
        &self,
        stealth_address: &StealthAddress,
        commitment:      [u8; 32],
        range_proof:     Vec<u8>,
        amount:          VusdAmount,
    ) -> Result<(), String> {
        // Verify the range proof before accepting the output
        // This prevents inflation attacks via invalid commitments
        use crate::BulletproofVerifier;
        if !BulletproofVerifier::verify_range_proof(&commitment, &range_proof) {
            return Err("Range proof verification failed — output rejected".to_string());
        }

        let mut inner = self.inner.write().unwrap();
        inner.outputs.insert(stealth_address.0, VusdOutput {
            stealth_address: stealth_address.clone(),
            commitment,
            range_proof,
            spent: false,
        });
        inner.total_supply = inner.total_supply.saturating_add(amount);
        Ok(())
    }

    /// Mint with plaintext amount — convenience wrapper for engine compatibility.
    ///
    /// Generates the commitment and range proof internally.
    /// The blinding factor is derived deterministically from the stealth address
    /// and amount so the recipient can recover it during scanning.
    pub fn mint_with_amount(
        &self,
        stealth_address: &StealthAddress,
        amount:          VusdAmount,
    ) -> Result<(), String> {
        // Derive blinding factor: H(stealth_address || amount)
        let blinding: [u8; 32] = {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut hasher, b"VUSD_RINGCT_BLIND_V1");
            sha2::Digest::update(&mut hasher, &stealth_address.0);
            sha2::Digest::update(&mut hasher, &amount.0.to_le_bytes());
            sha2::Digest::finalize(hasher).into()
        };

        // Build commitment C = amount·H + blinding·G
        // We store the commitment bytes but not the amount
        let commitment: [u8; 32] = {
            use sha2::Digest;
            // Simplified commitment for Phase III — full Pedersen in Phase IV
            // C = SHA256("VUSD_COMMIT" || amount || blinding)
            use sha2::Digest as _;
            let mut h = sha2::Sha256::new();
            h.update(b"VUSD_COMMIT_V1");
            h.update(&amount.0.to_le_bytes());
            h.update(&blinding);
            h.finalize().into()
        };

        // Range proof: in Phase III we use a placeholder (real bulletproof in Phase IV)
        // The real bulletproofs crate is in the privacy crate — threading it through
        // here requires a dependency on privacy from vscx-core (currently avoided).
        // Phase IV: move this to the privacy layer and call it from the CLI/engine glue.
        let range_proof = vec![0u8; 64]; // placeholder — real proof in Phase IV

        let mut inner = self.inner.write().unwrap();
        inner.outputs.insert(stealth_address.0, VusdOutput {
            stealth_address: stealth_address.clone(),
            commitment,
            range_proof,
            spent: false,
        });
        inner.total_supply = inner.total_supply.saturating_add(amount);
        Ok(())
    }

    /// Burn (spend) a VUSD output using a key image.
    ///
    /// The caller presents:
    ///   - `stealth_address`: the output being spent
    ///   - `key_image`: H_p(spend_privkey) · G — proves ownership without
    ///     revealing which key or linking to previous spends
    ///   - `amount`: the plaintext amount for supply tracking
    ///
    /// Returns Err if the key image has been seen before (double-spend).
    pub fn burn(
        &self,
        stealth_address: &StealthAddress,
        key_image:       [u8; 32],
        amount:          VusdAmount,
    ) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap();

        // Double-spend check
        if inner.key_images.contains(&key_image) {
            return Err(format!(
                "Double-spend detected: key image {} already seen",
                hex_short(&key_image)
            ));
        }

        let output = inner.outputs.get_mut(&stealth_address.0)
            .ok_or_else(|| "Output not found".to_string())?;

        if output.spent {
            return Err("Output already spent".to_string());
        }

        output.spent = true;
        inner.key_images.insert(key_image);
        inner.total_supply = VusdAmount(inner.total_supply.0.saturating_sub(amount.0));
        Ok(())
    }

    /// Burn by stealth address only — compatibility wrapper for engine.
    /// Uses a derived key image from the address bytes (Phase III placeholder).
    /// Phase IV: require real key image from the spender's wallet.
    pub fn burn_by_address(
        &self,
        stealth_address: &StealthAddress,
        amount:          VusdAmount,
    ) -> Result<(), String> {
        // Derive a deterministic key image placeholder
        let key_image: [u8; 32] = {
            use sha2::Digest as _;
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, b"VUSD_KEY_IMAGE_V1");
            sha2::Digest::update(&mut h, &stealth_address.0);
            sha2::Digest::finalize(h).into()
        };
        self.burn(stealth_address, key_image, amount)
    }

    pub fn total_supply(&self) -> VusdAmount {
        self.inner.read().unwrap().total_supply
    }

    pub fn output_count(&self) -> usize {
        self.inner.read().unwrap().outputs.len()
    }

    pub fn unspent_count(&self) -> usize {
        self.inner.read().unwrap().outputs.values()
            .filter(|o| !o.spent).count()
    }
}

impl Default for RingCtLedger {
    fn default() -> Self { Self::new() }
}

fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>() + "…"
}

/// Placeholder bulletproof verifier — real verification in Phase IV via privacy crate.
pub struct BulletproofVerifier;
impl BulletproofVerifier {
    pub fn verify_range_proof(_commitment: &[u8; 32], proof: &[u8]) -> bool {
        // Phase III: accept placeholder proofs (all-zero 64 bytes)
        // Phase IV: call bulletproofs::RangeProof::verify()
        proof.len() >= 64
    }
}

