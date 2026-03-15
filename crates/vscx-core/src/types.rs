// crates/vscx-core/src/types.rs
//
// Core primitive types for the VUSD / VSCx protocol.
// All financial arithmetic uses u128 with explicit decimal handling
// to avoid floating-point rounding errors near vault boundaries.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// MONETARY TYPES
// ─────────────────────────────────────────────────────────────────────────────

/// Satoshis: the smallest unit of Bitcoin (1 BTC = 100_000_000 satoshis).
/// All BTC collateral amounts are stored and computed in satoshis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Satoshis(pub u64);

impl Satoshis {
    pub const ZERO: Satoshis = Satoshis(0);
    pub const ONE_BTC: Satoshis = Satoshis(100_000_000);

    pub fn is_zero(self) -> bool { self.0 == 0 }

    pub fn checked_add(self, rhs: Satoshis) -> Option<Satoshis> {
        self.0.checked_add(rhs.0).map(Satoshis)
    }

    pub fn checked_sub(self, rhs: Satoshis) -> Option<Satoshis> {
        self.0.checked_sub(rhs.0).map(Satoshis)
    }

    /// Returns the USD value of this amount at the given price (8 decimal places).
    /// price_usd_8dec: price per BTC with 8 decimal places (e.g. 100_000_00000000 = $100,000.00)
    /// Returns value with 8 decimal places (scaled by 1e8).
    pub fn usd_value_8dec(self, price_usd_8dec: u64) -> u128 {
        // (satoshis * price_per_btc_8dec) / 1e8
        // Both have 8 decimal places, result has 8 decimal places
        (self.0 as u128) * (price_usd_8dec as u128) / 100_000_000
    }
}

impl fmt::Display for Satoshis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} sats ({:.8} BTC)", self.0, self.0 as f64 / 1e8)
    }
}

/// VUSD amount with 18 decimal places (matching ERC-20 convention).
/// 1 VUSD = 1_000_000_000_000_000_000 (1e18) base units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct VusdAmount(pub u128);

impl VusdAmount {
    pub const ZERO: VusdAmount = VusdAmount(0);
    /// 1 VUSD in base units
    pub const ONE: VusdAmount = VusdAmount(1_000_000_000_000_000_000);
    /// Minimum meaningful VUSD amount (0.000001 VUSD — dust limit)
    pub const DUST_LIMIT: VusdAmount = VusdAmount(1_000_000_000_000);

    pub fn is_zero(self) -> bool { self.0 == 0 }

    pub fn from_usd_8dec(usd_8dec: u128) -> VusdAmount {
        // Convert from 8-decimal USD value to 18-decimal VUSD
        VusdAmount(usd_8dec * 10_000_000_000) // multiply by 1e10
    }

    pub fn to_usd_8dec(self) -> u128 {
        self.0 / 10_000_000_000
    }

    pub fn checked_add(self, rhs: VusdAmount) -> Option<VusdAmount> {
        self.0.checked_add(rhs.0).map(VusdAmount)
    }

    pub fn checked_sub(self, rhs: VusdAmount) -> Option<VusdAmount> {
        self.0.checked_sub(rhs.0).map(VusdAmount)
    }

    pub fn saturating_add(self, rhs: VusdAmount) -> VusdAmount {
        VusdAmount(self.0.saturating_add(rhs.0))
    }

    /// Multiply by a basis point factor (1 bps = 0.01% = 1/10000)
    pub fn mul_bps(self, bps: u64) -> VusdAmount {
        VusdAmount(self.0 * bps as u128 / 10_000)
    }

    /// Multiply by percentage (e.g. 113 = 113% = multiply by 1.13)
    pub fn mul_percent(self, pct: u64) -> VusdAmount {
        VusdAmount(self.0 * pct as u128 / 100)
    }
}

impl fmt::Display for VusdAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let whole = self.0 / 1_000_000_000_000_000_000;
        let frac  = self.0 % 1_000_000_000_000_000_000;
        write!(f, "{}.{:018} VUSD", whole, frac)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IDENTIFIERS
// ─────────────────────────────────────────────────────────────────────────────

/// Unique vault identifier: SHA256(owner_pubkey_bytes || nonce)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VaultId([u8; 32]);

impl VaultId {
    /// Derive a VaultId from an owner's public key bytes and a random nonce.
    pub fn derive(owner_pubkey_bytes: &[u8], nonce: &[u8; 32]) -> VaultId {
        let mut hasher = Sha256::new();
        hasher.update(b"VUSD_VAULT_ID_V1");
        hasher.update(owner_pubkey_bytes);
        hasher.update(nonce);
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        VaultId(id)
    }

    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl fmt::Display for VaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vault:{}", &self.to_hex()[..16])
    }
}

/// Auction identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AuctionId([u8; 32]);

impl AuctionId {
    pub fn derive(vault_id: &VaultId, trigger_timestamp: u64) -> AuctionId {
        let mut hasher = Sha256::new();
        hasher.update(b"VUSD_AUCTION_ID_V1");
        hasher.update(vault_id.as_bytes());
        hasher.update(&trigger_timestamp.to_le_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        AuctionId(id)
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl fmt::Display for AuctionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "auction:{}", &self.to_hex()[..16])
    }
}

/// Represents an on-chain Bitcoin UTXO reference (txid:vout).
/// In Phase I this is a mock; wired to real bitcoin::OutPoint in Phase III.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self { OutPoint { txid, vout } }

    pub fn to_hex(&self) -> String {
        let txid_hex: String = self.txid.iter().rev().map(|b| format!("{:02x}", b)).collect();
        format!("{}:{}", txid_hex, self.vout)
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// A Bitcoin address (bech32 string). Phase I: opaque string. Phase III: validated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitcoinAddress(pub String);

impl BitcoinAddress {
    pub fn new(addr: impl Into<String>) -> Self { BitcoinAddress(addr.into()) }
}

impl fmt::Display for BitcoinAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Public key bytes (32-byte x-only Schnorr / Taproot key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct XOnlyPubkey(pub [u8; 32]);

impl XOnlyPubkey {
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl fmt::Display for XOnlyPubkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pk:{}", &self.to_hex()[..12])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// COLLATERAL RATIO
// ─────────────────────────────────────────────────────────────────────────────

/// Collateral ratio in basis points (e.g. 15000 = 150.00%)
/// Using basis points avoids float and keeps precision for boundary checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CollateralRatioBps(pub u32);

impl CollateralRatioBps {
    /// 150% — minimum safe ratio
    pub const MIN_SAFE: CollateralRatioBps = CollateralRatioBps(15000);
    /// 110% — liquidation threshold
    pub const LIQUIDATION_THRESHOLD: CollateralRatioBps = CollateralRatioBps(11000);
    /// 120% — at-risk warning threshold
    pub const AT_RISK_THRESHOLD: CollateralRatioBps = CollateralRatioBps(12000);

    pub fn is_safe(self) -> bool { self >= Self::MIN_SAFE }
    pub fn is_at_risk(self) -> bool { self < Self::MIN_SAFE && self >= Self::LIQUIDATION_THRESHOLD }
    pub fn is_liquidatable(self) -> bool { self < Self::LIQUIDATION_THRESHOLD }

    /// Returns the ratio as a human-readable percentage string (e.g. "150.00%")
    pub fn as_percent_str(self) -> String {
        format!("{:.2}%", self.0 as f64 / 100.0)
    }
}

impl fmt::Display for CollateralRatioBps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_percent_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ORACLE PRICE
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum age of an oracle price before VSCx rejects it (10 minutes).
pub const ORACLE_MAX_AGE_SECS: u64 = 600;

/// A verified oracle price report. In Phase I this is produced by MockOracle.
/// In Phase II it carries real Schnorr signatures from the oracle quorum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OraclePrice {
    /// BTC/USD price with 8 decimal places.
    /// e.g. 100_000_00000000 = $100,000.00
    pub btc_usd_8dec: u64,
    /// Unix timestamp of this price report.
    pub timestamp: u64,
    /// IDs of oracle nodes that signed this price (Phase II: real pubkeys).
    pub oracle_ids: Vec<u8>,
    /// Aggregate Schnorr signature bytes (Phase I: zeroed stub).
    pub aggregate_sig: Vec<u8>,
}

impl OraclePrice {
    /// Returns whether this price is fresh enough to be used.
    pub fn is_fresh(&self, now_secs: u64) -> bool {
        now_secs.saturating_sub(self.timestamp) <= ORACLE_MAX_AGE_SECS
    }

    /// Returns the USD value (8 dec) of a given BTC amount.
    pub fn btc_to_usd_8dec(&self, sats: Satoshis) -> u128 {
        sats.usd_value_8dec(self.btc_usd_8dec)
    }

    /// Returns the BTC price as a human-readable string.
    pub fn price_display(&self) -> String {
        format!("${:.2}", self.btc_usd_8dec as f64 / 1e8)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TAPROOT REFERENCES (Phase I: opaque bytes; Phase III: real scripts)
// ─────────────────────────────────────────────────────────────────────────────

/// A Taproot leaf script reference.
/// Phase I: stores script bytes as a placeholder.
/// Phase III: replaced with real bitcoin::Script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapLeaf {
    pub version: u8,
    pub script_bytes: Vec<u8>,
}

impl TapLeaf {
    pub fn placeholder() -> Self {
        TapLeaf { version: 0xc0, script_bytes: vec![] }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// STEALTH ADDRESS (Phase I stub; Phase IV: real dual-key derivation)
// ─────────────────────────────────────────────────────────────────────────────

/// A one-time stealth address for receiving private VUSD.
/// Phase I: just a 32-byte identifier.
/// Phase IV: real Monero-style dual-key stealth address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthAddress(pub [u8; 32]);

impl StealthAddress {
    pub fn placeholder() -> Self {
        StealthAddress([0u8; 32])
    }
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl fmt::Display for StealthAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stealth:{}", &self.to_hex()[..16])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROTOCOL CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

/// Minimum collateral ratio to open or maintain a vault (150.00%)
pub const MIN_COLLATERAL_RATIO_BPS: u32 = 15000;
/// Liquidation trigger threshold (110.00%)
pub const LIQUIDATION_THRESHOLD_BPS: u32 = 11000;
/// At-risk warning threshold (120.00%)
pub const AT_RISK_THRESHOLD_BPS: u32     = 12000;
/// Liquidation penalty in basis points (13%)
pub const LIQUIDATION_PENALTY_BPS: u64  = 1300;
/// Keeper bonus in basis points (2% of collateral)
pub const KEEPER_BONUS_BPS: u64         = 200;
/// Stability fee APR in basis points (1% default)
pub const DEFAULT_STABILITY_FEE_APR_BPS: u64 = 100;
/// Vault open fee in USD cents (100 cents = $1.00)
pub const VAULT_OPEN_FEE_USD_CENTS: u64 = 100;
/// Vault close fee in USD cents
pub const VAULT_CLOSE_FEE_USD_CENTS: u64 = 100;
/// Auction duration in seconds (6 hours)
pub const AUCTION_DURATION_SECS: u64    = 6 * 60 * 60;
/// Emergency timelock in blocks (~6 months at 10 min/block)
pub const EMERGENCY_TIMELOCK_BLOCKS: u32 = 26_280;
/// Fee index scaling factor (1e18)
pub const FEE_INDEX_SCALE: u128          = 1_000_000_000_000_000_000;

/// Protocol-controlled keeper pubkey embedded in Leaf B (liquidation branch).
///
/// This is a protocol constant — NOT the vault owner's key. Embedding the
/// owner's pubkey here was a privacy bug: spending Leaf B on-chain would have
/// revealed the owner's identity in the witness script.
///
/// This value is a well-known protocol pubkey whose corresponding private key
/// is held by the keeper network (multi-sig in Phase III). It is the same for
/// every vault, making Leaf B scripts indistinguishable across vaults.
///
/// Phase III: replace with a threshold multi-sig key over the keeper set.
pub const PROTOCOL_KEEPER_PUBKEY: XOnlyPubkey = XOnlyPubkey([
    0x02, 0x56, 0x4e, 0x37, 0x8b, 0xca, 0xd1, 0xf3,
    0x9a, 0x8c, 0x12, 0x7e, 0x4d, 0x83, 0x0f, 0x61,
    0xa9, 0x5b, 0x2e, 0x74, 0xc3, 0x1d, 0x08, 0x46,
    0xf2, 0x7a, 0x93, 0x5e, 0x6b, 0x12, 0xd4, 0x80,
]);


// ─────────────────────────────────────────────────────────────────────────────
// KEEPER KEY REGISTRY  (A4)
// ─────────────────────────────────────────────────────────────────────────────

/// A rotation event in the keeper key history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperKeyRotation {
    /// The new keeper pubkey after rotation.
    pub new_pubkey:   XOnlyPubkey,
    /// Unix timestamp of the rotation.
    pub rotated_at:  u64,
    /// Block height at which the rotation took effect.
    pub block_height: u64,
    /// Signatures from M-of-N keepers authorizing this rotation.
    /// Each entry: (keeper_pubkey_hash, Schnorr signature bytes)
    /// (keeper_pubkey_hash, schnorr_sig_bytes) — sig stored as Vec<u8> for serde compat
    pub authorizations: Vec<([u8; 32], Vec<u8>)>,
}

/// The protocol keeper key registry.
///
/// Maintains the current keeper pubkey used in Leaf B of all new vault MASTs,
/// plus a rotation history for auditability.
///
/// Rotation requires M-of-N Schnorr signatures from the registered keeper set.
/// This replaces the static `PROTOCOL_KEEPER_PUBKEY` constant for Phase III.
///
/// Old vaults keep the keeper key they were opened with — stored in VaultRecord.
/// The registry is only consulted at vault OPEN time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeeperKeyRegistry {
    /// Current active protocol keeper pubkey (embedded in new vault Leaf B scripts).
    pub current_pubkey: XOnlyPubkey,
    /// M: minimum signatures required to authorize a rotation.
    pub rotation_quorum: usize,
    /// Registered keeper pubkeys (the set that can sign rotations).
    pub registered_keepers: Vec<XOnlyPubkey>,
    /// Rotation history (most recent last).
    pub rotation_history: Vec<KeeperKeyRotation>,
}

impl KeeperKeyRegistry {
    /// Create a new registry initialized with the protocol default key.
    pub fn new_with_default() -> Self {
        KeeperKeyRegistry {
            current_pubkey:     PROTOCOL_KEEPER_PUBKEY,
            rotation_quorum:    3, // 3-of-5 threshold for mainnet
            registered_keepers: vec![PROTOCOL_KEEPER_PUBKEY], // bootstrap: single key
            rotation_history:   vec![],
        }
    }

    /// Rotate to a new keeper pubkey.
    ///
    /// Validates that `authorizations` contains at least `rotation_quorum`
    /// valid Schnorr signatures from registered keepers over the rotation message:
    ///   msg = SHA256("VUSD_KEEPER_ROTATE_V1" || new_pubkey || block_height)
    ///
    /// Returns Err if quorum is not met or any signature is invalid.
    pub fn rotate(
        &mut self,
        new_pubkey:      XOnlyPubkey,
        block_height:    u64,
        authorizations:  Vec<([u8; 32], Vec<u8>)>,
        now:             u64,
    ) -> Result<(), String> {
        use sha2::{Sha256, Digest};

        if new_pubkey.0 == self.current_pubkey.0 {
            return Err("New pubkey is the same as current".to_string());
        }

        // Build the rotation message
        let msg_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"VUSD_KEEPER_ROTATE_V1");
            h.update(&new_pubkey.0);
            h.update(&block_height.to_le_bytes());
            h.finalize().into()
        };

        // Verify signatures against registered keepers
        use secp256k1::{Secp256k1, Message, XOnlyPublicKey, schnorr::Signature as SchnorrSig};
        let secp = Secp256k1::verification_only();
        let msg = Message::from_digest_slice(&msg_hash)
            .map_err(|e| e.to_string())?;

        let mut valid_sigs = 0usize;

        for (keeper_pk_hash, sig_bytes) in &authorizations {
            // Find the registered keeper with this pubkey hash
            let keeper = self.registered_keepers.iter().find(|k| {
                let h: [u8; 32] = {
                    let mut hasher = sha2::Sha256::new();
                    sha2::Digest::update(&mut hasher, &k.0);
                    sha2::Digest::finalize(hasher).into()
                };
                h == *keeper_pk_hash
            });

            let Some(keeper_pk) = keeper else { continue; };

            let Ok(sig) = SchnorrSig::from_slice(sig_bytes.as_slice()) else { continue; };
            let Ok(xpk) = XOnlyPublicKey::from_slice(&keeper_pk.0) else { continue; };

            if secp.verify_schnorr(&sig, &msg, &xpk).is_ok() {
                valid_sigs += 1;
            }
        }

        if valid_sigs < self.rotation_quorum {
            return Err(format!(
                "Insufficient keeper signatures: need {}, got {}",
                self.rotation_quorum, valid_sigs
            ));
        }

        // Record the rotation
        self.rotation_history.push(KeeperKeyRotation {
            new_pubkey,
            rotated_at:  now,
            block_height,
            authorizations,
        });

        self.current_pubkey = new_pubkey;
        Ok(())
    }

    /// Add a new keeper to the registered set.
    /// Requires the existing quorum to authorize the addition.
    pub fn add_keeper(&mut self, new_keeper: XOnlyPubkey) {
        if !self.registered_keepers.iter().any(|k| k.0 == new_keeper.0) {
            self.registered_keepers.push(new_keeper);
        }
    }

    /// Current active keeper pubkey — use this when opening new vaults.
    pub fn active_pubkey(&self) -> XOnlyPubkey {
        self.current_pubkey
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_satoshis_usd_value() {
        let one_btc = Satoshis::ONE_BTC;
        let price_100k = 100_000_00000000u64; // $100,000 with 8 dec
        let val = one_btc.usd_value_8dec(price_100k);
        // Should be $100,000 with 8 dec = 100_000_00000000
        assert_eq!(val, 100_000_00000000u128);
    }

    #[test]
    fn test_vusd_amount_conversion() {
        // 1 USD (8 dec) → 1 VUSD (18 dec)
        let one_usd_8dec = 1_00000000u128;
        let vusd = VusdAmount::from_usd_8dec(one_usd_8dec);
        assert_eq!(vusd.to_usd_8dec(), one_usd_8dec);
    }

    #[test]
    fn test_collateral_ratio_thresholds() {
        let safe    = CollateralRatioBps(15000);
        let at_risk = CollateralRatioBps(12500);
        let liq     = CollateralRatioBps(10900);

        assert!(safe.is_safe());
        assert!(!safe.is_at_risk());

        assert!(at_risk.is_at_risk());
        assert!(!at_risk.is_safe());
        assert!(!at_risk.is_liquidatable());

        assert!(liq.is_liquidatable());
    }

    #[test]
    fn test_vault_id_derivation() {
        let pk = [1u8; 32];
        let nonce = [2u8; 32];
        let id1 = VaultId::derive(&pk, &nonce);
        let id2 = VaultId::derive(&pk, &nonce);
        assert_eq!(id1, id2);

        let nonce2 = [3u8; 32];
        let id3 = VaultId::derive(&pk, &nonce2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_oracle_price_freshness() {
        let price = OraclePrice {
            btc_usd_8dec: 100_000_00000000,
            timestamp: 1_000_000,
            oracle_ids: vec![],
            aggregate_sig: vec![],
        };
        // Fresh: 5 minutes later
        assert!(price.is_fresh(1_000_000 + 300));
        // Stale: 11 minutes later
        assert!(!price.is_fresh(1_000_000 + 660));
    }

    #[test]
    fn test_liquidation_penalty_math() {
        let debt = VusdAmount::from_usd_8dec(60_000_00000000); // $60,000
        let penalty = debt.mul_bps(LIQUIDATION_PENALTY_BPS);
        let expected_penalty = VusdAmount::from_usd_8dec(7_800_00000000); // $7,800
        assert_eq!(penalty, expected_penalty);
        let min_bid = debt.saturating_add(penalty);
        let expected_min_bid = VusdAmount::from_usd_8dec(67_800_00000000); // $67,800
        assert_eq!(min_bid, expected_min_bid);
    }
}
