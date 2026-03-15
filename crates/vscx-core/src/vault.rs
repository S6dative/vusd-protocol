// crates/vscx-core/src/vault.rs
//
// VaultRecord — the primary state object for a VUSD vault.
// VaultState  — the state machine enum with all 7 states.
// VaultError  — all possible failure modes.

use crate::types::*;
use serde::{Deserialize, Serialize};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// VAULT STATE
// ─────────────────────────────────────────────────────────────────────────────

/// The complete set of states a vault can occupy.
/// Transitions are enforced by the VaultEngine — no direct mutation allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultState {
    /// BTC locked, no VUSD minted yet. Vault is open and collateralized.
    Open,
    /// VUSD is outstanding. Stability fee is accruing. CR ≥ 150%.
    Active,
    /// CR has dropped below 150% but is still above 110%.
    /// A 24-hour cure window is open. Vault owner should add collateral or repay.
    AtRisk,
    /// CR has dropped below 110%. Liquidation auction is active.
    /// Vault is frozen — no further mints or repayments until settled.
    Liquidating,
    /// All VUSD debt has been repaid. BTC unlock is pending.
    Repaid,
    /// Liquidation auction has settled. BTC has been distributed.
    Settled,
    /// Terminal state. Vault is destroyed. No further operations possible.
    Closed,
}

impl VaultState {
    /// Returns whether this state allows minting more VUSD.
    pub fn can_mint(self) -> bool {
        matches!(self, VaultState::Open | VaultState::Active)
    }

    /// Returns whether this state allows adding more collateral.
    pub fn can_add_collateral(self) -> bool {
        !matches!(self, VaultState::Liquidating | VaultState::Repaid | VaultState::Settled | VaultState::Closed)
    }

    /// Returns whether this state allows repayment.
    pub fn can_repay(self) -> bool {
        matches!(self, VaultState::Open | VaultState::Active | VaultState::AtRisk)
    }

    /// Returns whether this is a terminal state.
    pub fn is_terminal(self) -> bool {
        matches!(self, VaultState::Closed)
    }

    /// Returns a short human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            VaultState::Open        => "OPEN",
            VaultState::Active      => "ACTIVE",
            VaultState::AtRisk      => "AT_RISK",
            VaultState::Liquidating => "LIQUIDATING",
            VaultState::Repaid      => "REPAID",
            VaultState::Settled     => "SETTLED",
            VaultState::Closed      => "CLOSED",
        }
    }
}

impl fmt::Display for VaultState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VAULT RECORD
// ─────────────────────────────────────────────────────────────────────────────

/// The complete on-chain + off-chain state of a single vault.
/// This struct is the primary storage object in the VaultEngine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRecord {
    // ── Identity ──────────────────────────────────────────────────────────
    /// Unique identifier: SHA256(owner_pubkey || nonce)
    pub vault_id: VaultId,
    /// Owner's x-only Taproot public key.
    pub owner_pubkey: XOnlyPubkey,
    /// The on-chain Taproot UTXO that holds the locked BTC collateral.
    /// Phase I: mock OutPoint. Phase III: real Bitcoin OutPoint.
    pub taproot_utxo: Option<OutPoint>,

    // ── Collateral ────────────────────────────────────────────────────────
    /// Total BTC locked in this vault (in satoshis).
    pub locked_btc: Satoshis,
    /// The satoshi amount paid as the vault open fee ($1 equiv at open time).
    pub open_fee_paid_sats: Satoshis,

    // ── Debt ──────────────────────────────────────────────────────────────
    /// Outstanding VUSD debt (18 decimal base units).
    pub debt_vusd: VusdAmount,
    /// Global fee index snapshot at last debt change.
    /// Used to compute accrued stability fee lazily.
    pub fee_index_at_last_update: u128,

    // ── State ─────────────────────────────────────────────────────────────
    /// Current state in the vault lifecycle state machine.
    pub state: VaultState,
    /// Unix timestamp when the vault was opened.
    pub open_timestamp: u64,
    /// Unix timestamp when the vault entered AT_RISK state (if applicable).
    /// The cure window expires 24 hours after this timestamp.
    pub at_risk_since: Option<u64>,
    /// Unix timestamp of the last state update.
    pub last_updated: u64,

    // ── Taproot Scripts (Phase I: placeholders; Phase III: real TapLeafs) ─
    /// A4: The protocol keeper pubkey at the time this vault was opened.
    /// Stored so Leaf B spends use the correct key even after rotation.
    pub vault_keeper_pubkey: XOnlyPubkey,
    /// Leaf A: owner sig + VUSD burn proof → cooperative close.
    pub repay_leaf: TapLeaf,
    /// Leaf B: keeper sig + oracle proof + auction winner → liquidation.
    pub liquidation_leaf: TapLeaf,
    /// Leaf C: owner sig after emergency timelock (~6 months).
    pub emergency_leaf: TapLeaf,

    // ── Repay Preimage Bridge (A6) ─────────────────────────────────────────
    /// SHA256 of `repay_preimage`. Committed in Leaf A tapscript at vault open.
    /// `OP_SHA256 <repay_hash> OP_EQUALVERIFY <owner_key> OP_CHECKSIG`
    /// This is the hash that gets embedded in the on-chain Taproot output.
    pub repay_hash: [u8; 32],

    /// The secret preimage: SHA256(repay_preimage) == repay_hash.
    /// Generated at vault open and revealed to the owner ONLY on full repayment
    /// (debt == 0 after repay_vusd). Never emitted in events or logs.
    /// The owner uses this to construct a valid Leaf A witness when spending
    /// the vault UTXO cooperatively (without keeper involvement).
    ///
    /// `None` until vault reaches Repaid state. Set by repay_vusd().
    pub repay_preimage: Option<[u8; 32]>,
}

impl VaultRecord {
    /// Create a new vault in OPEN state.
    pub fn new(
        vault_id: VaultId,
        owner_pubkey: XOnlyPubkey,
        locked_btc: Satoshis,
        open_fee_paid_sats: Satoshis,
        current_fee_index: u128,
        now: u64,
    ) -> VaultRecord {
        VaultRecord {
            vault_id,
            owner_pubkey,
            taproot_utxo: None,
            locked_btc,
            open_fee_paid_sats,
            debt_vusd: VusdAmount::ZERO,
            fee_index_at_last_update: current_fee_index,
            state: VaultState::Open,
            open_timestamp: now,
            at_risk_since: None,
            last_updated: now,
            vault_keeper_pubkey: crate::PROTOCOL_KEEPER_PUBKEY,
            repay_leaf: TapLeaf::placeholder(),
            liquidation_leaf: TapLeaf::placeholder(),
            emergency_leaf: TapLeaf::placeholder(),
            repay_hash: [0u8; 32],    // set by engine::open_vault after vault_id known
            repay_preimage: None,      // revealed to owner on full repayment
        }
    }

    /// Returns the accrued stability fee given the current global fee index.
    /// Uses the MakerDAO-style lazy accumulation pattern:
    ///   accrued_fee = debt * (current_index - snapshot_index) / INDEX_SCALE
    pub fn accrued_stability_fee(&self, current_fee_index: u128) -> VusdAmount {
        if self.debt_vusd.is_zero() {
            return VusdAmount::ZERO;
        }
        let index_delta = current_fee_index.saturating_sub(self.fee_index_at_last_update);
        let fee_raw = (self.debt_vusd.0 as u128)
            .saturating_mul(index_delta)
            / FEE_INDEX_SCALE;
        VusdAmount(fee_raw)
    }

    /// Returns the total amount owed (debt + accrued fee).
    pub fn total_owed(&self, current_fee_index: u128) -> VusdAmount {
        let fee = self.accrued_stability_fee(current_fee_index);
        self.debt_vusd.saturating_add(fee)
    }

    /// Computes the collateral ratio in basis points given an oracle price.
    /// Uses only the principal debt (for display / conservative reference).
    /// Returns None if debt is zero (no ratio applicable).
    pub fn collateral_ratio_bps(&self, price: &OraclePrice) -> Option<CollateralRatioBps> {
        self.collateral_ratio_bps_full(price, self.fee_index_at_last_update)
    }

    /// Computes the collateral ratio using total_owed (principal + accrued fee).
    /// This is the CORRECT value for liquidation threshold checks — fees reduce
    /// effective collateralization and must be included.
    ///
    /// `current_fee_index`: the global fee accumulator at the time of the check.
    pub fn collateral_ratio_bps_full(&self, price: &OraclePrice, current_fee_index: u128) -> Option<CollateralRatioBps> {
        let total_owed = self.total_owed(current_fee_index);
        if total_owed.is_zero() {
            return None;
        }
        let collateral_usd = price.btc_to_usd_8dec(self.locked_btc);
        let debt_usd       = total_owed.to_usd_8dec();
        if debt_usd == 0 {
            return None;
        }
        // CR = (collateral / total_owed) * 10000 (basis points)
        // Clamped to u32::MAX to prevent overflow on tiny-debt vaults.
        let cr_bps_u128 = collateral_usd.saturating_mul(10_000) / debt_usd;
        let cr_bps = cr_bps_u128.min(u32::MAX as u128) as u32;
        Some(CollateralRatioBps(cr_bps))
    }

    /// Returns the maximum additional VUSD that can be minted without
    /// violating the 150% minimum collateral ratio.
    pub fn max_additional_vusd(&self, price: &OraclePrice) -> VusdAmount {
        let collateral_usd_8dec = price.btc_to_usd_8dec(self.locked_btc);
        // max_debt = collateral / 1.5 = collateral * 2 / 3
        let max_debt_usd_8dec = collateral_usd_8dec * 2 / 3;
        let max_debt = VusdAmount::from_usd_8dec(max_debt_usd_8dec);
        if max_debt > self.debt_vusd {
            VusdAmount(max_debt.0 - self.debt_vusd.0)
        } else {
            VusdAmount::ZERO
        }
    }

    /// Returns the BTC/USD price at which this vault would be liquidated.
    /// Liquidation price = (debt * 1.10) / locked_btc
    pub fn liquidation_price_usd(&self) -> Option<u64> {
        if self.debt_vusd.is_zero() || self.locked_btc.is_zero() {
            return None;
        }
        // liq_price_8dec = (debt_usd_8dec * 11000 / 10000) / (locked_btc / 1e8)
        //                = (debt_usd_8dec * 11000 * 1e8) / (locked_btc * 10000)
        let debt_usd_8dec = self.debt_vusd.to_usd_8dec();
        let liq_price = (debt_usd_8dec * 11_000 * 100_000_000)
            / (self.locked_btc.0 as u128 * 10_000);
        Some(liq_price as u64)
    }

    /// Returns a snapshot of vault health for display.
    pub fn health_snapshot(&self, price: &OraclePrice, current_fee_index: u128) -> VaultHealth {
        VaultHealth {
            vault_id:          self.vault_id,
            state:             self.state,
            locked_btc:        self.locked_btc,
            debt_vusd:         self.debt_vusd,
            accrued_fee:       self.accrued_stability_fee(current_fee_index),
            total_owed:        self.total_owed(current_fee_index),
            collateral_ratio:  self.collateral_ratio_bps(price),
            liquidation_price: self.liquidation_price_usd(),
            btc_price:         price.btc_usd_8dec,
        }
    }
}

/// A read-only snapshot of a vault's current health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHealth {
    pub vault_id:          VaultId,
    pub state:             VaultState,
    pub locked_btc:        Satoshis,
    pub debt_vusd:         VusdAmount,
    pub accrued_fee:       VusdAmount,
    pub total_owed:        VusdAmount,
    pub collateral_ratio:  Option<CollateralRatioBps>,
    pub liquidation_price: Option<u64>,
    pub btc_price:         u64,
}

impl fmt::Display for VaultHealth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "┌─ Vault Health ──────────────────────")?;
        writeln!(f, "│ ID:        {}", self.vault_id)?;
        writeln!(f, "│ State:     {}", self.state)?;
        writeln!(f, "│ Locked:    {}", self.locked_btc)?;
        writeln!(f, "│ Debt:      {}", self.debt_vusd)?;
        writeln!(f, "│ Fee:       {}", self.accrued_fee)?;
        writeln!(f, "│ Total owed:{}", self.total_owed)?;
        if let Some(cr) = self.collateral_ratio {
            writeln!(f, "│ CR:        {}", cr)?;
        }
        if let Some(lp) = self.liquidation_price {
            writeln!(f, "│ Liq.price: ${:.2}", lp as f64 / 1e8)?;
        }
        writeln!(f, "└─────────────────────────────────────")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AUCTION RECORD
// ─────────────────────────────────────────────────────────────────────────────

/// A bid in a liquidation auction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuctionBid {
    pub bidder_key:  XOnlyPubkey,
    pub amount_vusd: VusdAmount,
    pub timestamp:   u64,
}

/// The full state of a liquidation auction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuctionRecord {
    pub auction_id:       AuctionId,
    pub vault_id:         VaultId,
    /// Outstanding VUSD debt at the time of liquidation.
    pub debt_at_liq:      VusdAmount,
    /// BTC collateral available to auction.
    pub collateral_sats:  Satoshis,
    /// Liquidation penalty (13% of debt).
    pub penalty_vusd:     VusdAmount,
    /// Minimum valid bid = debt + penalty.
    pub min_bid_vusd:     VusdAmount,
    /// The keeper who triggered this liquidation.
    pub keeper_pubkey:    XOnlyPubkey,
    /// Auction start time (unix timestamp).
    pub start_time:       u64,
    /// Auction end time (start + 6 hours).
    pub end_time:         u64,
    /// All bids received, sorted by amount descending.
    pub bids:             Vec<AuctionBid>,
    /// Winning bid (set on settlement).
    pub winning_bid:      Option<AuctionBid>,
}

impl AuctionRecord {
    pub fn new(
        vault_id: VaultId,
        debt_at_liq: VusdAmount,
        collateral_sats: Satoshis,
        keeper_pubkey: XOnlyPubkey,
        now: u64,
    ) -> AuctionRecord {
        let penalty_vusd = debt_at_liq.mul_bps(LIQUIDATION_PENALTY_BPS);
        let min_bid_vusd = debt_at_liq.saturating_add(penalty_vusd);
        let auction_id   = AuctionId::derive(&vault_id, now);
        AuctionRecord {
            auction_id,
            vault_id,
            debt_at_liq,
            collateral_sats,
            penalty_vusd,
            min_bid_vusd,
            keeper_pubkey,
            start_time: now,
            end_time:   now + AUCTION_DURATION_SECS,
            bids:        Vec::new(),
            winning_bid: None,
        }
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.end_time
    }

    pub fn highest_bid(&self) -> Option<&AuctionBid> {
        self.bids.iter().max_by_key(|b| b.amount_vusd)
    }

    /// Keeper BTC bonus = 2% of collateral
    pub fn keeper_bonus_sats(&self) -> Satoshis {
        Satoshis((self.collateral_sats.0 as u128 * KEEPER_BONUS_BPS as u128 / 10_000) as u64)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ERRORS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("Vault not found: {0}")]
    VaultNotFound(VaultId),

    #[error("Invalid state transition: {from} → {to}")]
    InvalidStateTransition { from: VaultState, to: VaultState },

    #[error("Insufficient collateral: collateral ratio {actual} < required {required}")]
    InsufficientCollateral { actual: CollateralRatioBps, required: CollateralRatioBps },

    #[error("Oracle price is stale (age {age_secs}s > max {max_secs}s)")]
    StalOraclePrice { age_secs: u64, max_secs: u64 },

    #[error("Amount below dust limit")]
    BelowDustLimit,

    #[error("Insufficient VUSD balance: have {have}, need {need}")]
    InsufficientVusdBalance { have: VusdAmount, need: VusdAmount },

    #[error("Vault is in terminal state {0} — no further operations possible")]
    TerminalState(VaultState),

    #[error("Vault open fee insufficient: paid {paid} sats, need {need} sats")]
    InsufficientOpenFee { paid: Satoshis, need: Satoshis },

    #[error("Vault close fee insufficient: paid {paid} sats, need {need} sats")]
    InsufficientCloseFee { paid: Satoshis, need: Satoshis },

    #[error("Cannot mint: vault collateral is zero")]
    ZeroCollateral,

    #[error("Auction not found: {0}")]
    AuctionNotFound(AuctionId),

    #[error("Auction has not expired yet")]
    AuctionNotExpired,

    #[error("Auction already settled")]
    AuctionAlreadySettled,

    #[error("Bid below minimum: bid {bid}, minimum {min}")]
    BidBelowMinimum { bid: VusdAmount, min: VusdAmount },

    #[error("No bids in auction — bad debt scenario")]
    NoBidsInAuction,

    #[error("Vault is not liquidatable: CR {cr}")]
    VaultNotLiquidatable { cr: CollateralRatioBps },

    #[error("Global settlement already triggered")]
    GlobalSettlementActive,

    #[error("Fee reserve insufficient to cover bad debt: shortfall {shortfall}")]
    FeeReserveInsufficient { shortfall: VusdAmount },

    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AuctionError {
    #[error("Auction not found")]
    NotFound,
    #[error("Auction has expired")]
    Expired,
    #[error("Bid below minimum of {min}")]
    BelowMinimum { min: VusdAmount },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_price(btc_usd: u64) -> OraclePrice {
        OraclePrice {
            btc_usd_8dec: btc_usd * 100_000_000,
            timestamp: 1_700_000_000,
            oracle_ids: vec![1, 2, 3, 4, 5],
            aggregate_sig: vec![],
        }
    }

    fn make_vault(locked_sats: u64, debt_usd: u64) -> VaultRecord {
        let pk    = XOnlyPubkey([1u8; 32]);
        let nonce = [2u8; 32];
        let id    = VaultId::derive(&pk.0, &nonce);
        let mut v = VaultRecord::new(
            id, pk, Satoshis(locked_sats),
            Satoshis(100_000), 0, 1_700_000_000
        );
        if debt_usd > 0 {
            v.debt_vusd = VusdAmount::from_usd_8dec(debt_usd * 100_000_000);
            v.state = VaultState::Active;
        }
        v
    }

    #[test]
    fn test_collateral_ratio_150_pct() {
        // 1 BTC at $100,000 with $60,000 debt = 166.67% CR
        let vault = make_vault(100_000_000, 60_000);
        let price = make_price(100_000);
        let cr = vault.collateral_ratio_bps(&price).unwrap();
        // 100000 / 60000 * 10000 = 16666 bps = 166.66%
        assert!(cr.0 >= 16600 && cr.0 <= 16700);
        assert!(cr.is_safe());
    }

    #[test]
    fn test_collateral_ratio_at_risk() {
        // 1 BTC at $72,000 with $60,000 debt = 120% CR → AT_RISK
        let vault = make_vault(100_000_000, 60_000);
        let price = make_price(72_000);
        let cr = vault.collateral_ratio_bps(&price).unwrap();
        assert!(cr.is_at_risk());
        assert!(!cr.is_safe());
        assert!(!cr.is_liquidatable());
    }

    #[test]
    fn test_collateral_ratio_liquidatable() {
        // 1 BTC at $64,000 with $60,000 debt = 106.67% → LIQUIDATABLE
        let vault = make_vault(100_000_000, 60_000);
        let price = make_price(64_000);
        let cr = vault.collateral_ratio_bps(&price).unwrap();
        assert!(cr.is_liquidatable());
    }

    #[test]
    fn test_liquidation_price() {
        // 1 BTC, $60,000 debt → liq at $60k * 1.10 = $66,000
        let vault = make_vault(100_000_000, 60_000);
        let liq_price = vault.liquidation_price_usd().unwrap();
        let liq_dollars = liq_price as f64 / 1e8;
        // Should be ~$66,000
        assert!((liq_dollars - 66_000.0).abs() < 1.0, "liq price was {}", liq_dollars);
    }

    #[test]
    fn test_max_additional_vusd() {
        // 1 BTC at $100,000 — no debt yet
        let vault = make_vault(100_000_000, 0);
        let price = make_price(100_000);
        let max = vault.max_additional_vusd(&price);
        // Max mintable = $100,000 * 2/3 = $66,666.67
        let max_usd = max.to_usd_8dec() / 100_000_000;
        assert!(max_usd >= 66_666 && max_usd <= 66_667);
    }

    #[test]
    fn test_stability_fee_accrual() {
        // Debt = $10,000 VUSD, fee index moves from 0 to 1e16 (= 1% of FEE_INDEX_SCALE)
        let vault = make_vault(100_000_000, 10_000);
        let fee_index_delta = FEE_INDEX_SCALE / 100; // 1% movement
        let fee = vault.accrued_stability_fee(fee_index_delta);
        // fee = debt * 1% = $100 VUSD
        let fee_usd = fee.to_usd_8dec() / 100_000_000;
        assert_eq!(fee_usd, 100);
    }

    #[test]
    fn test_vault_state_transitions() {
        let vault = make_vault(100_000_000, 0);
        assert_eq!(vault.state, VaultState::Open);
        assert!(vault.state.can_mint());
        assert!(vault.state.can_add_collateral());
        assert!(vault.state.can_repay());
        assert!(!vault.state.is_terminal());
    }

    #[test]
    fn test_auction_min_bid() {
        let debt = VusdAmount::from_usd_8dec(60_000_00000000); // $60,000
        let keeper = XOnlyPubkey([9u8; 32]);
        let auction = AuctionRecord::new(
            VaultId::derive(&[1u8; 32], &[2u8; 32]),
            debt,
            Satoshis(100_000_000),
            keeper,
            1_700_000_000,
        );
        // Min bid = $60,000 + 13% = $67,800
        let min_bid_usd = auction.min_bid_vusd.to_usd_8dec() / 100_000_000;
        assert_eq!(min_bid_usd, 67_800);
    }

    #[test]
    fn test_keeper_bonus() {
        let debt = VusdAmount::from_usd_8dec(60_000_00000000);
        let keeper = XOnlyPubkey([9u8; 32]);
        let auction = AuctionRecord::new(
            VaultId::derive(&[1u8; 32], &[2u8; 32]),
            debt,
            Satoshis(100_000_000), // 1 BTC
            keeper,
            1_700_000_000,
        );
        // 2% of 1 BTC = 0.02 BTC = 2_000_000 sats
        assert_eq!(auction.keeper_bonus_sats().0, 2_000_000);
    }
}
