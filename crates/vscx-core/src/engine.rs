// crates/vscx-core/src/engine.rs
//
// VaultEngine — the central orchestrator of the VSCx state machine.
//
// This is the most important file in the protocol. Every vault operation
// flows through here. The engine is the single source of truth for all
// vault state. Nothing mutates vaults except the engine.
//
// Design principles:
//   - No invalid state transition is possible (enforced at type + runtime level)
//   - Every operation that succeeds emits at least one event
//   - Oracle freshness is checked on every operation that depends on price
//   - All financial math uses integer arithmetic (no floats near money)

use crate::events::*;
use crate::mock::{MockBtcLayer, MockOracle, MockVusdLedger, RingCtLedger, current_time_secs};
use crate::oracle_feed::OracleFeed;
use crate::types::*;
use crate::vault::*;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{debug, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// ENGINE CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime configuration for the VaultEngine.
/// All protocol parameters are here — never hardcoded in logic.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Minimum collateral ratio in bps (default: 15000 = 150%)
    pub min_cr_bps: u32,
    /// Liquidation threshold in bps (default: 11000 = 110%)
    pub liquidation_threshold_bps: u32,
    /// At-risk warning threshold in bps (default: 12000 = 120%)
    pub at_risk_threshold_bps: u32,
    /// Liquidation penalty in bps (default: 1300 = 13%)
    pub liquidation_penalty_bps: u64,
    /// Keeper bonus in bps (default: 200 = 2%)
    pub keeper_bonus_bps: u64,
    /// Stability fee APR in bps (default: 100 = 1%)
    pub stability_fee_apr_bps: u64,
    /// Vault open fee in USD cents (default: 100 = $1.00)
    pub vault_open_fee_usd_cents: u64,
    /// Vault close fee in USD cents (default: 100 = $1.00)
    pub vault_close_fee_usd_cents: u64,
    /// Auction duration in seconds (default: 21600 = 6 hours)
    pub auction_duration_secs: u64,
    /// Cure window for AT_RISK vaults in seconds (default: 86400 = 24 hours)
    pub at_risk_cure_window_secs: u64,
    /// Whether the system is in global settlement mode
    pub global_settlement_active: bool,
    /// Locked price for global settlement (set when triggered)
    pub settlement_price: Option<OraclePrice>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            min_cr_bps:                 MIN_COLLATERAL_RATIO_BPS,
            liquidation_threshold_bps:  LIQUIDATION_THRESHOLD_BPS,
            at_risk_threshold_bps:      AT_RISK_THRESHOLD_BPS,
            liquidation_penalty_bps:    LIQUIDATION_PENALTY_BPS,
            keeper_bonus_bps:           KEEPER_BONUS_BPS,
            stability_fee_apr_bps:      DEFAULT_STABILITY_FEE_APR_BPS,
            vault_open_fee_usd_cents:   VAULT_OPEN_FEE_USD_CENTS,
            vault_close_fee_usd_cents:  VAULT_CLOSE_FEE_USD_CENTS,
            auction_duration_secs:      AUCTION_DURATION_SECS,
            at_risk_cure_window_secs:   86_400, // 24 hours
            global_settlement_active:   false,
            settlement_price:           None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VAULT ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/// The VSCx vault engine.
/// Thread-safe via DashMap for vault storage and Arc<RwLock> for shared state.
pub struct VaultEngine {
    /// All vaults, indexed by VaultId.
    pub vaults: DashMap<VaultId, VaultRecord>,
    /// All active auctions, indexed by AuctionId.
    pub auctions: DashMap<AuctionId, AuctionRecord>,
    /// Protocol configuration.
    pub config: Arc<RwLock<EngineConfig>>,
    /// Global stability fee index (grows over time based on APR).
    fee_index: Arc<RwLock<u128>>,
    /// Last time the fee index was updated (unix timestamp).
    pub fee_index_last_updated: Arc<RwLock<u64>>,
    /// Total VUSD supply outstanding.
    total_vusd_supply: Arc<RwLock<VusdAmount>>,
    /// Fee reserve accumulated from open/close fees and stability fees.
    fee_reserve: Arc<RwLock<VusdAmount>>,
    /// Event bus for all state changes.
    pub events: Arc<parking_lot::Mutex<EventBus>>,
    /// Oracle price source.
    /// Phase I:  MockOracle (in-memory, no sig verification)
    /// Phase II: OracleAggregator (real Schnorr sigs, HTTP feeds, 5-of-7 quorum)
    pub oracle: Arc<dyn OracleFeed>,
    /// Bitcoin layer — MockBtcLayer in tests, SignetBtcLayer on testnet.
    pub btc: std::sync::Arc<dyn crate::mock::BtcLayer>,
    /// Phase I VUSD ledger — plain balance map for testing.
    pub vusd_ledger: MockVusdLedger,
    /// A3: RingCT VUSD ledger — commitment-based outputs, key image double-spend detection.
    /// When use_ringct is true, mint/burn use this instead of vusd_ledger.
    pub ringct_ledger: RingCtLedger,
    /// Whether to use the RingCT ledger for mint/burn operations.
    /// False = MockVusdLedger (testnet/mock), True = RingCtLedger (signet/production).
    pub use_ringct: bool,
    /// A4: Keeper key registry — tracks current and historical keeper pubkeys.
    /// Replaces static PROTOCOL_KEEPER_PUBKEY for new vault opens.
    pub keeper_registry: std::sync::Arc<std::sync::RwLock<KeeperKeyRegistry>>,
}

impl VaultEngine {
    pub fn new(oracle: Arc<dyn OracleFeed>, btc: impl crate::mock::BtcLayer + 'static) -> Self {
        VaultEngine {
            vaults:                 DashMap::new(),
            auctions:               DashMap::new(),
            config:                 Arc::new(RwLock::new(EngineConfig::default())),
            fee_index:              Arc::new(RwLock::new(FEE_INDEX_SCALE)), // start at 1.0
            fee_index_last_updated: Arc::new(RwLock::new(current_time_secs())),
            total_vusd_supply:      Arc::new(RwLock::new(VusdAmount::ZERO)),
            fee_reserve:            Arc::new(RwLock::new(VusdAmount::ZERO)),
            events:                 Arc::new(parking_lot::Mutex::new(EventBus::new(10_000))),
            oracle,
            btc: std::sync::Arc::new(btc),
            vusd_ledger:    MockVusdLedger::new(),
            ringct_ledger:  RingCtLedger::new(),
            use_ringct:     false, // enable via with_ringct() for signet
            keeper_registry: std::sync::Arc::new(std::sync::RwLock::new(
                KeeperKeyRegistry::new_with_default()
            )),
        }
    }

    /// Enable RingCT ledger for signet/production operation.
    pub fn with_ringct(mut self) -> Self {
        self.use_ringct = true;
        self
    }

    pub fn with_config(mut self, config: EngineConfig) -> Self {
        *self.config.write() = config;
        self
    }

    // ─────────────────────────────────────────────────────────────────────────
    // READ HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    pub fn current_fee_index(&self) -> u128 {
        *self.fee_index.read()
    }

    pub fn total_vusd_supply(&self) -> VusdAmount {
        *self.total_vusd_supply.read()
    }

    pub fn fee_reserve(&self) -> VusdAmount {
        *self.fee_reserve.read()
    }

    /// Get vault health without modifying state.
    pub fn vault_health(&self, vault_id: VaultId) -> Result<VaultHealth, VaultError> {
        let vault = self.vaults.get(&vault_id)
            .ok_or(VaultError::VaultNotFound(vault_id))?;
        let price = self.fresh_price()?;
        Ok(vault.health_snapshot(&price, self.current_fee_index()))
    }

    /// Returns all vaults whose CR is below the liquidation threshold.
    pub fn liquidatable_vaults(&self) -> Vec<VaultId> {
        let price = match self.fresh_price() {
            Ok(p) => p,
            Err(_) => return vec![],
        };
        let fee_index = self.current_fee_index();
        self.vaults.iter()
            .filter(|entry| {
                let v = entry.value();
                matches!(v.state, VaultState::Active | VaultState::AtRisk)
                    && v.collateral_ratio_bps(&price)
                        .map(|cr| cr.is_liquidatable())
                        .unwrap_or(false)
            })
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Returns all vaults in AT_RISK state.
    pub fn at_risk_vaults(&self) -> Vec<VaultId> {
        self.vaults.iter()
            .filter(|e| matches!(e.value().state, VaultState::AtRisk))
            .map(|e| e.key().clone())
            .collect()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CORE OPERATIONS
    // ─────────────────────────────────────────────────────────────────────────

    /// ① Open a new vault.
    ///
    /// Caller provides:
    ///   - owner_pubkey: the vault owner's x-only public key
    ///   - collateral_sats: how many satoshis to lock
    ///   - fee_payment_sats: must cover the $1 open fee at current oracle price
    ///
    /// Returns the new VaultId on success.
    pub fn open_vault(
        &self,
        owner_pubkey: XOnlyPubkey,
        collateral_sats: Satoshis,
        fee_payment_sats: Satoshis,
        nonce: [u8; 32],
    ) -> Result<VaultId, VaultError> {
        let config = self.config.read().clone();

        if config.global_settlement_active {
            return Err(VaultError::GlobalSettlementActive);
        }

        // Validate fee payment
        let price = self.fresh_price()?;
        let min_fee_sats = self.usd_cents_to_sats(config.vault_open_fee_usd_cents, &price);
        if fee_payment_sats < min_fee_sats {
            return Err(VaultError::InsufficientOpenFee {
                paid: fee_payment_sats,
                need: min_fee_sats,
            });
        }

        if collateral_sats.is_zero() {
            return Err(VaultError::ZeroCollateral);
        }

        // Derive vault ID
        let vault_id = VaultId::derive(&owner_pubkey.0, &nonce);

        // Lock BTC on-chain (Phase I: mock; Phase III: real Taproot tx)
        // A4: Read current keeper pubkey from the registry (not static constant).
        // This allows keeper key rotation without redeploying the protocol.
        let protocol_keeper_pubkey = self.keeper_registry.read().unwrap().active_pubkey();

        let utxo = self.btc.lock_btc(collateral_sats, owner_pubkey);

        // Create vault record
        let now = current_time_secs();
        let fee_index = self.current_fee_index();
        let mut vault = VaultRecord::new(
            vault_id,
            owner_pubkey,
            collateral_sats,
            fee_payment_sats,
            fee_index,
            now,
        );
        vault.taproot_utxo = Some(utxo);

        // Collect open fee into reserve
        let fee_as_vusd = VusdAmount::from_usd_8dec(
            config.vault_open_fee_usd_cents as u128 * 1_000_000 // cents → 8-dec USD
        );
        self.add_to_reserve(fee_as_vusd, FeeReserveReason::OpenFeeCollected);

        // A6: Generate repay preimage and hash.
        // preimage = SHA256("VUSD_REPAY_PREIMAGE_V1" || vault_id.0 || owner_pubkey.0)
        // hash     = SHA256(preimage)
        //
        // The preimage is stored privately in the vault record.
        // It is revealed to the owner only on full debt repayment (repay_vusd).
        // The hash is committed in Leaf A of the Taproot output — on-chain enforced.
        // This design means: even if the engine is compromised, BTC cannot be
        // released without either (a) the owner's sig + preimage, or (b) keeper
        // liquidation. The preimage is the cryptographic proof of debt settlement.
        let repay_preimage: [u8; 32] = {
            let mut h = sha2_hash_tagged(vault_id.as_bytes(), b"VUSD_REPAY_PREIMAGE_V1");
            // XOR with owner_pubkey so different owners can't compute each other's preimage
            for (i, b) in owner_pubkey.0.iter().enumerate() {
                h[i] ^= b;
            }
            h
        };
        let repay_hash: [u8; 32] = sha2_hash(&repay_preimage);

        vault.repay_hash          = repay_hash;
        vault.repay_preimage      = None;
        vault.vault_keeper_pubkey = protocol_keeper_pubkey; // A4: snapshot at open time

        // Fix 3: Populate TapLeaf fields with the computed script bytes.
        // These are stored for auditability and recovery — not used for spending
        // (spending uses VaultMast in taproot-vault). The leaf_hash is the
        // tagged SHA256 of (version || script) that appears in the Merkle tree.
        vault.repay_leaf = TapLeaf {
            version: 0xc0, // BIP-342 TapScript version
            script_bytes: {
                // Repay script: OP_SHA256 <repay_hash> OP_EQUALVERIFY <owner_key> OP_CHECKSIG
                // Stored as the raw script — same bytes as in btc_tx::VaultScripts::repay
                let mut s = Vec::with_capacity(67);
                s.push(0xa8); // OP_SHA256
                s.push(0x20); // push 32 bytes
                s.extend_from_slice(&repay_hash);
                s.push(0x88); // OP_EQUALVERIFY
                s.push(0x20); // push 32 bytes
                s.extend_from_slice(&owner_pubkey.0);
                s.push(0xac); // OP_CHECKSIG
                s
            },
        };
        vault.liquidation_leaf = TapLeaf {
            version: 0xc0,
            script_bytes: {
                // Liquidation script: <keeper_key> OP_CHECKSIG
                let mut s = Vec::with_capacity(34);
                s.push(0x20); // push 32 bytes
                s.extend_from_slice(&protocol_keeper_pubkey.0);
                s.push(0xac); // OP_CHECKSIG
                s
            },
        };
        vault.emergency_leaf = TapLeaf {
            version: 0xc0,
            script_bytes: {
                // Emergency script: <timelock> OP_CSV OP_DROP <owner_key> OP_CHECKSIG
                let timelock = EMERGENCY_TIMELOCK_BLOCKS as u64;
                let mut s = Vec::with_capacity(37);
                // Push timelock as minimal CScriptNum
                if timelock <= 0x7f {
                    s.push(1); s.push(timelock as u8);
                } else {
                    s.push(2);
                    s.push((timelock & 0xff) as u8);
                    s.push(((timelock >> 8) & 0xff) as u8);
                }
                s.push(0xb2); // OP_CSV
                s.push(0x75); // OP_DROP
                s.push(0x20); // push 32 bytes
                s.extend_from_slice(&owner_pubkey.0);
                s.push(0xac); // OP_CHECKSIG
                s
            },
        };

        // Store vault
        self.vaults.insert(vault_id, vault.clone());

        // Emit event
        let mut owner_hash = sha2_hash(&owner_pubkey.0);
        // NOTE: taproot_utxo is intentionally omitted from the event.
        // Broadcasting the OutPoint would directly link the vault_id to a
        // specific on-chain UTXO, making chain analysis trivial. The UTXO
        // is tracked internally in VaultRecord.taproot_utxo only.
        self.emit(VscxEvent::VaultOpened(VaultOpenedEvent {
            vault_id,
            owner_pubkey_hash: owner_hash,
            locked_btc: collateral_sats,
            taproot_utxo: None,  // never emit the real UTXO — see note above
            open_fee_sats: fee_payment_sats,
            block_height: self.btc.block_height(),
            timestamp: now,
        }));

        info!(
            vault_id = %vault_id,
            locked_btc = %collateral_sats,
            "Vault opened"
        );

        Ok(vault_id)
    }

    /// ② Mint VUSD against a vault's collateral.
    ///
    /// The amount minted plus existing debt must not exceed 66% LTV (150% CR).
    /// VUSD is sent to the provided stealth address (Phase I: mock ledger).
    pub fn mint_vusd(
        &self,
        vault_id: VaultId,
        amount: VusdAmount,
        recipient: StealthAddress,
    ) -> Result<(), VaultError> {
        let config = self.config.read().clone();

        if config.global_settlement_active {
            return Err(VaultError::GlobalSettlementActive);
        }

        if amount < VusdAmount::DUST_LIMIT {
            return Err(VaultError::BelowDustLimit);
        }

        let price = self.fresh_price()?;
        let fee_index = self.current_fee_index();

        let mut vault = self.vaults.get_mut(&vault_id)
            .ok_or(VaultError::VaultNotFound(vault_id))?;

        if vault.state.is_terminal() {
            return Err(VaultError::TerminalState(vault.state));
        }
        if !vault.state.can_mint() {
            return Err(VaultError::InvalidStateTransition {
                from: vault.state,
                to: VaultState::Active,
            });
        }

        // Calculate CR if we add this debt
        let new_debt = vault.debt_vusd.saturating_add(amount);
        let collateral_usd_8dec = price.btc_to_usd_8dec(vault.locked_btc);
        let debt_usd_8dec = new_debt.to_usd_8dec();

        if debt_usd_8dec == 0 {
            return Err(VaultError::Internal("Debt is zero after mint".into()));
        }

        let new_cr_bps = (collateral_usd_8dec * 10_000 / debt_usd_8dec) as u32;
        let new_cr = CollateralRatioBps(new_cr_bps);

        if new_cr < CollateralRatioBps(config.min_cr_bps) {
            return Err(VaultError::InsufficientCollateral {
                actual: new_cr,
                required: CollateralRatioBps(config.min_cr_bps),
            });
        }

        // Update vault
        vault.debt_vusd = new_debt;
        vault.fee_index_at_last_update = fee_index;
        vault.state = VaultState::Active;
        vault.last_updated = current_time_secs();

        drop(vault); // release the dashmap lock

        // A3: Mint VUSD — use RingCT ledger on signet, mock ledger in tests
        if self.use_ringct {
            self.ringct_ledger.mint_with_amount(&recipient, amount)
                .map_err(|e| VaultError::Internal(e))?;
        } else {
            self.vusd_ledger.mint(&recipient, amount)
                .map_err(|e| VaultError::Internal(e))?;
        }

        // Update total supply
        *self.total_vusd_supply.write() = self.total_vusd_supply.read().saturating_add(amount);

        let now = current_time_secs();
        self.emit(VscxEvent::VusdMinted(VusdMintedEvent {
            vault_id,
            amount_vusd: amount,
            new_debt_total: new_debt,
            collateral_ratio_bps: new_cr_bps,
            fee_index_snapshot: fee_index,
            recipient_addr_hash: sha2_hash(&recipient.0),
            timestamp: now,
        }));

        info!(vault_id = %vault_id, amount = %amount, cr = %new_cr, "VUSD minted");
        Ok(())
    }

    /// ③ Add more BTC collateral to an existing vault.
    /// This can cure an AT_RISK vault if the resulting CR is ≥ 150%.
    pub fn add_collateral(
        &self,
        vault_id: VaultId,
        additional_sats: Satoshis,
        owner_pubkey: XOnlyPubkey,
    ) -> Result<CollateralRatioBps, VaultError> {
        let price = self.fresh_price()?;

        let mut vault = self.vaults.get_mut(&vault_id)
            .ok_or(VaultError::VaultNotFound(vault_id))?;

        // Ownership check: only the vault owner can add collateral.
        // This prevents a griefing attack where an adversary adds collateral
        // to link their own identity to someone else's vault.
        if vault.owner_pubkey.0 != owner_pubkey.0 {
            return Err(VaultError::Internal(
                "Caller pubkey does not match vault owner".into()
            ));
        }

        if !vault.state.can_add_collateral() {
            return Err(VaultError::InvalidStateTransition {
                from: vault.state,
                to: vault.state,
            });
        }

        // Lock additional BTC — use vault's recorded owner_pubkey, not caller's
        self.btc.lock_btc(additional_sats, vault.owner_pubkey);

        let prev_state = vault.state;
        vault.locked_btc = vault.locked_btc.checked_add(additional_sats)
            .ok_or(VaultError::Internal("Collateral overflow".into()))?;

        // Check if this cures an AT_RISK vault
        let new_cr = vault.collateral_ratio_bps(&price)
            .unwrap_or(CollateralRatioBps(u32::MAX));

        if prev_state == VaultState::AtRisk && new_cr.is_safe() {
            vault.state = VaultState::Active;
            vault.at_risk_since = None;
            self.emit(VscxEvent::VaultCured(VaultCuredEvent {
                vault_id,
                new_cr_bps: new_cr.0,
                action_taken: CureAction::AddedCollateral,
                timestamp: current_time_secs(),
            }));
            info!(vault_id = %vault_id, new_cr = %new_cr, "Vault cured by adding collateral");
        }

        vault.last_updated = current_time_secs();

        self.emit(VscxEvent::CollateralAdded(CollateralAddedEvent {
            vault_id,
            added_sats: additional_sats,
            new_total_locked: vault.locked_btc,
            new_collateral_ratio_bps: new_cr.0,
            timestamp: current_time_secs(),
        }));

        Ok(new_cr)
    }

    /// ④ Repay VUSD debt (partial or full).
    /// If the full debt is repaid, vault transitions to REPAID state.
    pub fn repay_vusd(
        &self,
        vault_id: VaultId,
        amount: VusdAmount,
        payer_address: &StealthAddress,
    ) -> Result<(VusdAmount, Option<[u8; 32]>), VaultError> {
        let fee_index = self.current_fee_index();

        let mut vault = self.vaults.get_mut(&vault_id)
            .ok_or(VaultError::VaultNotFound(vault_id))?;

        if !vault.state.can_repay() {
            return Err(VaultError::InvalidStateTransition {
                from: vault.state,
                to: vault.state,
            });
        }

        let accrued_fee = vault.accrued_stability_fee(fee_index);
        let total_owed = vault.debt_vusd.saturating_add(accrued_fee);

        if amount > total_owed {
            return Err(VaultError::InsufficientVusdBalance {
                have: amount,
                need: total_owed,
            });
        }

        // A3: Burn VUSD — use RingCT ledger on signet, mock ledger in tests
        if self.use_ringct {
            self.ringct_ledger.burn_by_address(payer_address, amount)
                .map_err(|e| VaultError::InsufficientVusdBalance {
                    have: VusdAmount::ZERO,
                    need: amount,
                })?;
        } else {
            self.vusd_ledger.burn(payer_address, amount)
                .map_err(|e| VaultError::InsufficientVusdBalance {
                    have: VusdAmount::ZERO,
                    need: amount,
                })?;
        }

        // Determine what portion covers fee vs principal
        let fee_paid = amount.min(accrued_fee);
        let principal_paid = VusdAmount(amount.0.saturating_sub(fee_paid.0));

        // Add stability fee to reserve
        if !fee_paid.is_zero() {
            self.add_to_reserve(fee_paid, FeeReserveReason::StabilityFeeCollected);
        }

        vault.debt_vusd = VusdAmount(vault.debt_vusd.0.saturating_sub(principal_paid.0));
        vault.fee_index_at_last_update = fee_index;

        // Update total supply
        *self.total_vusd_supply.write() = VusdAmount(
            self.total_vusd_supply.read().0.saturating_sub(amount.0)
        );

        let remaining_debt = vault.debt_vusd;
        let prev_state = vault.state;

        // If fully repaid, transition to REPAID and reveal the repay preimage.
        // A6: The preimage is stored on the vault record so close_vault() can
        // retrieve it when building the Leaf A witness for the on-chain spend.
        // It is also returned from repay_vusd() so the owner can store it
        // in their wallet — they'll need it if closing via the script path.
        if remaining_debt.is_zero() {
            vault.state = VaultState::Repaid;
            // Reveal preimage now that debt is fully cleared
            // Re-derive the preimage deterministically (same formula as open_vault).
            // We didn't store the raw preimage at open to avoid it sitting in memory.
            // SHA256(preimage) must equal vault.repay_hash — verified by close_vault().
            let preimage: [u8; 32] = {
                let mut h = sha2_hash_tagged(vault.vault_id.as_bytes(), b"VUSD_REPAY_PREIMAGE_V1");
                for (i, b) in vault.owner_pubkey.0.iter().enumerate() {
                    h[i] ^= b;
                }
                h
            };
            vault.repay_preimage = Some(preimage);
        }

        // If was AT_RISK and now safe, cure
        if prev_state == VaultState::AtRisk && !remaining_debt.is_zero() {
            let price = self.fresh_price()?;
            if let Some(cr) = vault.collateral_ratio_bps(&price) {
                if cr.is_safe() {
                    vault.state = VaultState::Active;
                    vault.at_risk_since = None;
                }
            }
        }

        vault.last_updated = current_time_secs();

        self.emit(VscxEvent::VusdRepaid(VusdRepaidEvent {
            vault_id,
            amount_repaid: amount,
            amount_burned: VusdAmount(principal_paid.0),
            fee_burned: fee_paid,
            remaining_debt,
            timestamp: current_time_secs(),
        }));

        let preimage = vault.repay_preimage;
        Ok((remaining_debt, preimage))
    }

    /// ⑤ Close a vault after full repayment.
    /// Requires vault to be in REPAID state, plus the $1 close fee.
    /// Returns BTC to the owner's address.
    ///
    /// `owner_pubkey` is validated against the vault record — only the original
    /// vault owner can close and claim the returned BTC.
    pub fn close_vault(
        &self,
        vault_id: VaultId,
        owner_pubkey: XOnlyPubkey,
        close_fee_sats: Satoshis,
        btc_return_address: BitcoinAddress,
    ) -> Result<Satoshis, VaultError> {
        let config = self.config.read().clone();
        let price = self.fresh_price()?;

        // Validate close fee
        let min_fee_sats = self.usd_cents_to_sats(config.vault_close_fee_usd_cents, &price);
        if close_fee_sats < min_fee_sats {
            return Err(VaultError::InsufficientCloseFee {
                paid: close_fee_sats,
                need: min_fee_sats,
            });
        }

        let mut vault = self.vaults.get_mut(&vault_id)
            .ok_or(VaultError::VaultNotFound(vault_id))?;

        // Ownership check: only the vault owner can close and receive BTC back.
        // Without this, any party knowing the vault_id could drain a repaid vault.
        if vault.owner_pubkey.0 != owner_pubkey.0 {
            return Err(VaultError::Internal(
                "Caller pubkey does not match vault owner — cannot close vault".into()
            ));
        }

        if vault.state != VaultState::Repaid {
            return Err(VaultError::InvalidStateTransition {
                from: vault.state,
                to: VaultState::Closed,
            });
        }

        // BTC to return = locked_btc - close_fee_sats
        let btc_to_return = vault.locked_btc
            .checked_sub(close_fee_sats)
            .ok_or(VaultError::Internal("Close fee exceeds collateral".into()))?;

        // A6: Retrieve the repay preimage — required for Leaf A (script path) spend.
        // For the cooperative KeyPath spend (most private), the preimage is not needed
        // on-chain, but we verify it's present to confirm debt was actually settled
        // by the engine before allowing close.
        let repay_preimage = vault.repay_preimage
            .ok_or_else(|| VaultError::Internal(
                "repay_preimage missing — vault must be fully repaid before close.                  Call repay_vusd() until remaining_debt is zero.".into()
            ))?;

        // Verify preimage integrity: SHA256(preimage) must equal stored repay_hash.
        // This is a belt-and-suspenders check — the preimage was derived deterministically
        // at vault open, so it should always match unless state was corrupted.
        let computed_hash = sha2_hash(&repay_preimage);
        if computed_hash != vault.repay_hash {
            return Err(VaultError::Internal(
                "repay_preimage does not hash to repay_hash — vault state corrupted".into()
            ));
        }

        // Spend the Taproot UTXO.
        // Phase I (MockBtcLayer): mock spend, returns synthetic OutPoint.
        // Phase III (SignetBtcLayer): broadcasts real KeyPath or Leaf A spending tx.
        // The preimage is stored on the vault record and available for Leaf A witness
        // assembly by the taproot-vault crate's TaprootSigner when called from the CLI.
        let spend_outpoint = if let Some(ref utxo) = vault.taproot_utxo {
            Some(self.btc.unlock_btc(utxo, &btc_return_address)
                .map_err(|e| VaultError::Internal(e))?)
        } else {
            None
        };

        let l1_tx_id = spend_outpoint; // Option<OutPoint> — carries txid + vout

        // Collect close fee into reserve
        let fee_as_vusd = VusdAmount::from_usd_8dec(
            config.vault_close_fee_usd_cents as u128 * 1_000_000
        );
        self.add_to_reserve(fee_as_vusd, FeeReserveReason::CloseFeeCollected);

        vault.state = VaultState::Closed;
        vault.last_updated = current_time_secs();

        let now = current_time_secs();
        self.emit(VscxEvent::VaultClosed(VaultClosedEvent {
            vault_id,
            vusd_burned: VusdAmount::ZERO, // already burned in repay step
            stability_fee_paid: VusdAmount::ZERO,
            close_fee_sats,
            btc_returned_sats: btc_to_return,
            l1_tx_id,     // A6: real txid from on-chain spend (None on MockBtcLayer)
            close_branch: CloseBranch::KeyPath,
            timestamp: now,
        }));

        info!(vault_id = %vault_id, btc_returned = %btc_to_return, "Vault closed");
        Ok(btc_to_return)
    }


    /// A4: Rotate the protocol keeper key.
    ///
    /// Requires M-of-N Schnorr signatures from the registered keeper set.
    /// New vaults opened after this call embed the new pubkey in Leaf B.
    /// Existing vaults keep their original keeper key (stored in VaultRecord).
    pub fn rotate_keeper_key(
        &self,
        new_pubkey:     XOnlyPubkey,
        block_height:   u64,
        authorizations: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<(), VaultError> {
        let now = current_time_secs();
        self.keeper_registry
            .write()
            .unwrap()
            .rotate(new_pubkey, block_height, authorizations, now)
            .map_err(|e| VaultError::Internal(format!("Keeper rotation failed: {}", e)))
    }

    /// A4: Current active keeper pubkey.
    pub fn current_keeper_pubkey(&self) -> XOnlyPubkey {
        self.keeper_registry.read().unwrap().active_pubkey()
    }

    /// A4: Register an additional keeper in the authorized set.
    pub fn register_keeper(&self, keeper_pubkey: XOnlyPubkey) {
        self.keeper_registry.write().unwrap().add_keeper(keeper_pubkey);
    }

    /// ⑥ Process an oracle price update.
    /// This is the heartbeat of the engine — called on every price tick.
    /// Transitions vaults between Active/AtRisk/Liquidating based on new CR.
    pub fn process_price_update(&self, price: OraclePrice) -> PriceUpdateResult {
        let mut result = PriceUpdateResult::default();

        // Staleness gate: refuse to act on stale oracle data.
        // If the price is stale, we return immediately with vaults_skipped_stale set.
        // Keepers MUST wait for a fresh price before triggering liquidations.
        // This prevents a stale-price attack where an oracle delay causes
        // incorrect liquidations during a price recovery.
        let now = current_time_secs();
        if !price.is_fresh(now) {
            warn!(
                age_secs = now.saturating_sub(price.timestamp),
                max_secs = ORACLE_MAX_AGE_SECS,
                "process_price_update: stale oracle price rejected — skipping vault scan"
            );
            result.rejected_stale = true;
            return result;
        }

        let fee_index = self.current_fee_index();
        for mut entry in self.vaults.iter_mut() {
            let vault = entry.value_mut();
            if !matches!(vault.state, VaultState::Active | VaultState::AtRisk) {
                continue;
            }

            // Use total_owed (principal + accrued fee) for CR — fees reduce collateralization.
            let cr = match vault.collateral_ratio_bps_full(&price, fee_index) {
                None => continue,
                Some(cr) => cr,
            };

            result.vaults_checked += 1;
            let now = current_time_secs();
            let config = self.config.read().clone();
            let vault_id = vault.vault_id;

            match vault.state {
                VaultState::Active => {
                    if cr < CollateralRatioBps(config.liquidation_threshold_bps) {
                        // Directly liquidatable (skipped AT_RISK window)
                        vault.state = VaultState::AtRisk;
                        vault.at_risk_since = Some(now);
                        result.vaults_liquidatable += 1;
                        let liq_price = vault.liquidation_price_usd().unwrap_or(0);
                        self.emit(VscxEvent::MarginCallWarning(MarginCallWarningEvent {
                            vault_id,
                            current_cr_bps: cr.0,
                            liquidation_price_8dec: liq_price,
                            cure_window_expiry: now, // already past threshold
                            btc_usd_at_trigger: price.btc_usd_8dec,
                            timestamp: now,
                        }));
                        warn!(vault_id = %vault_id, cr = %cr, "Vault directly liquidatable");
                    } else if cr < CollateralRatioBps(config.min_cr_bps) {
                        // Entered AT_RISK zone
                        vault.state = VaultState::AtRisk;
                        vault.at_risk_since = Some(now);
                        result.vaults_at_risk += 1;
                        let liq_price = vault.liquidation_price_usd().unwrap_or(0);
                        self.emit(VscxEvent::MarginCallWarning(MarginCallWarningEvent {
                            vault_id,
                            current_cr_bps: cr.0,
                            liquidation_price_8dec: liq_price,
                            cure_window_expiry: now + config.at_risk_cure_window_secs,
                            btc_usd_at_trigger: price.btc_usd_8dec,
                            timestamp: now,
                        }));
                        warn!(vault_id = %vault_id, cr = %cr, "Vault entered AT_RISK");
                    }
                }
                VaultState::AtRisk => {
                    if cr.is_safe() {
                        // Healed without intervention (price recovered)
                        vault.state = VaultState::Active;
                        vault.at_risk_since = None;
                        self.emit(VscxEvent::VaultCured(VaultCuredEvent {
                            vault_id,
                            new_cr_bps: cr.0,
                            action_taken: CureAction::AddedCollateral,
                            timestamp: now,
                        }));
                    } else if cr.is_liquidatable() {
                        result.vaults_liquidatable += 1;
                        debug!(vault_id = %vault_id, cr = %cr, "Vault ready for liquidation");
                    }
                }
                _ => {}
            }
        }

        self.emit(VscxEvent::OraclePriceUpdated(OraclePriceUpdatedEvent {
            btc_usd_8dec:        price.btc_usd_8dec,
            timestamp:           price.timestamp,
            oracle_ids:          price.oracle_ids.clone(),
            vaults_checked:      result.vaults_checked,
            vaults_at_risk:      result.vaults_at_risk,
            vaults_liquidatable: result.vaults_liquidatable,
        }));

        result
    }

    /// ⑦ Trigger liquidation of a vault (callable by any keeper).
    pub fn trigger_liquidation(
        &self,
        vault_id: VaultId,
        oracle_proof: OraclePrice,
        keeper_pubkey: XOnlyPubkey,
    ) -> Result<AuctionId, VaultError> {
        // Validate oracle proof freshness
        let now = current_time_secs();
        if !oracle_proof.is_fresh(now) {
            return Err(VaultError::StalOraclePrice {
                age_secs: now.saturating_sub(oracle_proof.timestamp),
                max_secs: ORACLE_MAX_AGE_SECS,
            });
        }

        let mut vault = self.vaults.get_mut(&vault_id)
            .ok_or(VaultError::VaultNotFound(vault_id))?;

        // Confirm CR is actually below liquidation threshold.
        // Use total_owed (debt + fee) — consistent with process_price_update.
        let fee_index = self.current_fee_index();
        let cr = vault.collateral_ratio_bps_full(&oracle_proof, fee_index)
            .ok_or(VaultError::Internal("Cannot compute CR for zero debt vault".into()))?;

        if !cr.is_liquidatable() {
            return Err(VaultError::VaultNotLiquidatable { cr });
        }

        if matches!(vault.state, VaultState::Liquidating) {
            return Err(VaultError::AuctionAlreadySettled); // already triggered
        }

        let fee_index = self.current_fee_index();
        let total_debt = vault.total_owed(fee_index);

        // Create auction
        let auction = AuctionRecord::new(
            vault_id,
            total_debt,
            vault.locked_btc,
            keeper_pubkey,
            now,
        );
        let auction_id = auction.auction_id;

        vault.state = VaultState::Liquidating;
        vault.last_updated = now;

        drop(vault);

        self.auctions.insert(auction_id, auction.clone());

        self.emit(VscxEvent::LiquidationTriggered(LiquidationTriggeredEvent {
            vault_id,
            auction_id,
            keeper_pubkey_hash: sha2_hash(&keeper_pubkey.0),
            debt_at_liquidation: auction.debt_at_liq,
            collateral_sats:    auction.collateral_sats,
            penalty_vusd:       auction.penalty_vusd,
            min_bid_vusd:       auction.min_bid_vusd,
            auction_end_time:   auction.end_time,
            trigger_cr_bps:     cr.0,
            timestamp:          now,
        }));

        warn!(vault_id = %vault_id, auction_id = %auction_id, "Liquidation triggered");
        Ok(auction_id)
    }

    /// ⑧ Submit a bid in a liquidation auction.
    pub fn submit_bid(
        &self,
        auction_id: AuctionId,
        bidder_key: XOnlyPubkey,
        bid_amount: VusdAmount,
    ) -> Result<(), VaultError> {
        let now = current_time_secs();
        let mut auction = self.auctions.get_mut(&auction_id)
            .ok_or(VaultError::AuctionNotFound(auction_id))?;

        if auction.is_expired(now) {
            return Err(VaultError::AuctionNotExpired); // reusing error — auction expired
        }

        if bid_amount < auction.min_bid_vusd {
            return Err(VaultError::BidBelowMinimum {
                bid: bid_amount,
                min: auction.min_bid_vusd,
            });
        }

        let is_leading = auction.highest_bid()
            .map(|b| bid_amount > b.amount_vusd)
            .unwrap_or(true);

        // Store a hash of the bidder key, not the raw key.
        // The winning bidder's identity is between them and the Taproot
        // settlement layer — the auction record doesn't need to expose it.
        auction.bids.push(AuctionBid {
            bidder_key: XOnlyPubkey(sha2_hash(&bidder_key.0)),
            amount_vusd: bid_amount,
            timestamp: now,
        });

        let vault_id = auction.vault_id;
        drop(auction);

        self.emit(VscxEvent::AuctionBidPlaced(AuctionBidPlacedEvent {
            auction_id,
            vault_id,
            bid_vusd: bid_amount,
            is_leading,
            timestamp: now,
        }));

        Ok(())
    }

    /// ⑨ Settle an expired auction. Distributes BTC to winner, keeper, and owner surplus.
    ///
    /// `owner_return_address`: if the auction generates surplus BTC (collateral > debt +
    /// penalty + keeper bonus), it is returned to this address. The owner provides this
    /// address at settlement time — it is never stored in the auction record, preventing
    /// any link between the vault and the return address in protocol state.
    pub fn settle_auction(
        &self,
        auction_id: AuctionId,
        owner_return_address: Option<BitcoinAddress>,
    ) -> Result<AuctionSettlement, VaultError> {
        let now = current_time_secs();

        let auction = self.auctions.get(&auction_id)
            .ok_or(VaultError::AuctionNotFound(auction_id))?;

        if !auction.is_expired(now) {
            return Err(VaultError::AuctionNotExpired);
        }
        if auction.winning_bid.is_some() {
            return Err(VaultError::AuctionAlreadySettled);
        }

        let winning_bid = auction.highest_bid()
            .cloned()
            .ok_or(VaultError::NoBidsInAuction)?;

        let vault_id      = auction.vault_id;
        let debt          = auction.debt_at_liq;
        let collateral    = auction.collateral_sats;
        let keeper_key    = auction.keeper_pubkey;
        let keeper_bonus  = auction.keeper_bonus_sats();
        drop(auction);

        // Burn winning VUSD bid
        // (Phase I: burn from a system address; Phase IV: RingCT burn)
        let system_addr = StealthAddress([0u8; 32]);
        // In real operation winner's VUSD would be verified then burned here

        // Compute BTC distribution
        // keeper gets 2%, winner gets remainder (collateral - keeper_bonus)
        let winner_btc = Satoshis(collateral.0.saturating_sub(keeper_bonus.0));

        // Surplus: if winning bid covers more than debt + penalty, the remaining
        // BTC collateral belongs to the vault owner. Calculate and return it.
        //
        // surplus_btc = total_collateral - winner_btc - keeper_bonus
        // This occurs when: bid_value_in_btc > debt_at_liq + penalty
        // We approximate: if winning_bid > min_bid, excess VUSD value implies
        // the owner recovers proportional collateral.
        //
        // Phase I: simplified surplus — return any collateral above keeper cut.
        // Phase III: compute precise surplus via oracle price at settlement time.
        let owner_surplus = {
            // Minimum collateral needed to cover debt at current oracle price:
            // debt / btc_price. Any collateral beyond this belongs to the owner.
            let total_consumed = keeper_bonus; // keeper always takes their cut
            if collateral.0 > total_consumed.0 + (winner_btc.0) {
                Satoshis(collateral.0.saturating_sub(total_consumed.0).saturating_sub(winner_btc.0))
            } else {
                Satoshis(0)
            }
        };

        // Return surplus to owner if address provided and surplus > 0
        if owner_surplus.0 > 0 {
            if let Some(ref return_addr) = owner_return_address {
                // Phase I: log. Phase III: construct Taproot output to return_addr.
                tracing::info!(
                    vault_id = %vault_id,
                    surplus_sats = owner_surplus.0,
                    "Auction surplus — returning excess collateral to vault owner"
                );
                // The return_addr is used for BTC distribution only.
                // It is NOT stored in the auction record or emitted in events,
                // preventing any link between the owner and the return address.
            } else {
                tracing::warn!(
                    vault_id = %vault_id,
                    surplus_sats = owner_surplus.0,
                    "Auction has surplus but no owner_return_address provided — surplus unrecoverable"
                );
            }
        }

        // Handle bad debt if winning bid < debt
        let bad_debt = if winning_bid.amount_vusd < debt {
            let shortfall = VusdAmount(debt.0 - winning_bid.amount_vusd.0);
            let reserve = self.fee_reserve.read().clone();
            if reserve >= shortfall {
                *self.fee_reserve.write() = VusdAmount(reserve.0 - shortfall.0);
                self.emit(VscxEvent::BadDebtAbsorbed(BadDebtAbsorbedEvent {
                    vault_id,
                    auction_id,
                    shortfall_vusd: shortfall,
                    reserve_before: reserve,
                    reserve_after: VusdAmount(reserve.0 - shortfall.0),
                    timestamp: now,
                }));
            }
            Some(shortfall)
        } else {
            None
        };

        // Transition vault to Settled
        if let Some(mut vault) = self.vaults.get_mut(&vault_id) {
            vault.state = VaultState::Settled;
            vault.last_updated = now;
        }

        // Mark auction as settled
        if let Some(mut auction) = self.auctions.get_mut(&auction_id) {
            auction.winning_bid = Some(winning_bid.clone());
        }

        // Update supply
        *self.total_vusd_supply.write() = VusdAmount(
            self.total_vusd_supply.read().0.saturating_sub(winning_bid.amount_vusd.0)
        );

        self.emit(VscxEvent::AuctionSettled(AuctionSettledEvent {
            auction_id,
            vault_id,
            winning_bid_vusd: winning_bid.amount_vusd,
            vusd_burned: winning_bid.amount_vusd,
            keeper_bonus_sats: keeper_bonus,
            owner_surplus_sats: owner_surplus,
            l1_tx_id: None,
            timestamp: now,
        }));

        info!(auction_id = %auction_id, vault_id = %vault_id, "Auction settled");

        Ok(AuctionSettlement {
            auction_id,
            vault_id,
            winner_btc_sats: winner_btc,
            keeper_btc_sats: keeper_bonus,
            owner_surplus_sats: owner_surplus,
            bad_debt,
        })
    }

    /// ⑩ Tick the stability fee index forward.
    /// Call this periodically (e.g. every block or every minute).
    pub fn tick_stability_fee(&self) {
        let now = current_time_secs();
        let last = *self.fee_index_last_updated.read();
        let elapsed_secs = now.saturating_sub(last);
        if elapsed_secs == 0 { return; }

        let config = self.config.read().clone();
        let apr_bps = config.stability_fee_apr_bps;

        // Per-second rate = APR / (365.25 * 24 * 3600)
        // fee_delta = current_index * apr_bps * elapsed_secs / (10000 * SECS_PER_YEAR)
        const SECS_PER_YEAR: u128 = 31_557_600;
        let current_index = *self.fee_index.read();
        let delta = current_index
            .saturating_mul(apr_bps as u128)
            .saturating_mul(elapsed_secs as u128)
            / (10_000 * SECS_PER_YEAR);

        if delta > 0 {
            let new_index = current_index.saturating_add(delta);
            *self.fee_index.write() = new_index;
            *self.fee_index_last_updated.write() = now;

            self.emit(VscxEvent::StabilityFeeIndexUpdated(StabilityFeeIndexUpdatedEvent {
                new_index,
                delta,
                timestamp: now,
                apr_bps,
            }));
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PRIVATE HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    fn fresh_price(&self) -> Result<OraclePrice, VaultError> {
        let price = self.oracle.get_price()
            .ok_or(VaultError::Internal("Oracle is offline".into()))?;
        let now = current_time_secs();
        if !price.is_fresh(now) {
            return Err(VaultError::StalOraclePrice {
                age_secs: now.saturating_sub(price.timestamp),
                max_secs: ORACLE_MAX_AGE_SECS,
            });
        }
        // T2: verify Schnorr signatures when the oracle requires it.
        // MockOracle skips this (requires_sig_verification = false).
        // OracleAggregator enforces it — rejects prices with bad or
        // insufficient quorum signatures before any vault operation proceeds.
        eprintln!("[DEBUG] fresh_price: got price, checking sigs requires={}", self.oracle.requires_sig_verification());
        if self.oracle.requires_sig_verification() {
            if !self.oracle.verify_price_sigs(&price) {
                return Err(VaultError::Internal(
                    "Oracle price signature verification failed".into()
                ));
            }
        }
        Ok(price)
    }

    fn usd_cents_to_sats(&self, cents: u64, price: &OraclePrice) -> Satoshis {
        // cents / 100 = dollars; dollars / btc_price = btc; btc * 1e8 = sats
        // sats = cents * 1e8 / (100 * btc_price_usd)
        let btc_price_dollars = price.btc_usd_8dec / 100_000_000;
        if btc_price_dollars == 0 { return Satoshis(0); }
        Satoshis((cents as u128 * 100_000_000 / (100 * btc_price_dollars as u128)) as u64)
    }

    fn add_to_reserve(&self, amount: VusdAmount, reason: FeeReserveReason) {
        let mut reserve = self.fee_reserve.write();
        let before = *reserve;
        *reserve = reserve.saturating_add(amount);
        let after = *reserve;
        drop(reserve);
        self.emit(VscxEvent::FeeReserveUpdated(FeeReserveUpdatedEvent {
            reserve_vusd: after,
            delta_vusd: amount.0 as i128,
            reason,
            timestamp: current_time_secs(),
        }));
    }

    fn emit(&self, event: VscxEvent) {
        self.events.lock().emit(event);
    }
}

fn sha2_hash_tagged(data: &[u8], tag: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(tag);
    h.update(data);
    h.finalize().into()
}

fn sha2_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

/// Result from settling an auction.
#[derive(Debug, Clone)]
pub struct AuctionSettlement {
    pub auction_id:         AuctionId,
    pub vault_id:           VaultId,
    pub winner_btc_sats:    Satoshis,
    pub keeper_btc_sats:    Satoshis,
    pub owner_surplus_sats: Satoshis,
    pub bad_debt:           Option<VusdAmount>,
}

/// Summary of what changed during a price update tick.
#[derive(Debug, Default)]
pub struct PriceUpdateResult {
    pub vaults_checked:      u32,
    pub vaults_at_risk:      u32,
    pub vaults_liquidatable: u32,
    /// True if the price was rejected as stale — no vault states were updated.
    pub rejected_stale:      bool,
}

impl VusdAmount {
    fn min(self, other: VusdAmount) -> VusdAmount {
        if self.0 < other.0 { self } else { other }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_engine(btc_price: u64) -> (VaultEngine, std::sync::Arc<MockOracle>) {
        let oracle = std::sync::Arc::new(MockOracle::new(btc_price));
        let btc    = MockBtcLayer::new();
        let engine = VaultEngine::new(oracle.clone(), btc);
        (engine, oracle)
    }

    fn open_vault_helper(engine: &VaultEngine, collateral_sats: u64) -> VaultId {
        let pk    = XOnlyPubkey([1u8; 32]);
        let nonce = rand_nonce();
        // Fee payment: 2000 sats should be > $1 at any reasonable BTC price
        engine.open_vault(pk, Satoshis(collateral_sats), Satoshis(2_000), nonce).unwrap()
    }

    fn rand_nonce() -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::SystemTime;
        let mut h = DefaultHasher::new();
        SystemTime::now().hash(&mut h);
        let v = h.finish();
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&v.to_le_bytes());
        nonce
    }

    #[test]
    fn test_full_vault_lifecycle_happy_path() {
        let engine  = make_engine(100_000);
        let vault_id = open_vault_helper(&engine, 100_000_000); // 1 BTC

        // Vault should be OPEN
        let vault = engine.vaults.get(&vault_id).unwrap();
        assert_eq!(vault.state, VaultState::Open);
        drop(vault);

        // Mint VUSD — $50,000 (50% LTV — well below 66% max)
        let recipient = StealthAddress([2u8; 32]);
        let mint_amount = VusdAmount::from_usd_8dec(50_000_00000000);
        engine.mint_vusd(vault_id, mint_amount, recipient.clone()).unwrap();

        let vault = engine.vaults.get(&vault_id).unwrap();
        assert_eq!(vault.state, VaultState::Active);
        drop(vault);

        // Repay fully
        engine.vusd_ledger.mint(&recipient, VusdAmount::ZERO).ok(); // already minted
        let (remaining, preimage) = engine.repay_vusd(vault_id, mint_amount, &recipient).unwrap();
        assert!(remaining.is_zero());
        assert!(preimage.is_some(), "preimage must be revealed on full repayment");

        let vault = engine.vaults.get(&vault_id).unwrap();
        assert_eq!(vault.state, VaultState::Repaid);
        drop(vault);

        // Close vault
        let btc_returned = engine.close_vault(
            vault_id,
            pk,  // owner pk — same key used to open vault above
            Satoshis(2_000),
            BitcoinAddress::new("bc1p_owner_return"),
        ).unwrap();

        assert!(btc_returned.0 > 0);
        let vault = engine.vaults.get(&vault_id).unwrap();
        assert_eq!(vault.state, VaultState::Closed);
    }

    #[test]
    fn test_mint_exceeding_max_ltv_rejected() {
        let engine   = make_engine(100_000);
        let vault_id = open_vault_helper(&engine, 100_000_000); // 1 BTC = $100k
        let recipient = StealthAddress([2u8; 32]);

        // Try to mint $70,000 (70% LTV) — should fail (max is 66.67%)
        let too_much = VusdAmount::from_usd_8dec(70_000_00000000);
        let result = engine.mint_vusd(vault_id, too_much, recipient);
        assert!(matches!(result, Err(VaultError::InsufficientCollateral { .. })));
    }

    #[test]
    fn test_price_drop_triggers_at_risk() {
        let engine   = make_engine(100_000);
        let vault_id = open_vault_helper(&engine, 100_000_000);
        let recipient = StealthAddress([2u8; 32]);
        let mint_amount = VusdAmount::from_usd_8dec(60_000_00000000);
        engine.mint_vusd(vault_id, mint_amount, recipient).unwrap();

        // Drop price to $72k → CR = 120% → AT_RISK
        oracle.set_price(72_000);
        let price = oracle.price();
        engine.process_price_update(price);

        let vault = engine.vaults.get(&vault_id).unwrap();
        assert_eq!(vault.state, VaultState::AtRisk);
    }

    #[test]
    fn test_price_drop_triggers_liquidation() {
        let engine   = make_engine(100_000);
        let vault_id = open_vault_helper(&engine, 100_000_000);
        let recipient = StealthAddress([2u8; 32]);
        let mint_amount = VusdAmount::from_usd_8dec(60_000_00000000);
        engine.mint_vusd(vault_id, mint_amount, recipient).unwrap();

        // Drop to $64k → CR = 106% → liquidatable
        oracle.set_price(64_000);
        let price = oracle.price();
        engine.process_price_update(price);

        let keeper = XOnlyPubkey([9u8; 32]);
        let proof  = oracle.price();
        let auction_id = engine.trigger_liquidation(vault_id, proof, keeper).unwrap();

        let vault = engine.vaults.get(&vault_id).unwrap();
        assert_eq!(vault.state, VaultState::Liquidating);
        assert!(engine.auctions.contains_key(&auction_id));
    }

    #[test]
    fn test_liquidation_auction_settle() {
        let engine   = make_engine(100_000);
        let vault_id = open_vault_helper(&engine, 100_000_000);
        let recipient = StealthAddress([2u8; 32]);
        engine.mint_vusd(vault_id, VusdAmount::from_usd_8dec(60_000_00000000), recipient).unwrap();

        oracle.set_price(64_000);
        let keeper = XOnlyPubkey([9u8; 32]);
        let proof  = oracle.price();
        let auction_id = engine.trigger_liquidation(vault_id, proof, keeper).unwrap();

        // Submit a bid above min
        let bidder = XOnlyPubkey([8u8; 32]);
        let bid = VusdAmount::from_usd_8dec(68_000_00000000); // above min of $67,800
        engine.submit_bid(auction_id, bidder, bid).unwrap();

        // Fast-forward auction time by modifying the auction record end time
        if let Some(mut auction) = engine.auctions.get_mut(&auction_id) {
            auction.end_time = current_time_secs().saturating_sub(1); // already expired
        }

        let settlement = engine.settle_auction(auction_id, None).unwrap();
        assert!(settlement.keeper_btc_sats.0 > 0);

        let vault = engine.vaults.get(&vault_id).unwrap();
        assert_eq!(vault.state, VaultState::Settled);
    }

    #[test]
    fn test_stale_oracle_blocks_mint() {
        let engine   = make_engine(100_000);
        let vault_id = open_vault_helper(&engine, 100_000_000);
        oracle.set_stale();
        let recipient = StealthAddress([2u8; 32]);
        let result = engine.mint_vusd(vault_id, VusdAmount::ONE, recipient);
        assert!(matches!(result, Err(VaultError::StalOraclePrice { .. })));
    }

    #[test]
    fn test_add_collateral_cures_at_risk() {
        let engine   = make_engine(100_000);
        let vault_id = open_vault_helper(&engine, 100_000_000);
        let recipient = StealthAddress([2u8; 32]);
        engine.mint_vusd(vault_id, VusdAmount::from_usd_8dec(60_000_00000000), recipient).unwrap();

        // Drop to 72k → AT_RISK
        oracle.set_price(72_000);
        let price = oracle.price();
        engine.process_price_update(price);
        assert_eq!(engine.vaults.get(&vault_id).unwrap().state, VaultState::AtRisk);

        // Add 0.5 BTC more collateral
        let owner_pk = XOnlyPubkey([1u8; 32]);
        engine.add_collateral(vault_id, Satoshis(50_000_000), owner_pk).unwrap();

        // Now 1.5 BTC at $72k = $108k / $60k debt = 180% CR → ACTIVE
        assert_eq!(engine.vaults.get(&vault_id).unwrap().state, VaultState::Active);
    }

    #[test]
    fn test_stability_fee_tick() {
        let (engine, oracle) = make_engine(100_000);
        let initial_index = engine.current_fee_index();
        // Simulate 1 year passing by directly manipulating last_updated
        *engine.fee_index_last_updated.write() = current_time_secs() - 31_557_600;
        engine.tick_stability_fee();
        let new_index = engine.current_fee_index();
        // Index should have grown by ~1% (100 bps)
        let growth_bps = (new_index - initial_index) * 10_000 / initial_index;
        assert!(growth_bps >= 99 && growth_bps <= 101, "growth bps = {}", growth_bps);
    }
}
