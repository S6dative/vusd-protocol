// crates/vscx-core/src/events.rs
//
// Complete event schema for all VSCx state changes.
// Events are the audit log, the keeper trigger mechanism,
// and the integration point for external subscribers.

use crate::types::*;
use crate::vault::VaultState;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// EVENT ENUM
// ─────────────────────────────────────────────────────────────────────────────

/// All events emitted by the VSCx engine.
/// Subscribers (keeper bots, UIs, indexers) receive these via the event bus.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VscxEvent {
    VaultOpened(VaultOpenedEvent),
    VusdMinted(VusdMintedEvent),
    CollateralAdded(CollateralAddedEvent),
    VusdRepaid(VusdRepaidEvent),
    MarginCallWarning(MarginCallWarningEvent),
    VaultCured(VaultCuredEvent),
    LiquidationTriggered(LiquidationTriggeredEvent),
    AuctionBidPlaced(AuctionBidPlacedEvent),
    AuctionSettled(AuctionSettledEvent),
    BadDebtAbsorbed(BadDebtAbsorbedEvent),
    VaultClosed(VaultClosedEvent),
    OraclePriceUpdated(OraclePriceUpdatedEvent),
    StabilityFeeIndexUpdated(StabilityFeeIndexUpdatedEvent),
    FeeReserveUpdated(FeeReserveUpdatedEvent),
    GlobalSettlementTriggered(GlobalSettlementTriggeredEvent),
}

impl VscxEvent {
    /// Returns the event name for logging and filtering.
    pub fn name(&self) -> &'static str {
        match self {
            VscxEvent::VaultOpened(_)               => "VaultOpened",
            VscxEvent::VusdMinted(_)                => "VusdMinted",
            VscxEvent::CollateralAdded(_)            => "CollateralAdded",
            VscxEvent::VusdRepaid(_)                 => "VusdRepaid",
            VscxEvent::MarginCallWarning(_)          => "MarginCallWarning",
            VscxEvent::VaultCured(_)                 => "VaultCured",
            VscxEvent::LiquidationTriggered(_)       => "LiquidationTriggered",
            VscxEvent::AuctionBidPlaced(_)           => "AuctionBidPlaced",
            VscxEvent::AuctionSettled(_)             => "AuctionSettled",
            VscxEvent::BadDebtAbsorbed(_)            => "BadDebtAbsorbed",
            VscxEvent::VaultClosed(_)                => "VaultClosed",
            VscxEvent::OraclePriceUpdated(_)         => "OraclePriceUpdated",
            VscxEvent::StabilityFeeIndexUpdated(_)   => "StabilityFeeIndexUpdated",
            VscxEvent::FeeReserveUpdated(_)          => "FeeReserveUpdated",
            VscxEvent::GlobalSettlementTriggered(_)  => "GlobalSettlementTriggered",
        }
    }

    pub fn vault_id(&self) -> Option<VaultId> {
        match self {
            VscxEvent::VaultOpened(e)           => Some(e.vault_id),
            VscxEvent::VusdMinted(e)            => Some(e.vault_id),
            VscxEvent::CollateralAdded(e)       => Some(e.vault_id),
            VscxEvent::VusdRepaid(e)            => Some(e.vault_id),
            VscxEvent::MarginCallWarning(e)     => Some(e.vault_id),
            VscxEvent::VaultCured(e)            => Some(e.vault_id),
            VscxEvent::LiquidationTriggered(e)  => Some(e.vault_id),
            VscxEvent::AuctionSettled(e)        => Some(e.vault_id),
            VscxEvent::VaultClosed(e)           => Some(e.vault_id),
            _                                   => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EVENT PAYLOADS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultOpenedEvent {
    pub vault_id:            VaultId,
    /// Hashed owner pubkey — not the raw key, for privacy
    pub owner_pubkey_hash:   [u8; 32],
    pub locked_btc:          Satoshis,
    pub taproot_utxo:        Option<OutPoint>,
    pub open_fee_sats:       Satoshis,
    pub block_height:        u64,
    pub timestamp:           u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VusdMintedEvent {
    pub vault_id:             VaultId,
    pub amount_vusd:          VusdAmount,
    pub new_debt_total:       VusdAmount,
    pub collateral_ratio_bps: u32,
    pub fee_index_snapshot:   u128,
    /// Hash of the stealth address — not the address itself
    pub recipient_addr_hash:  [u8; 32],
    pub timestamp:            u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollateralAddedEvent {
    pub vault_id:                VaultId,
    pub added_sats:              Satoshis,
    pub new_total_locked:        Satoshis,
    pub new_collateral_ratio_bps: u32,
    pub timestamp:               u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VusdRepaidEvent {
    pub vault_id:       VaultId,
    pub amount_repaid:  VusdAmount,
    pub amount_burned:  VusdAmount,
    pub fee_burned:     VusdAmount,
    pub remaining_debt: VusdAmount,
    pub timestamp:      u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarginCallWarningEvent {
    pub vault_id:             VaultId,
    pub current_cr_bps:       u32,
    pub liquidation_price_8dec: u64,
    pub cure_window_expiry:   u64,
    pub btc_usd_at_trigger:   u64,
    pub timestamp:            u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultCuredEvent {
    pub vault_id:          VaultId,
    pub new_cr_bps:        u32,
    pub action_taken:      CureAction,
    pub timestamp:         u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CureAction {
    AddedCollateral,
    PartialRepay,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidationTriggeredEvent {
    pub vault_id:              VaultId,
    pub auction_id:            AuctionId,
    /// Hashed keeper pubkey
    pub keeper_pubkey_hash:    [u8; 32],
    pub debt_at_liquidation:   VusdAmount,
    pub collateral_sats:       Satoshis,
    pub penalty_vusd:          VusdAmount,
    pub min_bid_vusd:          VusdAmount,
    pub auction_end_time:      u64,
    pub trigger_cr_bps:        u32,
    pub timestamp:             u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuctionBidPlacedEvent {
    pub auction_id:   AuctionId,
    pub vault_id:     VaultId,
    pub bid_vusd:     VusdAmount,
    /// Whether this is currently the highest bid
    pub is_leading:   bool,
    pub timestamp:    u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuctionSettledEvent {
    pub auction_id:          AuctionId,
    pub vault_id:            VaultId,
    pub winning_bid_vusd:    VusdAmount,
    pub vusd_burned:         VusdAmount,
    pub keeper_bonus_sats:   Satoshis,
    pub owner_surplus_sats:  Satoshis,
    pub l1_tx_id:            Option<OutPoint>,
    pub timestamp:           u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadDebtAbsorbedEvent {
    pub vault_id:       VaultId,
    pub auction_id:     AuctionId,
    pub shortfall_vusd: VusdAmount,
    pub reserve_before: VusdAmount,
    pub reserve_after:  VusdAmount,
    pub timestamp:      u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultClosedEvent {
    pub vault_id:           VaultId,
    pub vusd_burned:        VusdAmount,
    pub stability_fee_paid: VusdAmount,
    pub close_fee_sats:     Satoshis,
    pub btc_returned_sats:  Satoshis,
    pub l1_tx_id:           Option<OutPoint>,
    pub close_branch:       CloseBranch,
    pub timestamp:          u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CloseBranch {
    /// Owner used the KeyPath (cheapest, most private — no script revealed)
    KeyPath,
    /// Owner used Leaf A (script path repay — used when KeyPath unavailable)
    RepayLeaf,
    /// Emergency timelock spent (Leaf C — 6 month timelock)
    EmergencyTimelock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OraclePriceUpdatedEvent {
    pub btc_usd_8dec:        u64,
    pub timestamp:           u64,
    pub oracle_ids:          Vec<u8>,
    pub vaults_checked:      u32,
    pub vaults_at_risk:      u32,
    pub vaults_liquidatable: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StabilityFeeIndexUpdatedEvent {
    pub new_index:      u128,
    pub delta:          u128,
    pub timestamp:      u64,
    pub apr_bps:        u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeReserveUpdatedEvent {
    pub reserve_vusd:    VusdAmount,
    pub delta_vusd:      i128,    // signed — can decrease on bad debt absorption
    pub reason:          FeeReserveReason,
    pub timestamp:       u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeeReserveReason {
    OpenFeeCollected,
    CloseFeeCollected,
    StabilityFeeCollected,
    BadDebtAbsorbed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalSettlementTriggeredEvent {
    pub trigger_reason:      GlobalSettlementReason,
    pub final_btc_price_8dec: u64,
    pub total_vusd_supply:   VusdAmount,
    pub total_btc_locked:    Satoshis,
    pub timestamp:           u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GlobalSettlementReason {
    /// System collateral ratio fell below 95%
    SystemUndercollateralized,
    /// Emergency governance trigger
    GovernanceTrigger,
}

// ─────────────────────────────────────────────────────────────────────────────
// EVENT BUS
// ─────────────────────────────────────────────────────────────────────────────

/// A simple synchronous event bus.
/// Phase I: in-memory subscriber list.
/// Phase V: extended with async channels for Lightning integration.
pub struct EventBus {
    subscribers: Vec<Box<dyn Fn(&VscxEvent) + Send + Sync>>,
    history:     Vec<VscxEvent>,
    max_history: usize,
}

impl EventBus {
    pub fn new(max_history: usize) -> Self {
        EventBus {
            subscribers: Vec::new(),
            history: Vec::new(),
            max_history,
        }
    }

    pub fn subscribe(&mut self, handler: impl Fn(&VscxEvent) + Send + Sync + 'static) {
        self.subscribers.push(Box::new(handler));
    }

    pub fn emit(&mut self, event: VscxEvent) {
        tracing::debug!(event = event.name(), vault_id = ?event.vault_id(), "Event emitted");
        for sub in &self.subscribers {
            sub(&event);
        }
        self.history.push(event);
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }

    pub fn history(&self) -> &[VscxEvent] {
        &self.history
    }

    pub fn events_for_vault(&self, vault_id: VaultId) -> Vec<&VscxEvent> {
        self.history.iter()
            .filter(|e| e.vault_id() == Some(vault_id))
            .collect()
    }
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field("history_len", &self.history.len())
            .field("subscribers", &self.subscribers.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_event_bus_subscribe_and_emit() {
        let mut bus = EventBus::new(100);
        let received = Arc::new(Mutex::new(Vec::new()));
        let recv_clone = received.clone();

        bus.subscribe(move |event| {
            recv_clone.lock().unwrap().push(event.name().to_string());
        });

        let event = VscxEvent::OraclePriceUpdated(OraclePriceUpdatedEvent {
            btc_usd_8dec: 100_000_00000000,
            timestamp: 1_700_000_000,
            oracle_ids: vec![1, 2, 3, 4, 5],
            vaults_checked: 10,
            vaults_at_risk: 1,
            vaults_liquidatable: 0,
        });

        bus.emit(event);
        assert_eq!(received.lock().unwrap().len(), 1);
        assert_eq!(received.lock().unwrap()[0], "OraclePriceUpdated");
    }

    #[test]
    fn test_event_history() {
        let mut bus = EventBus::new(5);
        for i in 0..7 {
            bus.emit(VscxEvent::OraclePriceUpdated(OraclePriceUpdatedEvent {
                btc_usd_8dec: i * 100,
                timestamp: i,
                oracle_ids: vec![],
                vaults_checked: 0,
                vaults_at_risk: 0,
                vaults_liquidatable: 0,
            }));
        }
        // History capped at max_history=5
        assert_eq!(bus.history().len(), 5);
    }
}
