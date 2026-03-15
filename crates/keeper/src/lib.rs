// crates/keeper/src/lib.rs
//
// VSCx Keeper Network
//
// Keepers are permissionless bots that monitor vault collateral ratios and
// trigger liquidation auctions when a vault falls below the 110% threshold.
//
// Keeper lifecycle per vault:
//   1. Monitor: subscribe to oracle price updates, recompute all vault CRs
//   2. Detect:  CR < 110% → vault is liquidatable
//   3. Prove:   fetch fresh oracle proof (< 5 min old)
//   4. Trigger: call engine.trigger_liquidation(vault_id, oracle_proof, keeper_pk)
//   5. Bid:     optionally bid in the auction (keeper can also be a bidder)
//   6. Settle:  after 6h, call engine.settle_auction(auction_id)
//   7. Collect: receive 2% BTC bonus on successful settlement
//
// Multiple keepers can run simultaneously — the first to trigger wins.
// The system is designed so a keeper race condition cannot cause double-triggers.

use dashmap::DashMap;
use oracle::OracleAggregator;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::{debug, info, warn, error};
use vscx_core::{
    AuctionId, MockBtcLayer, MockOracle, Satoshis, VaultEngine,
    VaultId, VaultState, VusdAmount, XOnlyPubkey, current_time_secs,
    KEEPER_BONUS_BPS,
};

// ─────────────────────────────────────────────────────────────────────────────
// KEEPER ERRORS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum KeeperError {
    #[error("Oracle unavailable")]
    OracleUnavailable,

    #[error("Vault not liquidatable: {vault_id:?}")]
    NotLiquidatable { vault_id: VaultId },

    #[error("Already triggered this vault: {vault_id:?}")]
    AlreadyTriggered { vault_id: VaultId },

    #[error("Auction settlement failed: {reason}")]
    SettlementFailed { reason: String },

    #[error("Engine error: {0}")]
    EngineError(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// KEEPER STATS
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime statistics for a keeper bot instance.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KeeperStats {
    pub scans_completed:        u64,
    pub liquidations_triggered: u64,
    pub auctions_settled:       u64,
    pub bids_placed:            u64,
    pub total_bonus_sats:       u64,
    pub failed_triggers:        u64,
    pub last_scan_timestamp:    u64,
    pub last_scan_vault_count:  u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// KEEPER BOT
// ─────────────────────────────────────────────────────────────────────────────

/// A single keeper bot instance.
/// Can be run as a daemon — call `run_scan_cycle()` on each oracle price tick.
pub struct KeeperBot {
    /// Keeper identity (public key for receiving BTC bonus).
    pub keeper_pubkey: XOnlyPubkey,
    /// Keeper ID (for logging).
    pub keeper_id: u8,
    /// Vaults this keeper has already triggered (to avoid double-trigger attempts).
    triggered_vaults: Arc<RwLock<HashSet<VaultId>>>,
    /// Active auctions this keeper is watching for settlement.
    pending_settlements: Arc<RwLock<HashMap<AuctionId, PendingSettlement>>>,
    /// Runtime statistics.
    pub stats: Arc<RwLock<KeeperStats>>,
    /// Whether to also bid in auctions (keeper-as-bidder mode).
    pub bid_in_auctions: bool,
    /// Max VUSD to spend per auction bid (0 = don't bid).
    pub max_bid_vusd: VusdAmount,
}

#[derive(Debug, Clone)]
struct PendingSettlement {
    auction_id: AuctionId,
    vault_id:   VaultId,
    end_time:   u64,
}

impl KeeperBot {
    pub fn new(keeper_id: u8, keeper_pubkey: XOnlyPubkey) -> Self {
        KeeperBot {
            keeper_pubkey,
            keeper_id,
            triggered_vaults:    Arc::new(RwLock::new(HashSet::new())),
            pending_settlements: Arc::new(RwLock::new(HashMap::new())),
            stats:               Arc::new(RwLock::new(KeeperStats::default())),
            bid_in_auctions:     false,
            max_bid_vusd:        VusdAmount::ZERO,
        }
    }

    /// Enable bidding mode: this keeper will also bid in auctions it triggers.
    pub fn with_bidding(mut self, max_bid_vusd: VusdAmount) -> Self {
        self.bid_in_auctions = true;
        self.max_bid_vusd    = max_bid_vusd;
        self
    }

    // ─────────────────────────────────────────────────────────────────────
    // MAIN SCAN CYCLE
    // Called on each oracle price tick (every 60 seconds in production).
    // ─────────────────────────────────────────────────────────────────────

    /// Run one full scan cycle:
    ///   1. Check all liquidatable vaults and trigger
    ///   2. Check all pending auctions and settle expired ones
    pub fn run_scan_cycle(
        &self,
        engine: &VaultEngine,
        oracle: &OracleAggregator,
    ) {
        let now = current_time_secs();
        let mut stats = self.stats.write().unwrap();
        stats.last_scan_timestamp = now;

        // ── Step 1: Trigger new liquidations ──────────────────────────────
        let liquidatable = engine.liquidatable_vaults();
        stats.last_scan_vault_count = engine.vaults.len() as u32;
        stats.scans_completed += 1;
        drop(stats);

        if !liquidatable.is_empty() {
            info!(
                keeper_id = self.keeper_id,
                count = liquidatable.len(),
                "Keeper: found liquidatable vaults"
            );

            let oracle_proof = match oracle.collect_and_aggregate() {
                Ok(p) => p,
                Err(e) => {
                    warn!(keeper_id = self.keeper_id, err = %e, "Keeper: oracle proof failed");
                    self.stats.write().unwrap().failed_triggers += liquidatable.len() as u64;
                    return;
                }
            };

            for vault_id in liquidatable {
                if self.triggered_vaults.read().unwrap().contains(&vault_id) {
                    debug!(keeper_id = self.keeper_id, "Already triggered vault {:?}", vault_id);
                    continue;
                }

                match engine.trigger_liquidation(vault_id, oracle_proof.clone(), self.keeper_pubkey) {
                    Ok(auction_id) => {
                        self.triggered_vaults.write().unwrap().insert(vault_id);

                        // Record pending settlement
                        let end_time = now + vscx_core::AUCTION_DURATION_SECS;
                        self.pending_settlements.write().unwrap().insert(
                            auction_id,
                            PendingSettlement { auction_id, vault_id, end_time },
                        );

                        {
                            let mut stats = self.stats.write().unwrap();
                            stats.liquidations_triggered += 1;
                        }

                        info!(
                            keeper_id  = self.keeper_id,
                            vault_id   = %vault_id,
                            auction_id = %auction_id,
                            end_time   = end_time,
                            "Keeper: liquidation triggered"
                        );

                        // Optionally place an opening bid
                        if self.bid_in_auctions && !self.max_bid_vusd.is_zero() {
                            self.try_place_bid(engine, auction_id, vault_id);
                        }
                    }
                    Err(e) => {
                        warn!(
                            keeper_id = self.keeper_id,
                            vault_id  = %vault_id,
                            err       = %e,
                            "Keeper: trigger failed"
                        );
                        self.stats.write().unwrap().failed_triggers += 1;
                    }
                }
            }
        }

        // ── Step 2: Settle expired auctions ──────────────────────────────
        let expired: Vec<PendingSettlement> = self.pending_settlements
            .read().unwrap()
            .values()
            .filter(|ps| now >= ps.end_time)
            .cloned()
            .collect();

        for ps in expired {
            self.try_settle(engine, ps.auction_id);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // SETTLEMENT
    // ─────────────────────────────────────────────────────────────────────

    fn try_settle(&self, engine: &VaultEngine, auction_id: AuctionId) {
        match engine.settle_auction(auction_id, None) {
            Ok(settlement) => {
                self.pending_settlements.write().unwrap().remove(&auction_id);

                {
                    let mut stats = self.stats.write().unwrap();
                    stats.auctions_settled    += 1;
                    stats.total_bonus_sats    += settlement.keeper_btc_sats.0;
                }

                info!(
                    keeper_id        = self.keeper_id,
                    auction_id       = %auction_id,
                    vault_id         = %settlement.vault_id,
                    keeper_bonus_sats = settlement.keeper_btc_sats.0,
                    bad_debt          = settlement.bad_debt.is_some(),
                    "Keeper: auction settled"
                );

                if let Some(shortfall) = settlement.bad_debt {
                    warn!(
                        keeper_id = self.keeper_id,
                        auction_id = %auction_id,
                        shortfall = %shortfall,
                        "Keeper: bad debt absorbed by fee reserve"
                    );
                }
            }
            Err(e) => {
                error!(
                    keeper_id  = self.keeper_id,
                    auction_id = %auction_id,
                    err        = %e,
                    "Keeper: settlement failed"
                );
                self.stats.write().unwrap().failed_triggers += 1;
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // BIDDING
    // ─────────────────────────────────────────────────────────────────────

    fn try_place_bid(&self, engine: &VaultEngine, auction_id: AuctionId, vault_id: VaultId) {
        let vault = match engine.vaults.get(&vault_id) {
            Some(v) => v.clone(),
            None => return,
        };

        let debt = vault.debt_vusd;
        let penalty = debt.mul_bps(vscx_core::LIQUIDATION_PENALTY_BPS);
        let min_bid  = debt.saturating_add(penalty);

        // Bid at minimum + 1 VUSD above minimum
        let bid = VusdAmount(min_bid.0 + VusdAmount::ONE.0);

        if bid > self.max_bid_vusd {
            debug!(
                keeper_id  = self.keeper_id,
                bid        = %bid,
                max        = %self.max_bid_vusd,
                "Keeper: bid would exceed max_bid — skipping"
            );
            return;
        }

        match engine.submit_bid(auction_id, self.keeper_pubkey, bid) {
            Ok(_) => {
                self.stats.write().unwrap().bids_placed += 1;
                info!(
                    keeper_id  = self.keeper_id,
                    auction_id = %auction_id,
                    bid        = %bid,
                    "Keeper: bid placed"
                );
            }
            Err(e) => {
                warn!(keeper_id = self.keeper_id, err = %e, "Keeper: bid failed");
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // FORCED SETTLE (testnet utility — expire an auction immediately)
    // ─────────────────────────────────────────────────────────────────────

    /// Force-expire a pending auction and settle it immediately.
    /// Used in testnet chaos scenarios.
    pub fn force_settle_all(&self, engine: &VaultEngine) {
        let pending: Vec<_> = self.pending_settlements
            .read().unwrap()
            .values()
            .cloned()
            .collect();

        for ps in pending {
            // Expire the auction by backdating its end_time
            if let Some(mut auction) = engine.auctions.get_mut(&ps.auction_id) {
                auction.end_time = current_time_secs().saturating_sub(1);
            }
            self.try_settle(engine, ps.auction_id);
        }
    }

    pub fn snapshot_stats(&self) -> KeeperStats {
        self.stats.read().unwrap().clone()
    }

    pub fn triggered_count(&self) -> usize {
        self.triggered_vaults.read().unwrap().len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KEEPER COORDINATOR
// ─────────────────────────────────────────────────────────────────────────────

/// Manages a fleet of keeper bots running against the same engine.
/// In production each bot runs in its own process/thread.
/// In testnet simulation, this runs them all synchronously.
pub struct KeeperCoordinator {
    pub keepers: Vec<KeeperBot>,
}

impl KeeperCoordinator {
    pub fn new() -> Self {
        KeeperCoordinator { keepers: Vec::new() }
    }

    pub fn add_keeper(&mut self, keeper: KeeperBot) {
        self.keepers.push(keeper);
    }

    /// Run one scan cycle across ALL keepers.
    /// Simulates a competitive keeper network.
    pub fn run_all(&self, engine: &VaultEngine, oracle: &OracleAggregator) {
        for keeper in &self.keepers {
            keeper.run_scan_cycle(engine, oracle);
        }
    }

    /// Total liquidations triggered across all keepers.
    pub fn total_triggered(&self) -> u64 {
        self.keepers.iter()
            .map(|k| k.stats.read().unwrap().liquidations_triggered)
            .sum()
    }

    /// Total BTC bonus earned across all keepers.
    pub fn total_bonus_sats(&self) -> u64 {
        self.keepers.iter()
            .map(|k| k.stats.read().unwrap().total_bonus_sats)
            .sum()
    }

    /// Build a standard 3-keeper testnet coordinator.
    pub fn new_testnet(engine_oracle_price: u64) -> Self {
        let mut coord = Self::new();
        for id in 0..3u8 {
            let mut pk = [0u8; 32];
            pk[0] = id;
            pk[1] = 0xBE;
            pk[2] = 0xEF;
            let max_bid = VusdAmount::from_usd_8dec(200_000_00000000); // $200k max
            coord.add_keeper(
                KeeperBot::new(id, XOnlyPubkey(pk))
                    .with_bidding(max_bid)
            );
        }
        coord
    }
}

impl Default for KeeperCoordinator {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// AUCTION MONITOR
// ─────────────────────────────────────────────────────────────────────────────

/// Monitors all active auctions and reports status.
pub struct AuctionMonitor;

impl AuctionMonitor {
    /// Print a summary of all active auctions to the log.
    pub fn log_status(engine: &VaultEngine) {
        let now = current_time_secs();
        let mut active = 0;
        let mut expired_unsettled = 0;

        for entry in engine.auctions.iter() {
            let auction = entry.value();
            if auction.winning_bid.is_none() {
                if now < auction.end_time {
                    active += 1;
                    let remaining = auction.end_time - now;
                    info!(
                        auction_id  = %auction.auction_id,
                        vault_id    = %auction.vault_id,
                        min_bid     = %auction.min_bid_vusd,
                        bid_count   = auction.bids.len(),
                        ends_in_sec = remaining,
                        "Active auction"
                    );
                } else {
                    expired_unsettled += 1;
                    warn!(
                        auction_id = %auction.auction_id,
                        "Expired unsettled auction — keeper should settle"
                    );
                }
            }
        }

        info!(
            active             = active,
            expired_unsettled  = expired_unsettled,
            "Auction monitor summary"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oracle::OracleAggregator;
    use vscx_core::*;

    fn make_engine_with_vault(btc_price: u64, debt_usd: u64)
        -> (VaultEngine, VaultId, std::sync::Arc<oracle::OracleAggregator>)
    {
        let btc    = MockBtcLayer::new();
        let (oracle_agg, _) = oracle::OracleAggregator::new_with_mock_feeds(btc_price);
        let agg    = std::sync::Arc::new(oracle_agg);
        let engine = VaultEngine::new(agg.clone(), btc);

        let pk    = XOnlyPubkey([1u8; 32]);
        let nonce = [2u8; 32];
        let vault_id = engine.open_vault(pk, Satoshis(100_000_000), Satoshis(5_000), nonce).unwrap();

        if debt_usd > 0 {
            let addr = StealthAddress([3u8; 32]);
            engine.mint_vusd(
                vault_id,
                VusdAmount::from_usd_8dec(debt_usd * 100_000_000),
                addr,
            ).unwrap();
        }

        (engine, vault_id, agg)
    }

    #[test]
    fn test_keeper_full_lifecycle() {
        let (engine, vault_id, agg) = make_engine_with_vault(100_000, 60_000);

        // Crash price to liquidation zone
        agg.set_all_feed_prices(64_000);
        let price = agg.get_price().expect("oracle offline");
        engine.process_price_update(price);

        // Build oracle aggregator with matching price
        let (oracle_agg, _feeds) = OracleAggregator::new_with_mock_feeds(64_000);

        let keeper = KeeperBot::new(0, XOnlyPubkey([9u8; 32]))
            .with_bidding(VusdAmount::from_usd_8dec(200_000_00000000));

        keeper.run_scan_cycle(&engine, &oracle_agg);

        let stats = keeper.snapshot_stats();
        assert_eq!(stats.liquidations_triggered, 1);
        assert_eq!(stats.bids_placed, 1);

        // Vault should be in LIQUIDATING state
        assert_eq!(
            engine.vaults.get(&vault_id).unwrap().state,
            VaultState::Liquidating
        );

        // Force settle
        keeper.force_settle_all(&engine);

        let stats = keeper.snapshot_stats();
        assert_eq!(stats.auctions_settled, 1);
        assert!(stats.total_bonus_sats > 0, "Keeper should have earned BTC bonus");

        // Vault should be SETTLED
        assert_eq!(
            engine.vaults.get(&vault_id).unwrap().state,
            VaultState::Settled
        );
    }

    #[test]
    fn test_keeper_no_double_trigger() {
        let (engine, vault_id, agg) = make_engine_with_vault(100_000, 60_000);
        agg.set_all_feed_prices(64_000);
        let price = agg.get_price().expect("oracle offline");
        engine.process_price_update(price);

        let (oracle_agg, _) = OracleAggregator::new_with_mock_feeds(64_000);
        let keeper = KeeperBot::new(0, XOnlyPubkey([9u8; 32]));

        // Run twice — should only trigger once
        keeper.run_scan_cycle(&engine, &oracle_agg);
        keeper.run_scan_cycle(&engine, &oracle_agg);

        assert_eq!(keeper.stats.read().unwrap().liquidations_triggered, 1);
    }

    #[test]
    fn test_coordinator_multiple_keepers() {
        let (engine, vault_id, agg) = make_engine_with_vault(100_000, 60_000);
        agg.set_all_feed_prices(64_000);
        let price = agg.get_price().expect("oracle offline");
        engine.process_price_update(price);

        let (oracle_agg, _) = OracleAggregator::new_with_mock_feeds(64_000);
        let coord = KeeperCoordinator::new_testnet(64_000);

        coord.run_all(&engine, &oracle_agg);

        // Only one keeper can trigger (first wins, rest get "already triggered" from engine)
        // The vault should be in LIQUIDATING state exactly once
        assert_eq!(
            engine.vaults.get(&vault_id).unwrap().state,
            VaultState::Liquidating
        );

        // Total triggered across all keepers = 1 (only one can win)
        assert_eq!(coord.total_triggered(), 1);
    }

    #[test]
    fn test_keeper_stats_accumulate() {
        let keeper = KeeperBot::new(0, XOnlyPubkey([9u8; 32]));
        assert_eq!(keeper.snapshot_stats().scans_completed, 0);

        // Open a vault with no liquidatable position
        let (engine, _) = make_engine_with_vault(100_000, 0);
        let (oracle_agg, _) = OracleAggregator::new_with_mock_feeds(100_000);

        keeper.run_scan_cycle(&engine, &oracle_agg);
        assert_eq!(keeper.snapshot_stats().scans_completed, 1);
        assert_eq!(keeper.snapshot_stats().liquidations_triggered, 0);
    }
}
