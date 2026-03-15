// crates/testnet/src/harness.rs
//
// TestnetHarness — builds and holds the full protocol stack for testing.
// All scenarios use this as their shared foundation.

use keeper::KeeperCoordinator;
use lightning::{MockLightningNetwork, MockLightningNode, VusdWallet};
use oracle::OracleAggregator;
use vscx_core::OracleFeed as _;
use privacy::{PrivacyLayer, StealthWallet};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use taproot_vault::VaultTaprootClient;
use vscx_core::{
    BitcoinAddress, MockBtcLayer, MockOracle, Satoshis, StealthAddress,
    VaultEngine, VaultId, VaultState, VusdAmount, XOnlyPubkey, current_time_secs,
};

pub struct TestnetHarness {
    pub engine:      Arc<VaultEngine>,
    pub oracle_agg:  Arc<OracleAggregator>,
    pub privacy:     Arc<PrivacyLayer>,
    pub tap_client:  VaultTaprootClient,
    pub ln_network:  Arc<MockLightningNetwork>,
    pub keepers:     KeeperCoordinator,
    nonce:           std::sync::atomic::AtomicU64,
}

impl TestnetHarness {
    pub fn new(initial_btc_price: u64) -> Self {
        let btc         = MockBtcLayer::new();
        // T1: engine receives Arc<dyn OracleFeed> — OracleAggregator with real Schnorr sigs.
        // The mock feeds allow test price control; OracleFeed impl enables sig verification.
        let (oracle_agg, mock_feeds) = OracleAggregator::new_with_mock_feeds(initial_btc_price);
        let oracle_agg = Arc::new(oracle_agg);
        let engine      = Arc::new(VaultEngine::new(oracle_agg.clone(), btc.clone()));
        let privacy    = Arc::new(PrivacyLayer::new());
        let tap_client = VaultTaprootClient::new(btc);
        let ln_network = Arc::new(MockLightningNetwork::new());
        let keepers    = KeeperCoordinator::new_testnet(initial_btc_price);

        TestnetHarness {
            engine,
            oracle_agg: oracle_agg,
            privacy,
            tap_client,
            ln_network,
            keepers,
            nonce: std::sync::atomic::AtomicU64::new(1),
        }
    }

    pub fn next_nonce(&self) -> [u8; 32] {
        let n = self.nonce.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&n.to_le_bytes());
        out
    }

    pub fn make_owner(&self, seed: u8) -> XOnlyPubkey {
        let mut h = Sha256::new();
        h.update(b"OWNER");
        h.update(&[seed]);
        let r = h.finalize();
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&r);
        XOnlyPubkey(pk)
    }

    pub fn open_vault(&self, owner_seed: u8, collateral_sats: u64) -> VaultId {
        let owner = self.make_owner(owner_seed);
        let nonce = self.next_nonce();
        self.engine.open_vault(
            owner,
            Satoshis(collateral_sats),
            Satoshis(5_000),
            nonce,
        ).expect("open_vault failed")
    }

    pub fn mint(&self, vault_id: VaultId, amount_usd: u64, recipient_seed: u8) {
        let addr = StealthAddress([recipient_seed; 32]);
        self.engine.mint_vusd(
            vault_id,
            VusdAmount::from_usd_8dec(amount_usd as u128 * 100_000_000),
            addr,
        ).expect("mint_vusd failed");
    }

    pub fn set_price(&self, price: u64) {
        eprintln!("[DEBUG] set_price({}) called", price);
        self.oracle_agg.set_all_feed_prices(price);
        if let Some(p) = self.oracle_agg.get_price() {
            self.engine.process_price_update(p);
        }
        eprintln!("[DEBUG] set_price({}) complete", price);
    }

    /// Simulate oracle staleness by taking all shared feeds offline.
    /// The aggregator will return None (no quorum), so fresh_price() returns an error.
    pub fn set_oracle_stale(&self) {
        for feed in &self.oracle_agg.shared_feeds {
            *feed.offline.write().unwrap() = true;
        }
    }

    /// Restore oracle freshness after set_oracle_stale().
    pub fn set_oracle_fresh(&self) {
        for feed in &self.oracle_agg.shared_feeds {
            *feed.offline.write().unwrap() = false;
        }
    }

    pub fn run_keepers(&self) {
        self.keepers.run_all(&self.engine, &self.oracle_agg);
    }

    pub fn settle_all_expired(&self) {
        for keeper in &self.keepers.keepers {
            keeper.force_settle_all(&self.engine);
        }
    }

    pub fn assert_vault_state(&self, vault_id: VaultId, expected: VaultState) {
        let actual = self.engine.vaults.get(&vault_id)
            .map(|v| v.state)
            .expect("vault not found");
        assert_eq!(actual, expected,
            "Vault {} expected {:?} but was {:?}", vault_id, expected, actual);
    }

    /// Repay debt and return the revealed preimage (Some when fully repaid).
    pub fn repay(&self, vault_id: VaultId, amount_usd: u64, payer_seed: u8) -> Option<[u8; 32]> {
        let payer = StealthAddress([payer_seed; 32]);
        let (_, preimage) = self.engine.repay_vusd(
            vault_id,
            VusdAmount::from_usd_8dec(amount_usd as u128 * 100_000_000),
            &payer,
        ).expect("repay failed");
        preimage
    }

    pub fn repay_and_close(&self, vault_id: VaultId, amount_usd: u64, payer_seed: u8) {
        let payer = StealthAddress([payer_seed; 32]);
        let (_, _preimage) = self.engine.repay_vusd(
            vault_id,
            VusdAmount::from_usd_8dec(amount_usd as u128 * 100_000_000),
            &payer,
        ).expect("repay failed");
        // Retrieve vault owner from engine — close requires proof of ownership
        let owner = self.engine.vaults.get(&vault_id)
            .map(|v| v.owner_pubkey)
            .expect("vault not found for close");
        self.engine.close_vault(
            vault_id,
            owner,
            Satoshis(5_000),
            BitcoinAddress::new("tb1p_return"),
        ).expect("close failed");
    }
}
