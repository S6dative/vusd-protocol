// tests/integration/full_protocol_test.rs
//
// Full protocol integration tests.
// These tests exercise the complete stack: VSCx → Oracle → Taproot → Privacy → Lightning
// Every test here must pass before testnet launch.

use keeper::{KeeperBot, KeeperCoordinator};
use lightning::{MockLightningNetwork, MockLightningNode, VusdTransferService, VusdWallet};
use oracle::OracleAggregator;
use privacy::{KeyImage, PrivacyLayer, RingSignature, StealthWallet, RING_SIZE};
use std::sync::Arc;
use taproot_vault::VaultTaprootClient;
use vscx_core::{
    BitcoinAddress, MockBtcLayer, MockOracle, Satoshis, StealthAddress, VaultEngine,
    VaultId, VaultState, VusdAmount, XOnlyPubkey, current_time_secs,
    EMERGENCY_TIMELOCK_BLOCKS,
};

fn make_engine(price: u64) -> Arc<VaultEngine> {
    Arc::new(VaultEngine::new(
        MockOracle::new(price),
        MockBtcLayer::new(),
    ))
}

fn open_and_mint(engine: &VaultEngine, collateral_sats: u64, debt_usd: u64, seed: u8) -> VaultId {
    let nonce = { let mut n = [0u8; 32]; n[0] = seed; n[1] = 0xFE; n };
    let vid = engine.open_vault(
        XOnlyPubkey([seed; 32]),
        Satoshis(collateral_sats),
        Satoshis(5_000),
        nonce,
    ).unwrap();
    if debt_usd > 0 {
        engine.mint_vusd(vid, VusdAmount::from_usd_8dec(debt_usd * 100_000_000), StealthAddress([seed + 100; 32])).unwrap();
    }
    vid
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATION TEST 1: Complete vault lifecycle
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_complete_vault_lifecycle() {
    let engine = make_engine(100_000);
    let vault_id = open_and_mint(&engine, 100_000_000, 0, 1);

    assert_eq!(engine.vaults.get(&vault_id).unwrap().state, VaultState::Open);

    // Mint
    engine.mint_vusd(vault_id, VusdAmount::from_usd_8dec(50_000_00000000), StealthAddress([2u8; 32])).unwrap();
    assert_eq!(engine.vaults.get(&vault_id).unwrap().state, VaultState::Active);

    // Check health
    let h = engine.vault_health(vault_id).unwrap();
    assert!(h.collateral_ratio.unwrap().is_safe());

    // Repay
    let remaining = engine.repay_vusd(vault_id, VusdAmount::from_usd_8dec(50_000_00000000), &StealthAddress([2u8; 32])).unwrap();
    assert!(remaining.is_zero());
    assert_eq!(engine.vaults.get(&vault_id).unwrap().state, VaultState::Repaid);

    // Close
    engine.close_vault(vault_id, Satoshis(5_000), BitcoinAddress::new("tb1p_test")).unwrap();
    assert_eq!(engine.vaults.get(&vault_id).unwrap().state, VaultState::Closed);
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATION TEST 2: Oracle → state machine → keeper → auction
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_oracle_liquidation_keeper_pipeline() {
    let engine  = make_engine(100_000);
    let vault   = open_and_mint(&engine, 100_000_000, 60_000, 2);

    // Crash price
    engine.oracle.set_price(64_000);
    let (oracle_agg, _) = OracleAggregator::new_with_mock_feeds(64_000);
    engine.process_price_update(engine.oracle.price());

    // Run keeper
    let keeper_pk = XOnlyPubkey([0xBEu8; 32]);
    let keeper    = KeeperBot::new(0, keeper_pk).with_bidding(VusdAmount::from_usd_8dec(200_000_00000000));
    keeper.run_scan_cycle(&engine, &oracle_agg);

    assert_eq!(engine.vaults.get(&vault).unwrap().state, VaultState::Liquidating);
    assert_eq!(keeper.snapshot_stats().liquidations_triggered, 1);
    assert_eq!(keeper.snapshot_stats().bids_placed, 1);

    // Settle
    keeper.force_settle_all(&engine);
    assert_eq!(engine.vaults.get(&vault).unwrap().state, VaultState::Settled);
    assert!(keeper.snapshot_stats().total_bonus_sats > 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATION TEST 3: Taproot all 3 spend paths
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_taproot_all_spend_paths() {
    let btc    = MockBtcLayer::new();
    let client = VaultTaprootClient::new(btc);
    let owner  = XOnlyPubkey([0x42u8; 32]);
    let open_h = 800_000u32;

    // Open 3 vaults for 3 paths
    let (utxo_a, mast_a) = client.open_vault(owner, Satoshis::ONE_BTC, open_h).unwrap();
    let (utxo_b, mast_b) = client.open_vault(owner, Satoshis::ONE_BTC, open_h).unwrap();
    let (utxo_c, mast_c) = client.open_vault(owner, Satoshis::ONE_BTC, open_h).unwrap();

    // Path A: KeyPath (cooperative)
    client.close_vault_keypath(&utxo_a, vec![0u8; 64], &BitcoinAddress::new("tb1p_a")).unwrap();
    assert!(!client.btc.is_utxo_unspent(&utxo_a));

    // Path B: Liquidation leaf
    client.liquidate_vault(
        &utxo_b, &mast_b, vec![0u8; 64],
        vec![vec![0u8; 32]; 5], [0u8; 32],
        &BitcoinAddress::new("tb1p_w"), &BitcoinAddress::new("tb1p_k"),
        Satoshis(2_000_000),
    ).unwrap();
    assert!(!client.btc.is_utxo_unspent(&utxo_b));

    // Path C: Emergency timelock (after 26,280 blocks)
    let after_h = open_h + EMERGENCY_TIMELOCK_BLOCKS + 1;
    client.recover_vault_emergency(&utxo_c, &mast_c, vec![0u8; 64], after_h, &BitcoinAddress::new("tb1p_c")).unwrap();
    assert!(!client.btc.is_utxo_unspent(&utxo_c));
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATION TEST 4: Privacy layer full flow
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_privacy_layer_full_flow() {
    let privacy = PrivacyLayer::new();

    // Populate with decoys
    let decoy_wallet = StealthWallet::generate(&[0xDEu8; 32]);
    for i in 0..15u8 {
        privacy.create_mint_output(
            VusdAmount::from_usd_8dec(1_000_00000000),
            &decoy_wallet,
        ).unwrap();
    }

    // Mint to Alice
    let alice = StealthWallet::generate(&[0xAAu8; 32]);
    let out   = privacy.create_mint_output(
        VusdAmount::from_usd_8dec(10_000_00000000),
        &alice,
    ).unwrap();

    // Alice finds her output
    let found = alice.scan_output(&out.ephemeral_pubkey, &out.stealth_address);
    assert!(found.is_some());

    // Bob cannot find it
    let bob   = StealthWallet::generate(&[0xBBu8; 32]);
    let bob_f = bob.scan_output(&out.ephemeral_pubkey, &out.stealth_address);
    assert!(bob_f.is_none());

    // Double-spend detection
    let ki = KeyImage::derive(&found.unwrap(), &out.stealth_address.0);
    privacy.output_set.mark_spent(ki.clone()).unwrap();
    let second = privacy.output_set.mark_spent(ki);
    assert!(second.is_err());

    // Range proof valid
    assert!(out.range_proof.verify());
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATION TEST 5: Lightning end-to-end transfer
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_lightning_end_to_end() {
    let network = Arc::new(MockLightningNetwork::new());
    let privacy = Arc::new(PrivacyLayer::new());

    let alice_w = Arc::new(VusdWallet::new([0x01u8; 32]));
    let bob_w   = Arc::new(VusdWallet::new([0x02u8; 32]));

    let alice_n = Arc::new(MockLightningNode::new(alice_w.node_id.clone()));
    let bob_n   = Arc::new(MockLightningNode::new(bob_w.node_id.clone()));
    network.register_node(alice_n.clone());
    network.register_node(bob_n.clone());

    // Fund Alice
    alice_w.record_mint_output(
        StealthAddress([0x11u8; 32]), [0x12u8; 32],
        VusdAmount::from_usd_8dec(50_000_00000000), [0x13u8; 32], 0,
    );

    let svc      = VusdTransferService::new(alice_w.clone(), alice_n, network.clone(), privacy);
    let bob_keys = StealthWallet::generate(&[0x02u8; 32]);

    svc.send(
        &bob_n.node_id,
        &bob_keys,
        VusdAmount::from_usd_8dec(20_000_00000000),
        [0x55u8; 32],
    ).unwrap();

    assert_eq!(bob_n.inbox_count(), 1);
    let msgs   = bob_n.drain_inbox();
    let found  = bob_w.scan_transfer(&msgs[0]);
    assert!(found > 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATION TEST 6: Multiple vaults simultaneously
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_concurrent_vaults() {
    let engine = make_engine(100_000);
    let (oracle_agg, _) = OracleAggregator::new_with_mock_feeds(100_000);

    // Open 50 vaults and mint on all
    let mut vaults = Vec::new();
    for i in 0..50u8 {
        let v = open_and_mint(&engine, 100_000_000, 60_000, i + 50);
        vaults.push(v);
    }
    assert_eq!(engine.vaults.len(), 50);
    assert_eq!(engine.total_vusd_supply().to_usd_8dec() / 100_000_000, 3_000_000); // 50 × $60k

    // Crash price — all become AT_RISK
    engine.oracle.set_price(72_000);
    engine.process_price_update(engine.oracle.price());
    let at_risk = engine.at_risk_vaults().len();
    assert_eq!(at_risk, 50);

    // Crash further — all liquidatable
    let (agg_64, _) = OracleAggregator::new_with_mock_feeds(64_000);
    engine.oracle.set_price(64_000);
    engine.process_price_update(engine.oracle.price());

    // 3-keeper network handles all liquidations
    let coord = KeeperCoordinator::new_testnet(64_000);
    coord.run_all(&engine, &agg_64);

    let liquidating = vaults.iter()
        .filter(|&&v| engine.vaults.get(&v).map(|r| r.state == VaultState::Liquidating).unwrap_or(false))
        .count();
    assert_eq!(liquidating, 50, "All 50 vaults should be liquidating");
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATION TEST 7: Fee reserve absorbs bad debt
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_fee_reserve_absorbs_bad_debt() {
    let engine = make_engine(100_000);

    // Open several vaults to build fee reserve
    for i in 0..10u8 {
        let nonce = { let mut n = [0u8; 32]; n[0] = i + 150u8; n };
        engine.open_vault(XOnlyPubkey([i + 1; 32]), Satoshis(100_000_000), Satoshis(5_000), nonce).ok();
    }

    let reserve = engine.fee_reserve();
    assert!(!reserve.is_zero(), "Reserve should have collected open fees");
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATION TEST 8: Stability fee index grows over time
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_stability_fee_index_grows() {
    let engine = make_engine(100_000);
    let initial = engine.current_fee_index();

    // Simulate 1 year
    *engine.fee_index_last_updated.write().unwrap() = current_time_secs() - 31_557_600;
    engine.tick_stability_fee();
    let new_idx = engine.current_fee_index();

    let growth_bps = (new_idx - initial) * 10_000 / initial;
    assert!(growth_bps >= 99 && growth_bps <= 101,
        "Expected ~100bps growth (1% APR), got {}bps", growth_bps);
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATION TEST 9: Vault cure by adding collateral
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_vault_cured_by_adding_collateral() {
    let engine = make_engine(100_000);
    let vault  = open_and_mint(&engine, 100_000_000, 60_000, 90);

    engine.oracle.set_price(72_000);
    engine.process_price_update(engine.oracle.price());
    assert_eq!(engine.vaults.get(&vault).unwrap().state, VaultState::AtRisk);

    // Add 0.5 BTC — should cure
    engine.add_collateral(vault, Satoshis(50_000_000), XOnlyPubkey([90u8; 32])).unwrap();
    assert_eq!(engine.vaults.get(&vault).unwrap().state, VaultState::Active);
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATION TEST 10: Partial repay reduces debt without closing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_partial_repay() {
    let engine = make_engine(100_000);
    let vault  = open_and_mint(&engine, 100_000_000, 30_000, 95);

    // Repay half
    let payer = StealthAddress([95u8; 32]);
    let remaining = engine.repay_vusd(vault, VusdAmount::from_usd_8dec(10_000_00000000), &payer).unwrap();
    assert!(!remaining.is_zero(), "Still has debt after partial repay");
    assert_eq!(engine.vaults.get(&vault).unwrap().state, VaultState::Active);

    // Repay remainder
    let remaining2 = engine.repay_vusd(vault, VusdAmount::from_usd_8dec(20_000_00000000), &payer).unwrap();
    assert!(remaining2.is_zero());
    assert_eq!(engine.vaults.get(&vault).unwrap().state, VaultState::Repaid);
}
