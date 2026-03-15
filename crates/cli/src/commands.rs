// crates/cli/src/commands.rs
//
// All CLI command implementations.
// Each command operates against a shared ProtocolContext.

use anyhow::{anyhow, Result};
use keeper::{KeeperBot, KeeperCoordinator, AuctionMonitor};
use lightning::{VusdWallet, MockLightningNetwork, MockLightningNode, NodeId};
use oracle::OracleAggregator;
use privacy::{PrivacyLayer, StealthWallet};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use tracing::{info, warn};
use vscx_core::{OracleFeed as _, 
    BitcoinAddress, MockBtcLayer, MockOracle, Satoshis, StealthAddress,
    VaultEngine, VaultId, VaultState, VusdAmount, XOnlyPubkey, current_time_secs,
};

// ─────────────────────────────────────────────────────────────────────────────
// PROTOCOL CONTEXT
// ─────────────────────────────────────────────────────────────────────────────

/// The shared state for all CLI commands.
/// In production: loaded from a config file and network.
/// In testnet: all in-process.
pub struct ProtocolContext {
    pub engine:        Arc<VaultEngine>,
    pub oracle_agg:    Arc<OracleAggregator>,
    pub privacy:       Arc<PrivacyLayer>,
    pub wallet:        Arc<VusdWallet>,
    pub lightning_net: Arc<MockLightningNetwork>,
    pub owner_pubkey:  XOnlyPubkey,
    pub owner_seed:    [u8; 32],
    nonce_counter:     RwLock<u64>,
}

impl ProtocolContext {
    /// Build a fresh testnet context with default config.
    pub fn new_testnet() -> Self {
        let btc         = MockBtcLayer::new();
        // T1: OracleAggregator is the live oracle source fed into the engine.
        let (oracle_agg, _feeds) = OracleAggregator::new_with_mock_feeds(100_000);
        let oracle_agg = Arc::new(oracle_agg);
        let engine      = Arc::new(VaultEngine::new(oracle_agg.clone(), btc));
        let privacy    = Arc::new(PrivacyLayer::new());

        let owner_seed    = [0x41u8; 32]; // deterministic test seed
        let owner_privkey = sha2_hash_tagged(&owner_seed, b"OWNER_KEY");
        let owner_pubkey  = XOnlyPubkey(sha2_hash_tagged(&owner_privkey, b"OWNER_PUBKEY"));

        let wallet = Arc::new(VusdWallet::new(owner_seed));
        let ln_net = Arc::new(MockLightningNetwork::new());
        let ln_node = Arc::new(MockLightningNode::new(wallet.node_id.clone()));
        ln_net.register_node(ln_node);

        ProtocolContext {
            engine,
            oracle_agg,
            privacy,
            wallet,
            lightning_net: ln_net,
            owner_pubkey,
            owner_seed,
            nonce_counter: RwLock::new(1),
        }
    }

    /// Build a signet context using real Bitcoin node and oracle feeds.
    ///
    /// Requires bitcoind + LND running on signet. Uses SignetBtcLayer for
    /// real P2TR vault transactions and a live OracleAggregator with HTTP feeds.
    ///
    /// owner_seed: 32-byte seed for the vault owner keypair.
    ///             Derive from a BIP39 mnemonic or hardware wallet.
    pub fn new_signet(owner_seed: [u8; 32], signing_key: [u8; 32], change_address: &str) -> Self {
        use taproot_vault::SignetBtcLayer;

        // Real Bitcoin signet layer — broadcasts actual P2TR transactions
        let btc = SignetBtcLayer::signet()
            .with_signing_key(signing_key)
            .expect("invalid signing key")
            .with_change_address(change_address);

        // Oracle aggregator with real HTTP feeds + MuSig2 Schnorr sigs (A1)
        // Uses production feeds: Kraken, Binance, Coinbase, Bitstamp, OKX
        let oracle_agg = Arc::new(build_production_oracle());
        let engine = Arc::new(VaultEngine::new(oracle_agg.clone(), btc).with_ringct());

        let privacy    = Arc::new(PrivacyLayer::new());
        let owner_privkey = sha2_hash_tagged(&owner_seed, b"OWNER_KEY");
        let owner_pubkey  = XOnlyPubkey(sha2_hash_tagged(&owner_privkey, b"OWNER_PUBKEY"));

        let wallet = Arc::new(VusdWallet::new(owner_seed));
        let ln_net = Arc::new(MockLightningNetwork::new());
        let ln_node = Arc::new(MockLightningNode::new(wallet.node_id.clone()));
        ln_net.register_node(ln_node);

        tracing::info!(
            owner_pubkey = hex_short(&owner_pubkey.0),
            change_address = %change_address,
            "ProtocolContext: signet mode — real Bitcoin node"
        );

        ProtocolContext {
            engine,
            oracle_agg,
            privacy,
            wallet,
            lightning_net: ln_net,
            owner_pubkey,
            owner_seed,
            nonce_counter: RwLock::new(1),
        }
    }

    pub fn next_nonce(&self) -> [u8; 32] {
        let mut counter = self.nonce_counter.write().unwrap();
        *counter += 1;
        let mut nonce = [0u8; 32];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    pub fn current_price_usd(&self) -> u64 {
        self.oracle_agg.get_price().map(|p| p.btc_usd_8dec / 100_000_000).unwrap_or(0)
    }
}

fn sha2_hash_tagged(data: &[u8], tag: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag);
    h.update(data);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND: open-vault
// ─────────────────────────────────────────────────────────────────────────────


/// Build a 7-node OracleAggregator using all 5 production HTTP price feeds.
/// Each node polls all 5 feeds, computes the median, and signs with its keypair.
/// The aggregator requires 5-of-7 Schnorr quorum + MuSig2 aggregate.
fn build_production_oracle() -> OracleAggregator {
    use oracle::feeds::{FeedClient, production_feeds};

    let mut agg = OracleAggregator::new(5, 100); // 5-of-7 quorum, max 1% spread
    let feed_client = FeedClient::new();

    // Each node uses a deterministic seed — in production these would be
    // separate machines with secure key storage. For single-machine testnet
    // they share the same process but have different keypairs.
    for node_id in 0u8..7 {
        let mut seed = [0u8; 32];
        seed[0] = node_id;
        seed[1] = 0xFE; // VUSD oracle node domain separator
        seed[2] = 0xED;

        let feeds = production_feeds(&feed_client);
        agg.add_node(oracle::OracleNode::new(node_id, seed, feeds));
    }

    agg
}

pub fn cmd_open_vault(ctx: &ProtocolContext, args: &[String]) -> Result<()> {
    let collateral_sats = parse_flag(args, "--collateral")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(100_000_000); // default 1 BTC

    let price_usd = ctx.current_price_usd();
    let fee_sats: u64 = (100_000_000 / price_usd) + 1000; // ~$1 in sats + buffer

    println!("\n╔═══════════════════════════════════════╗");
    println!("║         OPEN VAULT                    ║");
    println!("╚═══════════════════════════════════════╝");
    println!("  Collateral : {} sats ({:.4} BTC)", collateral_sats, collateral_sats as f64 / 1e8);
    println!("  BTC price  : ${}", price_usd);
    println!("  Collateral : ${:.2}", collateral_sats as f64 / 1e8 * price_usd as f64);
    println!("  Open fee   : {} sats (~$1.00)", fee_sats);

    let nonce    = ctx.next_nonce();
    let vault_id = ctx.engine.open_vault(
        ctx.owner_pubkey,
        Satoshis(collateral_sats),
        Satoshis(fee_sats),
        nonce,
    )?;

    println!("\n  ✅ Vault opened!");
    println!("  Vault ID   : {}", vault_id);
    println!("  State      : OPEN");
    println!("  Max mint   : ${:.2}", collateral_sats as f64 / 1e8 * price_usd as f64 * 2.0 / 3.0);
    println!();

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND: mint
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_mint(ctx: &ProtocolContext, args: &[String]) -> Result<()> {
    let vault_id_hex = parse_flag(args, "--vault")
        .ok_or_else(|| anyhow!("--vault <vault_id> required"))?;
    let amount_usd = parse_flag(args, "--amount")
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("--amount <usd> required"))?;

    let vault_id = vault_id_from_str(&vault_id_hex, ctx)?;
    let amount   = VusdAmount::from_usd_8dec(amount_usd as u128 * 100_000_000);

    println!("\n╔═══════════════════════════════════════╗");
    println!("║         MINT VUSD                     ║");
    println!("╚═══════════════════════════════════════╝");
    println!("  Vault    : {}", vault_id);
    println!("  Amount   : ${}", amount_usd);

    let stealth_addr = StealthAddress(ctx.wallet.stealth_wallet.spend_pubkey);
    ctx.engine.mint_vusd(vault_id, amount, stealth_addr.clone())?;

    // Record in wallet
    let blinding = sha2_hash_tagged(&stealth_addr.0, b"MINT_BLIND");
    ctx.wallet.record_mint_output(
        stealth_addr.clone(),
        ctx.wallet.stealth_wallet.view_pubkey,
        amount,
        blinding,
        0,
    );

    let health = ctx.engine.vault_health(vault_id)?;

    println!("\n  ✅ Minted {} VUSD", amount_usd);
    println!("  New CR    : {}", health.collateral_ratio
        .map(|cr| cr.as_percent_str())
        .unwrap_or_default());
    println!("  Liq price : ${:.2}", health.liquidation_price
        .map(|p| p as f64 / 1e8)
        .unwrap_or(0.0));
    println!();

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND: add-collateral
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_add_collateral(ctx: &ProtocolContext, args: &[String]) -> Result<()> {
    let vault_id_hex = parse_flag(args, "--vault")
        .ok_or_else(|| anyhow!("--vault required"))?;
    let sats = parse_flag(args, "--amount")
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("--amount <sats> required"))?;

    let vault_id = vault_id_from_str(&vault_id_hex, ctx)?;

    println!("\n  Adding {} sats collateral to vault {}...", sats, vault_id);
    let new_cr = ctx.engine.add_collateral(vault_id, Satoshis(sats), ctx.owner_pubkey)?;

    println!("  ✅ Collateral added. New CR: {}", new_cr);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND: health
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_health(ctx: &ProtocolContext, args: &[String]) -> Result<()> {
    let vault_id_hex = parse_flag(args, "--vault")
        .ok_or_else(|| anyhow!("--vault required"))?;
    let vault_id = vault_id_from_str(&vault_id_hex, ctx)?;
    let health   = ctx.engine.vault_health(vault_id)?;

    println!("\n{}", health);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND: repay
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_repay(ctx: &ProtocolContext, args: &[String]) -> Result<()> {
    let vault_id_hex = parse_flag(args, "--vault")
        .ok_or_else(|| anyhow!("--vault required"))?;
    let amount_usd   = parse_flag(args, "--amount")
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| anyhow!("--amount <usd> required"))?;

    let vault_id = vault_id_from_str(&vault_id_hex, ctx)?;
    let amount   = VusdAmount::from_usd_8dec(amount_usd as u128 * 100_000_000);
    let payer    = StealthAddress(ctx.wallet.stealth_wallet.spend_pubkey);

    println!("\n  Repaying ${} VUSD on vault {}...", amount_usd, vault_id);
    let (remaining, _preimage) = ctx.engine.repay_vusd(vault_id, amount, &payer)?;

    println!("  ✅ Repaid. Remaining debt: ${:.2}",
        remaining.to_usd_8dec() as f64 / 1e8);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND: close
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_close(ctx: &ProtocolContext, args: &[String]) -> Result<()> {
    let vault_id_hex = parse_flag(args, "--vault")
        .ok_or_else(|| anyhow!("--vault required"))?;
    let vault_id = vault_id_from_str(&vault_id_hex, ctx)?;

    let price = ctx.oracle_agg.get_price().expect("oracle offline");
    let fee_sats  = (100_000_000u64 / (price.btc_usd_8dec / 100_000_000)) + 1000;
    let return_addr = BitcoinAddress::new("tb1p_owner_return_testnet");

    println!("\n  Closing vault {}...", vault_id);
    let returned = ctx.engine.close_vault(vault_id, ctx.owner_pubkey, Satoshis(fee_sats), return_addr)?;

    println!("  ✅ Vault closed. BTC returned: {} sats ({:.8} BTC)",
        returned.0, returned.0 as f64 / 1e8);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND: balance
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_balance(ctx: &ProtocolContext) -> Result<()> {
    let balance = ctx.wallet.balance();
    let price   = ctx.current_price_usd();

    println!("\n╔═══════════════════════════════════════╗");
    println!("║         WALLET BALANCE                ║");
    println!("╚═══════════════════════════════════════╝");
    println!("  VUSD balance : ${:.2}", balance.to_usd_8dec() as f64 / 1e8);
    println!("  Outputs held : {}", ctx.wallet.unspent_count());
    println!("  BTC price    : ${}", price);
    println!("  Total supply : ${:.2}", ctx.engine.total_vusd_supply().to_usd_8dec() as f64 / 1e8);
    println!("  Fee reserve  : ${:.2}", ctx.engine.fee_reserve().to_usd_8dec() as f64 / 1e8);
    println!();
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND: oracle
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_oracle(ctx: &ProtocolContext) -> Result<()> {
    let price = ctx.oracle_agg.get_price().expect("oracle offline");

    println!("\n╔═══════════════════════════════════════╗");
    println!("║         ORACLE PRICE                  ║");
    println!("╚═══════════════════════════════════════╝");
    println!("  BTC/USD  : {}", price.price_display());
    println!("  Age      : {}s", current_time_secs().saturating_sub(price.timestamp));
    println!("  Oracles  : {} of 7 signed", price.oracle_ids.len());
    println!("  Fresh    : {}", price.is_fresh(current_time_secs()));
    println!();
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND: keeper
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_keeper(ctx: &ProtocolContext, args: &[String]) -> Result<()> {
    let sub = args.get(0).map(|s| s.as_str()).unwrap_or("status");
    match sub {
        "run" => {
            println!("\n  Starting keeper bot (Ctrl+C to stop)...");
            println!("  Scanning every 30 seconds...\n");
            let keeper_pk = XOnlyPubkey([0xBEu8; 32]);
            let keeper    = KeeperBot::new(0, keeper_pk);
            let mut cycles = 0;
            loop {
                keeper.run_scan_cycle(&ctx.engine, &ctx.oracle_agg);
                cycles += 1;
                let stats = keeper.snapshot_stats();
                println!(
                    "  [cycle {:>4}] vaults={} liquidated={} settled={} bonus={}sats",
                    cycles,
                    stats.last_scan_vault_count,
                    stats.liquidations_triggered,
                    stats.auctions_settled,
                    stats.total_bonus_sats,
                );
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        }
        "status" => {
            let keeper_pk = XOnlyPubkey([0xBEu8; 32]);
            let keeper    = KeeperBot::new(0, keeper_pk);
            keeper.run_scan_cycle(&ctx.engine, &ctx.oracle_agg);
            let stats = keeper.snapshot_stats();
            println!("\n  Keeper status:");
            println!("    Scans        : {}", stats.scans_completed);
            println!("    Vaults seen  : {}", stats.last_scan_vault_count);
            println!("    Liquidatable : {}", ctx.engine.liquidatable_vaults().len());
            println!("    At-risk      : {}", ctx.engine.at_risk_vaults().len());
        }
        _ => println!("  Usage: vusd keeper [run|status]"),
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND: auctions
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_auctions(ctx: &ProtocolContext) -> Result<()> {
    let now   = current_time_secs();
    let count = ctx.engine.auctions.len();

    println!("\n╔═══════════════════════════════════════╗");
    println!("║         ACTIVE AUCTIONS               ║");
    println!("╚═══════════════════════════════════════╝");
    println!("  Total auctions: {}", count);

    for entry in ctx.engine.auctions.iter() {
        let a = entry.value();
        let settled    = a.winning_bid.is_some();
        let expired    = now >= a.end_time;
        let status     = if settled { "SETTLED" } else if expired { "EXPIRED-UNSETTLED" } else { "ACTIVE" };
        let remaining  = if !expired { a.end_time.saturating_sub(now) } else { 0 };
        println!("\n  ─── Auction {} ───", a.auction_id);
        println!("    Vault       : {}", a.vault_id);
        println!("    Status      : {}", status);
        println!("    Min bid     : ${:.2}", a.min_bid_vusd.to_usd_8dec() as f64 / 1e8);
        println!("    Bids        : {}", a.bids.len());
        if !expired { println!("    Ends in     : {}s", remaining); }
    }
    println!();
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND: testnet — full chaos scenario
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_testnet(ctx: &ProtocolContext) -> Result<()> {
    println!("\n╔═══════════════════════════════════════════════════╗");
    println!("║   VUSD TESTNET CHAOS SCENARIO                     ║");
    println!("╚═══════════════════════════════════════════════════╝\n");

    let coord = KeeperCoordinator::new_testnet(100_000);

    // ── Open 5 vaults ──────────────────────────────────────────────────
    println!("[ Opening 5 vaults ]");
    let mut vault_ids = Vec::new();
    for i in 0..5u8 {
        let mut pk    = [i + 1u8; 32];
        let nonce     = [i + 100u8; 32];
        let collateral = 100_000_000u64; // 1 BTC each
        let fee_sats  = 5_000u64;
        let vid = ctx.engine.open_vault(
            XOnlyPubkey(pk), Satoshis(collateral), Satoshis(fee_sats), nonce,
        )?;
        vault_ids.push(vid);
        println!("  Vault {}: {}", i, vid);
    }

    // ── Mint VUSD on all vaults ─────────────────────────────────────────
    println!("\n[ Minting $60,000 VUSD on each vault ]");
    for (i, &vault_id) in vault_ids.iter().enumerate() {
        let addr = StealthAddress([i as u8 + 10u8; 32]);
        ctx.engine.mint_vusd(
            vault_id,
            VusdAmount::from_usd_8dec(60_000_00000000),
            addr,
        )?;
        println!("  Vault {}: minted $60k", i);
    }

    println!("\n  Total VUSD supply: ${:.0}",
        ctx.engine.total_vusd_supply().to_usd_8dec() as f64 / 1e8);

    // ── Process oracle tick at $100k ────────────────────────────────────
    println!("\n[ Oracle tick @ $100,000 — all vaults healthy ]");
    let price = ctx.oracle_agg.get_price().expect("oracle offline");
    let result = ctx.engine.process_price_update(price);
    println!("  Vaults at-risk    : {}", result.vaults_at_risk);
    println!("  Vaults liquidatable: {}", result.vaults_liquidatable);

    // ── Crash price to $72k → AT_RISK ──────────────────────────────────
    println!("\n[ PRICE CRASH: $100k → $72k → CR 120% → AT_RISK ]");
    ctx.oracle_agg.set_all_feed_prices(72_000);
    let price = ctx.oracle_agg.get_price().expect("oracle offline");
    let result = ctx.engine.process_price_update(price);
    println!("  Vaults at-risk    : {}", result.vaults_at_risk);

    // ── Cure vault 0 by adding collateral ──────────────────────────────
    println!("\n[ Vault 0: CURED by adding 0.5 BTC collateral ]");
    let mut pk0 = [1u8; 32];
    ctx.engine.add_collateral(vault_ids[0], Satoshis(50_000_000), XOnlyPubkey(pk0))?;
    let h0 = ctx.engine.vault_health(vault_ids[0])?;
    println!("  Vault 0 new CR: {}", h0.collateral_ratio.map(|c|c.as_percent_str()).unwrap_or_default());

    // ── Crash to $64k → liquidation zone ──────────────────────────────
    println!("\n[ PRICE CRASH: $72k → $64k → CR ~106% → LIQUIDATABLE ]");
    ctx.oracle_agg.set_all_feed_prices(64_000);
    let (oracle_agg_64, _) = OracleAggregator::new_with_mock_feeds(64_000);
    let price = ctx.oracle_agg.get_price().expect("oracle offline");
    let result = ctx.engine.process_price_update(price);
    println!("  Vaults liquidatable: {}", result.vaults_liquidatable);
    println!("  (Vault 0 was cured so it may not be in this set)");

    // ── Keeper network triggers liquidations ───────────────────────────
    println!("\n[ KEEPER NETWORK: scanning and triggering liquidations ]");
    coord.run_all(&ctx.engine, &oracle_agg_64);
    println!("  Total triggered: {}", coord.total_triggered());

    // ── Simulate bids ──────────────────────────────────────────────────
    println!("\n[ Submitting winning bids on all active auctions ]");
    let bidder = XOnlyPubkey([0xAAu8; 32]);
    let mut bid_count = 0;
    for entry in ctx.engine.auctions.iter() {
        let a = entry.value();
        if a.winning_bid.is_none() {
            let bid = VusdAmount(a.min_bid_vusd.0 + VusdAmount::ONE.0);
            if let Ok(_) = ctx.engine.submit_bid(a.auction_id, bidder, bid) {
                bid_count += 1;
            }
        }
    }
    println!("  Bids placed: {}", bid_count);

    // ── Force-settle all auctions ──────────────────────────────────────
    println!("\n[ Force-settling all expired auctions ]");
    for keeper in &coord.keepers {
        keeper.force_settle_all(&ctx.engine);
    }
    println!("  Keeper 0 settled: {}", coord.keepers[0].snapshot_stats().auctions_settled);
    println!("  Total BTC bonus:  {} sats", coord.total_bonus_sats());

    // ── Final state summary ────────────────────────────────────────────
    println!("\n╔═══════════════════════════════════════════════════╗");
    println!("║   FINAL STATE                                     ║");
    println!("╚═══════════════════════════════════════════════════╝");
    for (i, &vid) in vault_ids.iter().enumerate() {
        let state = ctx.engine.vaults.get(&vid).map(|v| v.state).unwrap_or(VaultState::Closed);
        println!("  Vault {}: {:?}", i, state);
    }
    println!("  Total supply : ${:.0}", ctx.engine.total_vusd_supply().to_usd_8dec() as f64 / 1e8);
    println!("  Fee reserve  : ${:.2}", ctx.engine.fee_reserve().to_usd_8dec() as f64 / 1e8);
    println!();

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMAND: demo — full Phase I→V end-to-end walkthrough
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_demo(ctx: &ProtocolContext) -> Result<()> {
    use lightning::{
        MockLightningNetwork, MockLightningNode, NodeId,
        VusdTransferService, VusdWallet,
    };
    use privacy::StealthWallet;
    use std::sync::Arc;

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║   VUSD PROTOCOL — FULL END-TO-END DEMO                       ║");
    println!("║   BTC-backed private stablecoin on Lightning                  ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    // ── Phase I: Open vault and mint ──────────────────────────────────
    println!("━━━ PHASE I: VSCx Core ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("BTC price: $100,000. Opening vault with 1 BTC collateral.\n");

    let vault_id = ctx.engine.open_vault(
        ctx.owner_pubkey,
        Satoshis(100_000_000),
        Satoshis(5_000),
        ctx.next_nonce(),
    )?;
    println!("  ✅ Vault opened: {}", vault_id);

    let mint_amount = VusdAmount::from_usd_8dec(50_000_00000000); // $50k
    let stealth     = StealthAddress(ctx.wallet.stealth_wallet.spend_pubkey);
    ctx.engine.mint_vusd(vault_id, mint_amount, stealth.clone())?;
    ctx.wallet.record_mint_output(stealth.clone(), ctx.wallet.stealth_wallet.view_pubkey, mint_amount, [7u8; 32], 0);
    println!("  ✅ Minted $50,000 VUSD (CR: 200%)");

    let health = ctx.engine.vault_health(vault_id)?;
    println!("  ✅ Vault health: CR={}, liq_price=${:.0}",
        health.collateral_ratio.map(|c|c.as_percent_str()).unwrap_or_default(),
        health.liquidation_price.unwrap_or(0) as f64 / 1e8,
    );

    // ── Phase II: Oracle update ───────────────────────────────────────
    println!("\n━━━ PHASE II: Oracle Network ━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let agg_price = ctx.oracle_agg.collect_and_aggregate()
        .expect("Oracle aggregation failed");
    println!("  ✅ 7-node oracle aggregated: {} (5-of-7 threshold Schnorr)", agg_price.price_display());
    println!("  ✅ {} oracle node IDs signed", agg_price.oracle_ids.len());

    // ── Phase III: Taproot vault ──────────────────────────────────────
    println!("\n━━━ PHASE III: Taproot Vault Layer ━━━━━━━━━━━━━━━━━━━━━");
    use taproot_vault::{VaultMast, VaultTaprootClient};
    let tap_client = VaultTaprootClient::with_arc_btc(ctx.engine.btc.clone());
    let (_, mast)  = tap_client.open_vault(ctx.owner_pubkey, Satoshis(100_000_000), 800_000, [0u8; 32])?;
    println!("  ✅ Taproot MAST constructed");
    println!("    Leaf A hash : 0x{}", hex_short(&mast.leaf_repay.leaf_hash));
    println!("    Leaf B hash : 0x{}", hex_short(&mast.leaf_liquidation.leaf_hash));
    println!("    Leaf C hash : 0x{}", hex_short(&mast.leaf_emergency.leaf_hash));
    println!("    Merkle root : 0x{}", hex_short(&mast.merkle_root));
    println!("    P2TR addr   : {}", &mast.p2tr_address()[..32]);
    println!("  ✅ All 3 spend paths: Repay / Liquidation / Emergency Timelock");

    // ── Phase IV: Privacy layer ───────────────────────────────────────
    println!("\n━━━ PHASE IV: Privacy Rails (RingCT) ━━━━━━━━━━━━━━━━━━━");

    // Populate output set with decoys
    let decoy_wallet = StealthWallet::generate(&[0xABu8; 32]);
    for i in 0..15u8 {
        ctx.privacy.create_mint_output(
            VusdAmount::from_usd_8dec(1_000_00000000),
            &decoy_wallet,
        ).ok();
    }

    let recipient_wallet = StealthWallet::generate(&[0xCDu8; 32]);
    let output = ctx.privacy.create_mint_output(mint_amount, &recipient_wallet)?;
    println!("  ✅ Private VUSD output created");
    println!("    Stealth addr  : {}", output.stealth_address);
    println!("    Commitment    : 0x{}", hex_short(&output.amount_commitment.commitment));
    println!("    Range proof   : {} bytes", output.range_proof.proof_bytes.len());
    println!("  ✅ Recipient scanning for output...");

    let found = recipient_wallet.scan_output(&output.ephemeral_pubkey, &output.stealth_address);
    println!("  ✅ Output found: {} (amount hidden from network)", found.is_some());
    println!("  ✅ Ring size: {} (1 real + 10 decoys)", privacy::RING_SIZE);

    // ── Phase V: Lightning transfer ───────────────────────────────────
    println!("\n━━━ PHASE V: Lightning Transfer ━━━━━━━━━━━━━━━━━━━━━━━━");
    let network   = Arc::new(MockLightningNetwork::new());
    let privacy   = Arc::new(PrivacyLayer::new());

    let alice_wallet = Arc::new(VusdWallet::new([0x01u8; 32]));
    let bob_wallet   = Arc::new(VusdWallet::new([0x02u8; 32]));

    let alice_node = Arc::new(MockLightningNode::new(alice_wallet.node_id.clone()));
    let bob_node   = Arc::new(MockLightningNode::new(bob_wallet.node_id.clone()));

    network.register_node(alice_node.clone());
    network.register_node(bob_node.clone());

    // Fund Alice with $20,000
    let send_amount = VusdAmount::from_usd_8dec(20_000_00000000);
    alice_wallet.record_mint_output(
        StealthAddress([0x11u8; 32]),
        [0x12u8; 32],
        VusdAmount::from_usd_8dec(30_000_00000000), // $30k balance
        [0x13u8; 32],
        0,
    );

    println!("  Alice balance: ${:.0}", alice_wallet.balance().to_usd_8dec() as f64 / 1e8);

    let service = lightning::VusdTransferService::new(
        alice_wallet.clone(),
        alice_node.clone(),
        network.clone(),
        privacy.clone(),
    );

    let bob_keys = StealthWallet::generate(&[0x02u8; 32]);
    tokio::runtime::Runtime::new().unwrap().block_on(service.send(&bob_node.node_id, &bob_keys, send_amount))?;
    println!("  ✅ Alice → Bob: $20,000 VUSD over Lightning");
    println!("  ✅ Bob inbox: {} pending messages", bob_node.inbox_count());

    let msgs = bob_node.drain_inbox();
    let found = bob_wallet.scan_transfer(&msgs[0]);
    println!("  ✅ Bob scanned transfer, found {} output(s)", found);
    println!("  ✅ Transaction: ring signature hidden sender, stealth addr hidden recipient");

    // ── Close vault ───────────────────────────────────────────────────
    println!("\n━━━ VAULT CLOSE (Full lifecycle) ━━━━━━━━━━━━━━━━━━━━━━━");

    let repay_addr = StealthAddress(ctx.wallet.stealth_wallet.spend_pubkey);
    let (remaining, _preimage) = ctx.engine.repay_vusd(vault_id, mint_amount, &repay_addr)?;
    println!("  ✅ VUSD debt repaid. Remaining: ${:.0}", remaining.to_usd_8dec() as f64 / 1e8);

    let returned = ctx.engine.close_vault(
        vault_id,
        ctx.owner_pubkey,
        Satoshis(5_000),
        BitcoinAddress::new("tb1p_demo_return"),
    )?;
    println!("  ✅ Vault closed. BTC returned: {} sats ({:.8} BTC)",
        returned.0, returned.0 as f64 / 1e8);

    // ── Summary ───────────────────────────────────────────────────────
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║   DEMO COMPLETE                                               ║");
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║  Phase I  ✅  VSCx state machine: vault lifecycle working     ║");
    println!("║  Phase II ✅  Oracle: 5-of-7 threshold Schnorr aggregation    ║");
    println!("║  Phase III✅  Taproot: MAST with 3 spend paths constructed    ║");
    println!("║  Phase IV ✅  Privacy: stealth addrs + ring sigs + RingCT     ║");
    println!("║  Phase V  ✅  Lightning: private VUSD transfer Alice→Bob      ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// HELP
// ─────────────────────────────────────────────────────────────────────────────

pub fn cmd_help() -> Result<()> {
    println!(r#"
VUSD Protocol — CLI Vault Operator

USAGE:
  vusd <command> [options]

COMMANDS:
  open-vault  --collateral <sats>          Open a new vault
  mint        --vault <id> --amount <usd>  Mint VUSD against your vault
  add-collateral --vault <id> --amount <sats>  Add BTC collateral
  health      --vault <id>                 Show vault health
  repay       --vault <id> --amount <usd>  Repay VUSD debt
  close       --vault <id>                 Close vault (must be fully repaid)
  balance                                  Show VUSD wallet balance
  oracle                                   Show current oracle price
  keeper      [run|status]                 Keeper bot operations
  auctions                                 List active liquidation auctions
  testnet                                  Run chaos test scenario
  demo                                     Run full Phase I-V end-to-end demo
  help                                     Show this help

EXAMPLES:
  vusd demo
  vusd open-vault --collateral 100000000
  vusd oracle
  vusd testnet
"#);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

fn parse_flag<'a>(args: &'a [String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
}

fn vault_id_from_str(s: &str, ctx: &ProtocolContext) -> Result<VaultId> {
    // Find first vault that starts with this prefix
    for entry in ctx.engine.vaults.iter() {
        let id_hex = entry.key().to_hex();
        if id_hex.starts_with(s) || s == "first" || s == "0" {
            return Ok(*entry.key());
        }
    }
    Err(anyhow!("Vault not found: {}. Use 'first' for the most recently opened vault.", s))
}

fn hex_short(bytes: &[u8]) -> String {
    bytes[..8].iter().map(|b| format!("{:02x}", b)).collect::<String>() + "..."
}
