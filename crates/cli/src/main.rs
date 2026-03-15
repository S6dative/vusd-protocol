// crates/cli/src/main.rs
//
// VUSD Protocol — Command-Line Vault Operator Tool
//
// Usage:
//   vusd open-vault  --collateral <sats> [--nonce <hex>]
//   vusd mint        --vault <vault_id> --amount <usd>
//   vusd add-collateral --vault <vault_id> --amount <sats>
//   vusd health      --vault <vault_id>
//   vusd repay       --vault <vault_id> --amount <usd>
//   vusd close       --vault <vault_id>
//   vusd balance
//   vusd oracle      (show current oracle price)
//   vusd keeper run  (run keeper bot in foreground)
//   vusd keeper status
//   vusd auctions    (list active auctions)
//   vusd testnet     (run a full simulation scenario)
//   vusd demo        (run the full Phase I→V demo)

use anyhow::Result;
use oracle::OracleAggregator;
use privacy::{PrivacyLayer, StealthWallet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{info, warn};
use vscx_core::{
    BitcoinAddress, MockBtcLayer, MockOracle, Satoshis, StealthAddress,
    VaultEngine, VaultId, VusdAmount, XOnlyPubkey, current_time_secs,
};

mod commands;
use commands::*;

fn main() -> Result<()> {
    // Set up logging
    tracing_subscriber::fmt()
        .with_env_filter("vusd=debug,vscx_core=debug,oracle=info,keeper=info")
        .with_target(false)
        .init();

    // Parse args (simple manual parser — no clap dependency in workspace yet)
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    // ── Mode: --signet or default testnet ────────────────────────────────────
    //
    // Signet mode: requires environment variables:
    //   VUSD_OWNER_SEED_HEX    — 64-char hex of 32-byte owner seed
    //   VUSD_SIGNING_KEY_HEX   — 64-char hex of 32-byte signing key
    //   VUSD_CHANGE_ADDRESS    — bech32m change address on signet
    //
    // Example:
    //   export VUSD_OWNER_SEED_HEX=0102030405...
    //   export VUSD_SIGNING_KEY_HEX=0a0b0c0d0e...
    //   export VUSD_CHANGE_ADDRESS=tb1p...
    //   vusd --signet open-vault --collateral 0.1

    let signet_mode = args.iter().any(|a| a == "--signet");
    let args_filtered: Vec<String> = args.iter()
        .filter(|a| *a != "--signet")
        .cloned().collect();
    let cmd = args_filtered.get(1).map(|s| s.as_str()).unwrap_or("help");

    let ctx = if signet_mode {
        let seed_hex  = std::env::var("VUSD_OWNER_SEED_HEX")
            .expect("VUSD_OWNER_SEED_HEX not set — export your 64-char hex seed");
        let sign_hex  = std::env::var("VUSD_SIGNING_KEY_HEX")
            .expect("VUSD_SIGNING_KEY_HEX not set — export your signing key");
        let change    = std::env::var("VUSD_CHANGE_ADDRESS")
            .expect("VUSD_CHANGE_ADDRESS not set — export your signet change address");

        let owner_seed  = hex_to_32(&seed_hex).expect("invalid VUSD_OWNER_SEED_HEX");
        let signing_key = hex_to_32(&sign_hex).expect("invalid VUSD_SIGNING_KEY_HEX");

        println!("⚡ VUSD — signet mode");
        ProtocolContext::new_signet(owner_seed, signing_key, &change)
    } else {
        ProtocolContext::new_testnet()
    };

    match cmd {
        "open-vault"     => cmd_open_vault(&ctx, &args_filtered[2..]),
        "mint"           => cmd_mint(&ctx, &args_filtered[2..]),
        "add-collateral" => cmd_add_collateral(&ctx, &args_filtered[2..]),
        "health"         => cmd_health(&ctx, &args_filtered[2..]),
        "repay"          => cmd_repay(&ctx, &args_filtered[2..]),
        "close"          => cmd_close(&ctx, &args_filtered[2..]),
        "balance"        => cmd_balance(&ctx),
        "oracle"         => cmd_oracle(&ctx),
        "keeper"         => cmd_keeper(&ctx, &args_filtered[2..]),
        "auctions"       => cmd_auctions(&ctx),
        "testnet"        => cmd_testnet(&ctx),
        "demo"           => cmd_demo(&ctx),
        _                => cmd_help(),
    }
}

fn hex_to_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() < 64 { return None; }
    let bytes: Vec<u8> = (0..32)
        .filter_map(|i| u8::from_str_radix(&s[i*2..i*2+2], 16).ok())
        .collect();
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(out)
    } else { None }
}
