// crates/testnet/src/main.rs
//
// VUSD Testnet Harness
//
// Runs a complete testnet simulation covering all Phase VI requirements:
//   ✓ All vaults lifecycle (open → mint → repay → close)
//   ✓ Oracle network with real aggregation
//   ✓ Liquidation auctions with keeper bots
//   ✓ Bad debt scenarios
//   ✓ Chaos tests (stale oracle, flash crash, no-bid auction)
//   ✓ Privacy layer (stealth addrs, ring sigs, RingCT)
//   ✓ Lightning transfers
//   ✓ Performance benchmarks
//   ✓ Testnet launch checklist verification

use anyhow::Result;
use tracing_subscriber::EnvFilter;

mod harness;
mod scenarios;
mod benchmarks;
mod checklist;

use harness::TestnetHarness;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new("info"))
        .with_target(false)
        .with_thread_ids(false)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let scenario = args.get(1).map(|s| s.as_str()).unwrap_or("all");

    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║   VUSD PROTOCOL — TESTNET HARNESS v0.1                          ║");
    println!("║   Bitcoin-backed private stablecoin on Lightning                 ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    match scenario {
        "all"        => run_all()?,
        "happy"      => scenarios::run_happy_path()?,
        "liquidation"=> scenarios::run_liquidation_scenario()?,
        "chaos"      => scenarios::run_chaos_tests()?,
        "privacy"    => scenarios::run_privacy_scenario()?,
        "lightning"  => scenarios::run_lightning_scenario()?,
        "bench"      => benchmarks::run_benchmarks()?,
        "checklist"  => checklist::run_checklist()?,
        _            => {
            eprintln!("Unknown scenario. Use: all | happy | liquidation | chaos | privacy | lightning | bench | checklist");
        }
    }

    Ok(())
}

fn run_all() -> Result<()> {
    println!("Running ALL testnet scenarios...\n");
    scenarios::run_happy_path()?;
    scenarios::run_liquidation_scenario()?;
    scenarios::run_chaos_tests()?;
    scenarios::run_privacy_scenario()?;
    scenarios::run_lightning_scenario()?;
    benchmarks::run_benchmarks()?;
    checklist::run_checklist()?;
    println!("\n✅ ALL TESTNET SCENARIOS PASSED\n");
    Ok(())
}
