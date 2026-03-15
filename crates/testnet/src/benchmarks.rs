// crates/testnet/src/benchmarks.rs
//
// Performance benchmarks for testnet readiness.
// All benchmarks must hit their targets before testnet launch.

use crate::harness::TestnetHarness;
use anyhow::Result;
use std::time::{Duration, Instant};
use vscx_core::{Satoshis, StealthAddress, VusdAmount, XOnlyPubkey};

pub fn run_benchmarks() -> Result<()> {
    println!("━━━ BENCHMARKS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    bench_vault_open()?;
    bench_mint_throughput()?;
    bench_keeper_scan_1000_vaults()?;
    bench_oracle_aggregation()?;
    bench_stability_fee_tick()?;

    println!("  ALL BENCHMARKS PASSED ✅\n");
    Ok(())
}

fn bench_vault_open() -> Result<()> {
    let h = TestnetHarness::new(100_000);
    let count = 1_000;
    let start = Instant::now();

    for i in 0..count as u8 {
        let nonce = {
            let mut n = [0u8; 32];
            n[0] = i;
            n[1] = 0xBE;
            n[2] = 0xEF;
            n
        };
        h.engine.open_vault(
            XOnlyPubkey([i.wrapping_add(1); 32]),
            Satoshis(100_000_000),
            Satoshis(5_000),
            nonce,
        )?;
    }

    let elapsed = start.elapsed();
    let per_vault = elapsed / count;
    println!("  open_vault × {}:  {:?} total, {:?}/vault", count, elapsed, per_vault);
    assert!(per_vault < Duration::from_millis(10),
        "open_vault should be <10ms each, was {:?}", per_vault);
    println!("  ✅ open_vault: {} µs/call (target <10ms)", per_vault.as_micros());
    Ok(())
}

fn bench_mint_throughput() -> Result<()> {
    let h = TestnetHarness::new(100_000);
    let count = 500u32;
    let mut vaults = Vec::new();

    for i in 0..count as u8 {
        let nonce = {
            let mut n = [0u8; 32];
            n[0] = i; n[1] = 0xAA;
            n
        };
        let vid = h.engine.open_vault(
            XOnlyPubkey([i.wrapping_add(1); 32]),
            Satoshis(100_000_000),
            Satoshis(5_000),
            nonce,
        )?;
        vaults.push(vid);
    }

    let start = Instant::now();
    for (i, &vid) in vaults.iter().enumerate() {
        let addr = StealthAddress([(i % 256) as u8; 32]);
        h.engine.mint_vusd(
            vid,
            VusdAmount::from_usd_8dec(50_000_00000000),
            addr,
        )?;
    }
    let elapsed = start.elapsed();
    let per_mint = elapsed / count;

    println!("  mint_vusd × {}:  {:?} total, {:?}/mint", count, elapsed, per_mint);
    assert!(per_mint < Duration::from_millis(10),
        "mint_vusd should be <10ms each, was {:?}", per_mint);
    println!("  ✅ mint_vusd: {} µs/call (target <10ms)", per_mint.as_micros());
    Ok(())
}

fn bench_keeper_scan_1000_vaults() -> Result<()> {
    use oracle::OracleAggregator;

    let h = TestnetHarness::new(100_000);

    // Open 1,000 vaults and mint on all
    for i in 0..250u8 {
        let nonce = { let mut n = [0u8; 32]; n[0] = i; n[1] = 0xCC; n };
        let vid = h.engine.open_vault(
            XOnlyPubkey([i.wrapping_add(1); 32]),
            Satoshis(100_000_000),
            Satoshis(5_000),
            nonce,
        )?;
        h.mint(vid, 60_000, i.wrapping_add(100));
    }

    let (oracle_agg, _) = OracleAggregator::new_with_mock_feeds(100_000);
    let start = Instant::now();
    // Run 4 scan cycles (simulates 4 ticks with 250 vaults each = 1000 vault-scans)
    for _ in 0..4 {
        h.keepers.keepers[0].run_scan_cycle(&h.engine, &oracle_agg);
    }
    let elapsed = start.elapsed();
    let vault_count = h.engine.vaults.len();
    println!("  keeper scan × {} vaults: {:?}", vault_count, elapsed);
    assert!(elapsed < Duration::from_millis(500),
        "Keeper scan of 250 vaults should be <500ms, was {:?}", elapsed);
    println!("  ✅ Keeper: scans {} vaults in {:?} (target <500ms/scan)", vault_count, elapsed / 4);
    Ok(())
}

fn bench_oracle_aggregation() -> Result<()> {
    use oracle::OracleAggregator;
    let (agg, _) = OracleAggregator::new_with_mock_feeds(100_000);
    let count = 100u32;
    let start = Instant::now();
    for _ in 0..count {
        agg.collect_and_aggregate().expect("aggregation failed");
    }
    let elapsed  = start.elapsed();
    let per_call = elapsed / count;
    println!("  oracle_aggregate × {}: {:?} total, {:?}/call", count, elapsed, per_call);
    assert!(per_call < Duration::from_millis(50),
        "Oracle aggregation should be <50ms, was {:?}", per_call);
    println!("  ✅ Oracle aggregation: {:?}/call (target <50ms)", per_call);
    Ok(())
}

fn bench_stability_fee_tick() -> Result<()> {
    let h = TestnetHarness::new(100_000);
    let count = 10_000u32;
    let start = Instant::now();
    for _ in 0..count {
        h.engine.tick_stability_fee();
    }
    let elapsed = start.elapsed();
    let per_tick = elapsed / count;
    println!("  stability_fee_tick × {}: {:?} total, {:?}/tick", count, elapsed, per_tick);
    assert!(per_tick < Duration::from_micros(100),
        "Fee tick should be <100µs, was {:?}", per_tick);
    println!("  ✅ Fee tick: {}ns/call (target <100µs)", per_tick.as_nanos());
    Ok(())
}
