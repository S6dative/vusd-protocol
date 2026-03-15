// crates/thunder-node/src/main.rs  — G12: real tokio daemon
use thunder_node::{
    ThunderNode, ThreatMatrix, ThunderFeeBreakdown, ThreatSeverity,
    config::{ThunderConfig, config_file},
};
use lightning::{LndConfig, AnonTransport, TorConfig, PrivateChannelConfig,
                 KeyRotationConfig, RelayNodeConfig, JitterConfig, NodeId};
use vscx_core::VusdAmount;
use sha2::{Digest, Sha256};
use rand::RngCore;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .compact()
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("thunder-node {}", VERSION);
        return;
    }

    let cmd     = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let subargs = &args[2..];

    match cmd {
        "setup"   => cmd_setup(subargs),
        "threats" => cmd_threats(),
        "fees"    => cmd_fees(subargs),
        "status"  => cmd_status(),
        "start"   => cmd_start(),
        "rotate"  => cmd_rotate(),
        "version" => println!("thunder-node {}", VERSION),
        _         => print_help(),
    }
}

// ── G12: real tokio runtime ──────────────────────────────────────────────────

fn cmd_start() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    rt.block_on(async_start());
}

async fn async_start() {
    println!("\n  ⚡ Thunder Node v{} — Starting", VERSION);
    println!("  ═══════════════════════════════════════════════════════════");

    let cfg = match ThunderConfig::load() {
        Ok(c)  => c,
        Err(e) => { eprintln!("  ✗ Config: {}\n  Run `thunder setup`", e); std::process::exit(1); }
    };

    if cfg.fees.operator_spend_pubkey_hex.is_empty() {
        eprintln!("  ✗ Operator wallet keys not configured. Run: thunder setup --gen-wallet");
        std::process::exit(1);
    }

    println!("  Node:  {}  |  Fee: {}% op + {}x LN",
        cfg.node_name,
        cfg.fees.operator_fee_bps as f64 / 100.0,
        cfg.fees.fee_multiplier);

    // Build AnonTransport
    let tor_cfg = TorConfig {
        socks5_proxy:   cfg.tor.socks5_proxy.clone(),
        control_port:   cfg.tor.control_port,
        onion_address:  cfg.tor.onion_address.clone(),
        clearnet_reject: true,
    };
    let relay_nodes: Vec<RelayNodeConfig> = cfg.relays.iter().map(|r| RelayNodeConfig {
        pubkey_hex:       r.pubkey_hex.clone(),
        onion_address:    r.onion_address.clone(),
        channel_id:       r.channel_id,
        max_forward_msat: r.max_forward_msat,
        is_active:        true,
    }).collect();

    let anon = AnonTransport::new(
        tor_cfg,
        PrivateChannelConfig { private_only: true, min_channel_sats: 100_000, target_channel_count: 5, preferred_peers: vec![] },
        KeyRotationConfig { enabled: cfg.rotation.enabled, interval: std::time::Duration::from_secs(cfg.rotation.interval_days as u64 * 86400), min_drain_balance_sats: 10_000, drain_timeout: std::time::Duration::from_secs(3600) },
        NodeId([0u8; 32]),
        relay_nodes,
        JitterConfig { min_ms: 100, max_ms: 2_000 },
        2,
    );

    let lnd_cfg = LndConfig {
        rest_url:      cfg.lnd.endpoint.clone(),
        macaroon_hex:  cfg.lnd.macaroon_hex.clone(),
        tls_cert_pem:  None,
        timeout:       std::time::Duration::from_secs(cfg.lnd.timeout_secs),
    };

    println!("  Connecting to LND at {}...", cfg.lnd.endpoint);

    let node = match ThunderNode::from_config(&cfg, anon, lnd_cfg, ThreatMatrix::full()).await {
        Ok(n)  => n,
        Err(e) => { eprintln!("  ✗ Failed: {}", e); std::process::exit(1); }
    };

    println!("  LND connected ✓");
    println!("  Running pre-flight checks...");

    if let Err(e) = node.preflight().await {
        eprintln!("\n  ✗ Pre-flight FAILED: {}\n  Resolve and restart.", e);
        std::process::exit(1);
    }

    println!("  Pre-flight: all checks passed ✓");
    println!();
    println!("  ┌───────────────────────────────────────────────────────┐");
    println!("  │  ⚡ Thunder Node is live — accepting relay traffic     │");
    println!("  │  Ctrl+C to stop.                                      │");
    println!("  └───────────────────────────────────────────────────────┘");
    println!();

    // Wrap in Arc so relay loop + stats heartbeat can both hold a reference
    let node_arc   = std::sync::Arc::new(node);
    let node_stats = std::sync::Arc::clone(&node_arc);
    let node_relay = std::sync::Arc::clone(&node_arc);

    // ── Ctrl+C shutdown channel ──────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = shutdown_tx.send(());
    });

    // ── Stats heartbeat (60s) ────────────────────────────────────────────────
    let stats_h = tokio::spawn(async move {
        let mut iv = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            iv.tick().await;
            let s = node_stats.stats().await;
            tracing::info!(
                transfers = s.transfers_relayed,
                uptime    = s.uptime_secs,
                fees_earned = s.total_operator_fees.0,
                "heartbeat"
            );
        }
    });

    // ── Inbound relay dispatch loop with auto-reconnect ────────────────────
    // If LND disconnects, the relay loop exits. This outer task restarts it
    // automatically with exponential backoff (WARN-3 fix).
    let relay_h = tokio::spawn(async move {
        let mut backoff_secs = 5u64;
        loop {
            match node_relay.clone().start_relay_loop().await {
                Ok(()) => {
                    tracing::warn!("Relay loop exited cleanly — restarting in {}s", backoff_secs);
                }
                Err(e) => {
                    tracing::error!(err = %e, "Relay loop error — restarting in {}s", backoff_secs);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
            backoff_secs = (backoff_secs * 2).min(300); // cap at 5 minutes
        }
    });

    // Block until Ctrl+C
    let _ = shutdown_rx.await;
    stats_h.abort();
    relay_h.abort();

    let stats = node_arc.stats().await;
    let d = 1_000_000_000_000_000_000u128;
    println!("\n  Session ended: {} transfers | {:.4} VUSD earned\n",
        stats.transfers_relayed,
        stats.total_operator_fees.0 as f64 / d as f64);
}

// ── STATUS ───────────────────────────────────────────────────────────────────

fn cmd_status() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async_status());
}

async fn async_status() {
    println!("\n  ⚡ Thunder Node — Status");
    match ThunderConfig::load() {
        Err(e) => eprintln!("  ⚠  {}\n  Run: thunder setup", e),
        Ok(cfg) => {
            println!("  Config:   {}", config_file().display());
            println!("  Fees:     {}% op  {}x LN  |  Relays: {}  |  Rotation: {} days",
                cfg.fees.operator_fee_bps as f64 / 100.0,
                cfg.fees.fee_multiplier,
                cfg.relays.len(),
                cfg.rotation.interval_days);
            println!();

            let chk = |ok: bool, label: &str| {
                println!("    {}  {}", if ok { "✅" } else { "❌" }, label);
            };
            let tcp_ok = |addr: &str| {
                std::net::TcpStream::connect_timeout(
                    &addr.parse().unwrap_or("127.0.0.1:1".parse().unwrap()),
                    std::time::Duration::from_secs(2)).is_ok()
            };

            chk(tcp_ok(&cfg.tor.socks5_proxy),
                &format!("Tor SOCKS5 ({})", cfg.tor.socks5_proxy));
            let lnd_addr = cfg.lnd.endpoint.replace("https://","").replace("http://","");
            chk(tcp_ok(&lnd_addr), &format!("LND REST ({})", cfg.lnd.endpoint));
            chk(!cfg.fees.operator_spend_pubkey_hex.is_empty(), "Operator wallet keys");
            chk(cfg.relays.len() >= 2, &format!("Relay nodes (have {}, need 2)", cfg.relays.len()));
            chk(!cfg.tor.onion_address.is_empty(), "Onion address configured");
        }
    }
    println!();
}

// ── SETUP ────────────────────────────────────────────────────────────────────

fn cmd_setup(args: &[String]) {
    let gen_wallet = args.iter().any(|a| a == "--gen-wallet" || a == "--generate-wallet");
    println!("\n  ⚡ Thunder Node — Setup");

    let cfg_path = config_file();
    if cfg_path.exists() {
        println!("  Config exists: {}", cfg_path.display());
    } else {
        let toml = ThunderConfig::generate_default_toml("");
        if let Some(p) = cfg_path.parent() { std::fs::create_dir_all(p).ok(); }
        std::fs::write(&cfg_path, &toml).expect("write config");
        println!("  ✓ Config created: {}", cfg_path.display());
    }

    println!();
    println!("  TORRC additions:");
    println!("    HiddenServiceDir /var/lib/tor/vultd-lnd/");
    println!("    HiddenServicePort 9735 127.0.0.1:9735");
    println!("    SOCKSPort 9050  |  NumEntryGuards 4");
    println!();
    println!("  LND.CONF additions:");
    println!("    [tor] tor.active=true  tor.v3=true  tor.socks=127.0.0.1:9050");
    println!("    [Application Options] nolisten=true  externalip=<onion>.onion");
    println!();

    if gen_wallet { generate_wallet_keys(); }
    else { println!("  Run: thunder setup --gen-wallet  to generate operator wallet keys.\n"); }
}

fn generate_wallet_keys() {
    let mut s = [0u8; 32]; let mut v = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut s);
    rand::rngs::OsRng.fill_bytes(&mut v);

    let sp: [u8; 32] = Sha256::new().chain_update(b"VUSD_SPEND_PUB").chain_update(&s).finalize().into();
    let vp: [u8; 32] = Sha256::new().chain_update(b"VUSD_VIEW_PUB").chain_update(&v).finalize().into();

    let hex = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
    println!("  SPEND PRIVATE (keep OFFLINE): {}", hex(&s));
    println!("  SPEND PUBLIC  (→ config.toml): {}", hex(&sp));
    println!("  VIEW  PRIVATE (keep OFFLINE): {}", hex(&v));
    println!("  VIEW  PUBLIC  (→ config.toml): {}", hex(&vp));
    println!();
    println!("  In config.toml [fees]:");
    println!("    operator_spend_pubkey_hex = \"{}\"", hex(&sp));
    println!("    operator_view_pubkey_hex  = \"{}\"", hex(&vp));
    println!();
}

// ── THREATS ──────────────────────────────────────────────────────────────────

fn cmd_threats() {
    let matrix = ThreatMatrix::full();
    let (c, h, m, l) = matrix.severity_counts();
    println!("\n  ⚡ Threat Matrix — {} threats: {} crit {} high {} med {} low\n",
        matrix.mitigations.len(), c, h, m, l);
    for sev in [ThreatSeverity::Critical, ThreatSeverity::High, ThreatSeverity::Medium, ThreatSeverity::Low] {
        for t in matrix.mitigations.iter().filter(|t| t.severity == sev) {
            println!("  [{}] {}{}",
                t.id, t.threat,
                if t.verified { "  ✓" } else { "" });
            println!("       → {}", &t.mitigation[..t.mitigation.len().min(100)]);
            println!();
        }
    }
}

// ── FEES ─────────────────────────────────────────────────────────────────────

fn cmd_fees(args: &[String]) {
    let a: u128 = args.first().and_then(|s| s.parse().ok()).unwrap_or(1000);
    let d = 1_000_000_000_000_000_000u128;
    match ThunderFeeBreakdown::compute(VusdAmount(a * d)) {
        Ok(f) => {
            let fmt = |v: VusdAmount| format!("{:.6}", v.0 as f64 / d as f64);
            println!("\n  {} VUSD transfer:", a);
            println!("    Thunder fee:   {} VUSD  (2x LN)", fmt(f.thunder_fee));
            println!("    Operator cut:  {} VUSD  (1%)", fmt(f.operator_cut));
            println!("    Net recipient: {} VUSD\n", fmt(f.net_to_recipient));
        }
        Err(e) => eprintln!("  Error: {}", e),
    }
}

// ── ROTATE ───────────────────────────────────────────────────────────────────

fn cmd_rotate() {
    println!("\n  ⚡ Key Rotation (T14 mitigation)");
    println!("  1. Drain channels via keysend to relay peers");
    println!("  2. lncli closechannel <channel_point>  (each channel)");
    println!("  3. lncli stop");
    println!("  4. Backup: cp -r ~/.lnd ~/.lnd.bak.$(date +%s)");
    println!("  5. Generate new wallet: lnd --configfile=~/.lnd/lnd.conf");
    println!("  6. Fund new wallet with non-KYC Bitcoin");
    println!("  7. Open new private channels with relay peers");
    println!("  8. Update config.toml [[relays]] channel IDs");
    println!("  9. Notify peers of new pubkey (encrypted, out-of-band)\n");
}

fn print_help() {
    println!("\n  ⚡ thunder v{}  |  setup | threats | fees [n] | status | start | rotate\n", VERSION);
}
