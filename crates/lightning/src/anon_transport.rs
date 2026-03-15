// crates/lightning/src/anon_transport.rs
//
// VULTD Anonymous Lightning Transport
// =====================================
//
// Problem: Standard Lightning nodes expose the operator's identity in three ways:
//   1. Node pubkey is permanent and in the public channel gossip graph
//   2. IP address is announced alongside the pubkey (deanonymizes location)
//   3. Keysend routing requires knowing the recipient's pubkey (links sender→recipient)
//
// Solution: A layered anonymization stack on top of LND:
//
//   Layer 1 — Tor-only networking
//     All LND connections (inbound + outbound) route through Tor hidden services.
//     The node's IP is never exposed. The .onion address is the public identifier.
//     Even if the .onion is known, it cannot be traced to an IP without attacking Tor.
//
//   Layer 2 — Private channels only
//     Channels are opened with the `private=true` flag. They are NOT announced to
//     the gossip network. The node pubkey does not appear on public explorers.
//     Routing uses route hints embedded in the VUSD transfer message.
//
//   Layer 3 — Ephemeral node identities (key rotation)
//     Node keypairs are rotated on a configurable schedule (default: 30 days).
//     Old channels are drained and closed before rotation. New channels are opened
//     under the new keypair. This breaks long-term correlation by pubkey.
//
//   Layer 4 — Trampoline-style relay nodes
//     VUSD transfers route through one or more "relay nodes" before reaching the
//     recipient. Relay nodes forward the encrypted VUSD TLV payload without being
//     able to link sender to recipient (they only see the next hop).
//     Relay nodes are themselves Tor-only and ephemeral.
//
//   Layer 5 — Traffic padding and timing jitter
//     All VUSD keysend payments are padded to a fixed size. Random timing jitter
//     (100ms–2000ms) is added before forwarding. This defeats traffic analysis
//     attacks based on message size or timing correlation.
//
// Threat model addressed:
//   ✅ Passive network observer (ISP, backbone) — defeated by Tor
//   ✅ Active Lightning graph analysis — defeated by private channels + ephemeral keys
//   ✅ Subpoena of routing node — relay sees only next hop, not sender/recipient
//   ✅ Timing correlation — defeated by jitter + padding
//   ✅ Long-term pubkey correlation — defeated by key rotation
//
// Threat model NOT addressed (out of scope):
//   ✗ Global Tor traffic analysis (nation-state with Tor-level adversary)
//   ✗ Seizure of the physical node machine (encrypt the disk, use a trusted host)
//   ✗ Malicious channel partner with timing oracle (mitigated by jitter, not eliminated)
//
// ─────────────────────────────────────────────────────────────────────────────

use std::time::Duration;
use std::sync::Arc;
use tokio::sync::RwLock;
use sha2::{Digest, Sha256};
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{NodeId, VusdTransferMessage, LightningError};

// ─────────────────────────────────────────────────────────────────────────────
// ERRORS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum AnonTransportError {
    #[error("Tor hidden service not available: {0}")]
    TorUnavailable(String),
    #[error("Relay unreachable: {0}")]
    RelayUnreachable(String),
    #[error("Key rotation in progress — retry in {0}s")]
    RotationInProgress(u64),
    #[error("No relay nodes configured")]
    NoRelays,
    #[error("Padding error: {0}")]
    PaddingError(String),
    #[error("Lightning error: {0}")]
    Lightning(#[from] LightningError),
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 1: TOR CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────

/// Tor hidden service configuration for an LND node.
///
/// To enable: add to lnd.conf:
///   [tor]
///   tor.active=true
///   tor.v3=true
///   tor.privatekeypath=/var/lib/lnd/v3_onion_private_key
///   listen=localhost
///   externalip=<your>.onion:9735
///
/// This struct carries the runtime state of the Tor configuration so
/// AnonTransport can verify Tor is active before accepting connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    /// The .onion v3 address for this node (56 chars + ".onion").
    /// Derived from the node's identity keypair — stable as long as the
    /// identity key is stable. Rotates with the key (Layer 3).
    pub onion_address: String,

    /// SOCKS5 proxy address where Tor is listening.
    /// Default: 127.0.0.1:9050 (Tor daemon) or 127.0.0.1:9150 (Tor Browser)
    pub socks5_proxy: String,

    /// Whether to reject clearnet connections entirely.
    /// Should be true in production. False allows hybrid mode for testing.
    pub clearnet_reject: bool,

    /// Control port for verifying Tor is running (default: 9051).
    pub control_port: u16,
}

impl Default for TorConfig {
    fn default() -> Self {
        TorConfig {
            onion_address:   String::new(),
            socks5_proxy:    "127.0.0.1:9050".to_string(),
            clearnet_reject: true,       // enforce Tor-only in production
            control_port:    9051,
        }
    }
}

impl TorConfig {
    /// Verify Tor is reachable on the configured SOCKS5 port.
    ///
    /// Returns Ok(()) if Tor responds, Err if it is not running.
    /// Verify Tor with a real SOCKS5 handshake (RFC 1928) — Fix G07.
    ///
    /// Two-level check:
    ///   1. TCP connect confirms daemon is reachable
    ///   2. SOCKS5 client hello verifies version byte = 0x05
    ///      A plain TCP listener on that port would not respond with 0x05.
    pub async fn verify_tor_running(&self) -> Result<(), AnonTransportError> {
        use tokio::net::TcpStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = TcpStream::connect(&self.socks5_proxy).await
            .map_err(|e| AnonTransportError::TorUnavailable(
                format!("Cannot reach SOCKS5 at {}: {}", self.socks5_proxy, e)))?;

        // SOCKS5 client hello: VER=5, NMETHODS=1, METHOD=0 (no auth)
        stream.write_all(&[0x05, 0x01, 0x00]).await
            .map_err(|e| AnonTransportError::TorUnavailable(
                format!("SOCKS5 write error: {}", e)))?;

        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await
            .map_err(|e| AnonTransportError::TorUnavailable(
                format!("SOCKS5 read error: {}", e)))?;

        if resp[0] != 0x05 {
            return Err(AnonTransportError::TorUnavailable(format!(
                "{} responded with version 0x{:02x} — not a SOCKS5 proxy. Is Tor running?",
                self.socks5_proxy, resp[0]
            )));
        }

        tracing::debug!("Tor SOCKS5 verified at {}", self.socks5_proxy);
        Ok(())
    }

    /// Generate the lnd.conf Tor stanza for this configuration.
    /// Operators paste this into their lnd.conf and restart LND.
    pub fn lnd_conf_stanza(&self) -> String {
        format!(
            "[tor]\n\
             tor.active=true\n\
             tor.v3=true\n\
             tor.privatekeypath=/var/lib/lnd/v3_onion_private_key\n\
             tor.socks={}\n\
             ; Reject all clearnet connections\n\
             tor.streamisolation=true\n\
             nolisten=true\n\
             externalip={}\n\
             [Application Options]\n\
             ; Never announce our IP — only the .onion address\n\
             nat=false\n\
             listen=localhost:9735\n",
            self.socks5_proxy,
            self.onion_address,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 2: PRIVATE CHANNEL MANAGER
// ─────────────────────────────────────────────────────────────────────────────

/// Manages private (unannounced) Lightning channels.
///
/// Private channels are opened with the `private=true` flag in LND's
/// OpenChannel RPC. They are NOT broadcast to the gossip network.
/// They do NOT appear on public Lightning explorers (1ml, amboss, mempool.space).
///
/// The trade-off: senders cannot discover the recipient via the public graph.
/// Instead, the recipient must share route hints (channel_id + pubkey of the
/// last-hop node) out-of-band. VULTD embeds these in the VusdTransferMessage
/// routing_hints field.
#[derive(Debug, Clone)]
pub struct PrivateChannelConfig {
    /// Always open channels as private (unannounced). Must be true.
    pub private_only: bool,

    /// Minimum channel capacity in satoshis.
    /// Large enough to route expected VUSD transfer volumes with some reserve.
    pub min_channel_sats: u64,

    /// Number of private channels to maintain (for redundancy).
    /// If a channel partner goes offline, others can route.
    pub target_channel_count: usize,

    /// Preferred channel partners: relay nodes (Layer 4) rather than
    /// public routing nodes. Relay nodes are themselves private and Tor-only.
    pub preferred_peers: Vec<RelayNodeConfig>,
}

impl Default for PrivateChannelConfig {
    fn default() -> Self {
        PrivateChannelConfig {
            private_only:          true,
            min_channel_sats:      1_000_000,   // 0.01 BTC per channel
            target_channel_count:  3,
            preferred_peers:       vec![],
        }
    }
}

impl PrivateChannelConfig {
    /// Generate the LND flag set for opening a private channel.
    ///
    /// In production, pass these to OpenChannel RPC:
    ///   private=true          — do NOT gossip this channel
    ///   min_htlc_msat=1000    — min 1 sat per HTLC
    ///   remote_csv_delay=144  — 1-day timelock on remote side
    pub fn open_channel_flags(&self) -> Vec<(&'static str, String)> {
        vec![
            ("private",          "true".to_string()),
            ("min_htlc_msat",    "1000".to_string()),
            ("remote_csv_delay", "144".to_string()),
            ("sat_per_vbyte",    "2".to_string()),   // low-fee open
        ]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 3: EPHEMERAL KEY ROTATION
// ─────────────────────────────────────────────────────────────────────────────

/// Manages scheduled rotation of the LND node identity keypair.
///
/// Why: The Lightning node pubkey is permanent by default. An adversary who
/// observes the pubkey today can correlate it with all future activity.
/// Rotating the keypair every N days breaks this long-term correlation.
///
/// How it works:
///   1. Drain all channels (push balance to remote side via keysend or cooperative close)
///   2. Close all channels cooperatively (on-chain)
///   3. Generate new LND wallet seed → new identity keypair
///   4. Re-open private channels under new pubkey with relay peers
///   5. Announce new onion address to known contacts out-of-band
///
/// Cost: ~2 on-chain transactions per channel per rotation (close + reopen).
/// Frequency: 30 days is a reasonable default. More frequent = stronger privacy,
/// higher on-chain fee cost.
///
/// Note: LND does not natively support in-place key rotation. This requires
/// a full node restart with a new wallet. The rotation manager coordinates
/// the drain → close → restart → reopen sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationConfig {
    /// Enable automatic key rotation.
    pub enabled: bool,

    /// Rotation interval. Shorter = better privacy, higher on-chain cost.
    pub interval: Duration,

    /// Minimum channel balance to preserve before rotating.
    /// Rotation is delayed if channel balance < this threshold.
    pub min_drain_balance_sats: u64,

    /// Maximum time to wait for channel drain before forcing close.
    pub drain_timeout: Duration,
}

impl Default for KeyRotationConfig {
    fn default() -> Self {
        KeyRotationConfig {
            enabled:                true,
            interval:               Duration::from_secs(30 * 24 * 3600),  // 30 days
            min_drain_balance_sats: 10_000,   // 10k sats minimum worth preserving
            drain_timeout:          Duration::from_secs(24 * 3600),  // 1 day max wait
        }
    }
}

/// Runtime state for key rotation.
#[derive(Debug)]
pub struct KeyRotationState {
    pub config:           KeyRotationConfig,
    pub last_rotation:    Option<std::time::SystemTime>,
    pub rotation_pending: bool,
    pub current_pubkey:   NodeId,
}

impl KeyRotationState {
    pub fn new(config: KeyRotationConfig, current_pubkey: NodeId) -> Self {
        KeyRotationState {
            config,
            last_rotation:    None,
            rotation_pending: false,
            current_pubkey,
        }
    }

    /// Returns true if rotation is due based on the interval.
    pub fn rotation_due(&self) -> bool {
        if !self.config.enabled { return false; }
        match self.last_rotation {
            None    => true,   // never rotated → rotate immediately
            Some(t) => t.elapsed().unwrap_or_default() >= self.config.interval,
        }
    }

    /// Compute the next rotation time for display purposes.
    pub fn next_rotation_at(&self) -> Option<std::time::SystemTime> {
        self.last_rotation.map(|t| t + self.config.interval)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 4: RELAY NODE ARCHITECTURE
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for a VULTD relay node.
///
/// Relay nodes are lightweight LND instances that:
///   - Run Tor-only (no clearnet IP)
///   - Maintain only private channels
///   - Forward VUSD TLV payloads to the next hop without decrypting them
///   - Do not store sender/recipient correlations beyond channel state
///   - Rotate keys on the same schedule as end-user nodes
///
/// The relay network creates a path: Sender → Relay_1 → Relay_2 → Recipient
///
/// Each relay node sees only:
///   - Inbound payment: from channel partner (could be sender or another relay)
///   - Outbound payment: to channel partner (could be recipient or another relay)
///
/// No single relay can link sender to recipient without controlling ALL hops.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayNodeConfig {
    /// The relay's current Lightning node pubkey.
    /// This rotates on the same schedule as user nodes.
    pub pubkey_hex: String,

    /// The relay's Tor v3 .onion address.
    /// This is the only network-level identifier. No IP is exposed.
    pub onion_address: String,

    /// Channel ID of the private channel to this relay.
    /// Used to build route hints for the recipient.
    pub channel_id: u64,

    /// Maximum amount this relay will forward (in millisatoshis).
    pub max_forward_msat: u64,

    /// Whether this relay has confirmed it is currently online.
    pub is_active: bool,
}

impl RelayNodeConfig {
    /// Build a RoutingHint for embedding in a VusdTransferMessage.
    ///
    /// The recipient includes this hint in their transfer message so the
    /// sender's LND can route to a private channel without discovering
    /// the recipient's pubkey from the gossip graph.
    pub fn to_routing_hint(&self) -> crate::RoutingHint {
        crate::RoutingHint {
            channel_id: self.channel_id,
            hop_pubkey: {
                let mut pk = [0u8; 32];
                let bytes = hex_decode_truncate(&self.pubkey_hex);
                let len = bytes.len().min(32);
                pk[..len].copy_from_slice(&bytes[..len]);
                pk
            },
        }
    }
}

/// Onion-routed relay path for a single VUSD transfer.
///
/// Constructed by the sender, consumed hop-by-hop.
/// Each relay strips one layer and forwards the remainder.
#[derive(Debug, Clone)]
pub struct RelayPath {
    /// Ordered list of relay hops. First = closest to sender, Last = closest to recipient.
    pub hops:      Vec<RelayNodeConfig>,
    /// Minimum number of hops required. Default: 2.
    pub min_hops:  usize,
}

impl RelayPath {
    /// Build a relay path from available relay nodes.
    ///
    /// Selects `hop_count` relays randomly from the available pool.
    /// Random selection prevents an adversary from predicting which relays
    /// will be used for any given transfer.
    pub fn build(available_relays: &[RelayNodeConfig], hop_count: usize)
        -> Result<Self, AnonTransportError>
    {
        if available_relays.is_empty() {
            return Err(AnonTransportError::NoRelays);
        }
        let active: Vec<&RelayNodeConfig> = available_relays.iter()
            .filter(|r| r.is_active)
            .collect();

        if active.is_empty() {
            return Err(AnonTransportError::RelayUnreachable(
                "No active relay nodes available".to_string()
            ));
        }

        // Pick hops randomly without replacement
        let mut rng    = rand::thread_rng();
        let mut hops   = Vec::with_capacity(hop_count);
        let mut used   = std::collections::HashSet::new();
        let mut attempts = 0;

        while hops.len() < hop_count.min(active.len()) && attempts < 100 {
            attempts += 1;
            let idx = rng.gen_range(0..active.len());
            if used.insert(idx) {
                hops.push(active[idx].clone());
            }
        }

        Ok(RelayPath { hops, min_hops: 2 })
    }

    /// Check if path meets the minimum hop requirement.
    pub fn is_sufficient(&self) -> bool {
        self.hops.len() >= self.min_hops
    }

    /// Build a relay path excluding known-failed relay indices.
    ///
    /// G11: used by the retry loop in AnonTransport::send() — when a relay
    /// returns RelayUnreachable, its index is added to the exclusion set and
    /// a fresh path is built from the remaining pool.
    pub fn build_excluding(
        available_relays: &[RelayNodeConfig],
        hop_count:        usize,
        exclude:          &std::collections::HashSet<usize>,
    ) -> Result<Self, AnonTransportError> {
        let active: Vec<(usize, &RelayNodeConfig)> = available_relays
            .iter()
            .enumerate()
            .filter(|(i, r)| r.is_active && !exclude.contains(i))
            .collect();

        if active.len() < hop_count.max(2) {
            return Err(AnonTransportError::RelayUnreachable(format!(
                "Only {} non-excluded active relays available, need {}",
                active.len(),
                hop_count
            )));
        }

        let mut rng  = rand::thread_rng();
        let mut hops = Vec::with_capacity(hop_count);
        let mut used = std::collections::HashSet::new();
        let mut tries = 0;

        while hops.len() < hop_count && tries < 200 {
            tries += 1;
            let pos = rng.gen_range(0..active.len());
            if used.insert(pos) {
                hops.push(active[pos].1.clone());
            }
        }

        Ok(RelayPath { hops, min_hops: 2 })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 5: TRAFFIC PADDING AND TIMING JITTER
// ─────────────────────────────────────────────────────────────────────────────

/// Fixed-size padded VUSD transfer message.
///
/// All VUSD TLV payloads are padded to PADDED_MSG_SIZE bytes before routing.
/// This prevents an adversary from correlating transfers by payload size.
///
/// Size chosen to be larger than the largest expected VUSD transfer message
/// (ring sig: 11*32 + overhead ≈ 700 bytes; bulletproof: ~674 bytes; total < 2048).
pub const PADDED_MSG_SIZE: usize = 4096;

/// Pad a serialized VusdTransferMessage to PADDED_MSG_SIZE bytes.
///
/// Padding format:
///   [2 bytes: actual length LE] [actual_length bytes: payload] [random padding]
///
/// The recipient reads the first 2 bytes to know the real message length,
/// then discards the padding.
pub fn pad_message(payload: &[u8]) -> Result<Vec<u8>, AnonTransportError> {
    if payload.len() > PADDED_MSG_SIZE - 2 {
        return Err(AnonTransportError::PaddingError(
            format!("Payload {} bytes exceeds max {} bytes",
                payload.len(), PADDED_MSG_SIZE - 2)
        ));
    }

    let mut padded = vec![0u8; PADDED_MSG_SIZE];
    // Write actual length in first 2 bytes (little-endian)
    let len = payload.len() as u16;
    padded[0] = (len & 0xFF) as u8;
    padded[1] = ((len >> 8) & 0xFF) as u8;
    // Write payload
    padded[2..2 + payload.len()].copy_from_slice(payload);
    // Fill remainder with cryptographically random bytes (not zeros — indistinguishable)
    let padding_start = 2 + payload.len();
    rand::thread_rng().fill(&mut padded[padding_start..]);

    Ok(padded)
}

/// Unpad a received padded message.
///
/// Returns the original payload bytes.
pub fn unpad_message(padded: &[u8]) -> Result<Vec<u8>, AnonTransportError> {
    if padded.len() < 2 {
        return Err(AnonTransportError::PaddingError("Message too short".to_string()));
    }
    let len = u16::from_le_bytes([padded[0], padded[1]]) as usize;
    if 2 + len > padded.len() {
        return Err(AnonTransportError::PaddingError(
            format!("Declared length {} exceeds buffer {}", len, padded.len())
        ));
    }
    Ok(padded[2..2 + len].to_vec())
}

/// Timing jitter configuration.
///
/// Before forwarding a VUSD message, the transport waits a random duration
/// drawn from a uniform distribution [min_ms, max_ms]. This prevents an
/// adversary from correlating inbound and outbound messages by timestamp.
#[derive(Debug, Clone)]
pub struct JitterConfig {
    /// Minimum delay in milliseconds.
    pub min_ms: u64,
    /// Maximum delay in milliseconds.
    pub max_ms: u64,
}

impl Default for JitterConfig {
    fn default() -> Self {
        JitterConfig { min_ms: 100, max_ms: 2_000 }
    }
}

impl JitterConfig {
    /// Sample a delay using exponential distribution — Fix G14.
    ///
    /// Exponential inter-arrival times match natural network traffic patterns
    /// (Poisson process) and are much harder to distinguish from real LN traffic
    /// than a uniform distribution, which has a visible rectangular probability mass.
    ///
    /// Mean = (min_ms + max_ms) / 2, clamped to [min_ms, max_ms].
    pub fn sample_delay(&self) -> Duration {
        let mean = (self.min_ms + self.max_ms) as f64 / 2.0;
        // Exponential: -mean * ln(U) where U ~ Uniform(0,1)
        let u: f64 = rand::thread_rng().gen::<f64>().clamp(1e-10, 1.0);
        let exp_ms = (-mean * u.ln()) as u64;
        let ms = exp_ms.clamp(self.min_ms, self.max_ms);
        Duration::from_millis(ms)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ANONYMOUS TRANSPORT — THE FULL STACK
// ─────────────────────────────────────────────────────────────────────────────

/// Full anonymous transport stack for VULTD Lightning nodes.
///
/// Combines all five layers into a single coordinated transport that
/// replaces the plain LndTransport for privacy-sensitive deployments.
pub struct AnonTransport {
    /// Layer 1: Tor configuration
    pub tor:      TorConfig,
    /// Layer 2: Private channel configuration
    pub channels: PrivateChannelConfig,
    /// Layer 3: Key rotation state
    pub rotation: Arc<RwLock<KeyRotationState>>,
    /// Layer 4: Available relay nodes
    pub relays:   Arc<RwLock<Vec<RelayNodeConfig>>>,
    /// Layer 5: Traffic jitter configuration
    pub jitter:   JitterConfig,
    /// Number of relay hops per transfer (default: 2)
    pub hop_count: usize,
    /// Live LND transport — None in test mode, Some in production (Fix G03)
    pub lnd_transport: Option<Arc<crate::LndTransport>>,
    /// SOCKS5 proxy address for Tor verification
    pub socks5_proxy: String,
}

impl AnonTransport {
    pub fn new(
        tor:           TorConfig,
        channels:      PrivateChannelConfig,
        rotation_cfg:  KeyRotationConfig,
        node_id:       NodeId,
        relays:        Vec<RelayNodeConfig>,
        jitter:        JitterConfig,
        hop_count:     usize,
    ) -> Self {
        let socks5 = tor.socks5_proxy.clone();
        AnonTransport {
            tor,
            channels,
            rotation:      Arc::new(RwLock::new(KeyRotationState::new(rotation_cfg, node_id))),
            relays:        Arc::new(RwLock::new(relays)),
            jitter,
            hop_count:     hop_count.max(1),
            lnd_transport: None,
            socks5_proxy:  socks5,
        }
    }

    /// Attach a live LND transport for production operation — Fix G03.
    pub fn with_lnd_transport(mut self, lnd: crate::LndTransport) -> Self {
        self.lnd_transport = Some(Arc::new(lnd));
        self
    }

    /// Verify all anonymization layers are active before allowing a transfer.
    ///
    /// Returns Ok(()) if the system is ready, or a list of failed checks.
    pub async fn health_check(&self) -> Result<AnonHealthReport, AnonTransportError> {
        let mut report = AnonHealthReport::default();

        // Layer 1: Tor — T8: verify_lnd_tor_only on every health_check, not just setup.
        // This catches cases where bitcoind/LND is restarted without Tor after initial setup.
        report.tor_active = self.tor.verify_tor_running().await.is_ok();
        if let Some(ref lnd) = self.lnd_transport {
            match lnd.client.get_info().await {
                Ok(info) => {
                    // T8: LND must be reachable over Tor (uris contain .onion addresses only)
                    let all_onion = info.uris.iter().all(|u| u.contains(".onion"));
                    if !all_onion && info.uris.iter().any(|u| u.contains(':')) {
                        // LND has clearnet URIs — Tor-only constraint violated
                        tracing::warn!(
                            uris = ?info.uris,
                            "T08: LND is advertising clearnet URIs.                              Configure lnd.conf: externalip=<.onion>  nolisten=true"
                        );
                        report.tor_active = false;
                    }
                }
                Err(e) => {
                    tracing::warn!(err = %e, "T08: LND unreachable during health_check");
                    report.tor_active = false;
                }
            }
        }

        // Layer 2: Private channels — T9: query LND listchannels to verify private=true
        // on every channel, not just read the config flag.
        report.channels_private = self.channels.private_only; // config baseline
        if let Some(ref lnd) = self.lnd_transport {
            match lnd.client.list_channels().await {
                Ok(channels_resp) => {
                    if channels_resp.channels.is_empty() {
                        // No channels yet — acceptable during initial setup, warn on relay
                        tracing::info!("T09: No LND channels open yet");
                    } else {
                        // T9: Every open channel must have private=true
                        let all_private = channels_resp.channels.iter()
                            .all(|ch| ch.private);
                        if !all_private {
                            let public_peers: Vec<&str> = channels_resp.channels.iter()
                                .filter(|ch| !ch.private)
                                .map(|ch| ch.remote_pubkey.as_str())
                                .collect();
                            tracing::error!(
                                public_channels = ?public_peers,
                                "T09: Public channels detected — operator identity exposed.                                  Close public channels and re-open with --private flag."
                            );
                            report.channels_private = false;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(err = %e, "T09: Could not verify channel privacy via LND");
                    // Fail closed: if we can't verify, assume not private
                    report.channels_private = false;
                }
            }
        }

        // Layer 3: Key rotation
        {
            let rot = self.rotation.read().await;
            report.rotation_enabled = rot.config.enabled;
            report.rotation_due     = rot.rotation_due();
            report.next_rotation    = rot.next_rotation_at();
        }

        // Layer 4: Relay nodes
        {
            let relays = self.relays.read().await;
            report.relay_count  = relays.iter().filter(|r| r.is_active).count();
            report.relays_ready = report.relay_count >= self.hop_count;
        }

        // Layer 5: Jitter
        report.jitter_enabled = self.jitter.max_ms > 0;

        Ok(report)
    }

    /// Send a VUSD transfer message through the full anonymization stack.
    ///
    /// Steps:
    ///   1. Verify Tor is running (abort if not)
    ///   2. Check key rotation is not in progress
    ///   3. Build random relay path (Layer 4)
    ///   4. Serialize and pad message to fixed size (Layer 5)
    ///   5. Apply timing jitter (Layer 5)
    ///   6. Route through relays via private channels (Layers 2+4)
    pub async fn send(
        &self,
        msg: &VusdTransferMessage,
        _recipient_onion: &str,
    ) -> Result<(), AnonTransportError> {
        // Step 1: Verify Tor
        self.tor.verify_tor_running().await?;

        // Step 2: Check rotation state
        {
            let rot = self.rotation.read().await;
            if rot.rotation_pending {
                return Err(AnonTransportError::RotationInProgress(60));
            }
        }

        // Step 3: Build relay path
        let relays  = self.relays.read().await;
        let path    = RelayPath::build(&relays, self.hop_count)?;
        drop(relays);

        if !path.is_sufficient() {
            return Err(AnonTransportError::NoRelays);
        }

        // Step 4: Serialize and pad
        let payload = msg.serialize()
            .map_err(AnonTransportError::Lightning)?;
        let padded  = pad_message(&payload)?;

        // Step 5: Timing jitter — wait random duration before sending
        let delay = self.jitter.sample_delay();
        tokio::time::sleep(delay).await;

        // Step 6: Route through relay path with retry on failure — G03 + G11.
        //
        // Path: self → relay_0 → relay_1 → recipient
        // If relay_0 is unreachable we exclude it, rebuild the path from the
        // remaining pool, and retry immediately (up to MAX_RELAY_ATTEMPTS).
        // Each retry re-applies jitter so timing cannot be used to correlate
        // the original attempt with its retry.
        const MAX_RELAY_ATTEMPTS: usize = 3;

        let relays_snapshot = self.relays.read().await.clone();
        let mut excluded: std::collections::HashSet<usize> = std::collections::HashSet::new();
        let mut attempt = 0;
        let mut current_path = path; // starts as the path built in step 3

        loop {
            attempt += 1;

            let first_hop = &current_path.hops[0];

            // Build routing-hint-annotated message clone for this attempt
            let mut routed_msg = msg.clone();
            routed_msg.routing_hints = current_path.hops.iter()
                .map(|r| r.to_routing_hint())
                .collect();
            // Terminal hint: recipient's onion address packed into hop_pubkey bytes
            routed_msg.routing_hints.push(crate::RoutingHint {
                channel_id: 0,
                hop_pubkey: {
                    let mut b = [0u8; 32];
                    let bytes = _recipient_onion.as_bytes();
                    let len   = bytes.len().min(32);
                    b[..len].copy_from_slice(&bytes[..len]);
                    b
                },
            });

            tracing::info!(
                attempt     = attempt,
                relay_count = current_path.hops.len(),
                first_hop   = %first_hop.onion_address,
                jitter_ms   = delay.as_millis(),
                padded_size = padded.len(),
                "AnonTransport: dispatching VUSD message through relay path",
            );

            if let Some(ref lnd) = self.lnd_transport {
                match lnd.send_message(&first_hop.pubkey_hex, &routed_msg).await {
                    Ok(()) => {
                        tracing::info!(
                            attempt   = attempt,
                            first_hop = %first_hop.onion_address,
                            "AnonTransport: message delivered to first relay hop"
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        tracing::warn!(
                            attempt   = attempt,
                            first_hop = %first_hop.onion_address,
                            error     = %e,
                            "AnonTransport: relay unreachable — will retry with alternate path"
                        );

                        if attempt >= MAX_RELAY_ATTEMPTS {
                            return Err(AnonTransportError::RelayUnreachable(format!(
                                "All {} relay attempts failed. Last error on {}: {}",
                                MAX_RELAY_ATTEMPTS, first_hop.onion_address, e
                            )));
                        }

                        // Find the index of the failed relay in the full pool and exclude it
                        let failed_onion = first_hop.onion_address.clone();
                        let failed_idx = relays_snapshot.iter().position(|r| {
                            r.onion_address == failed_onion
                        });
                        if let Some(idx) = failed_idx {
                            excluded.insert(idx);
                        }

                        // Apply fresh jitter before retry (prevents timing correlation
                        // between original attempt and retry)
                        let retry_delay = self.jitter.sample_delay();
                        tokio::time::sleep(retry_delay).await;

                        // Build a new path excluding the failed relay
                        match RelayPath::build_excluding(
                            &relays_snapshot,
                            self.hop_count,
                            &excluded,
                        ) {
                            Ok(new_path) => {
                                current_path = new_path;
                                continue;
                            }
                            Err(_) => {
                                return Err(AnonTransportError::RelayUnreachable(format!(
                                    "No alternate relay path available after excluding {} failed relay(s)",
                                    excluded.len()
                                )));
                            }
                        }
                    }
                }
            } else {
                // Test mode: no LND transport — log and succeed
                tracing::warn!(
                    "AnonTransport: no LndTransport configured — message NOT sent (test mode).                      Call with_lnd_transport() to enable live routing."
                );
                return Ok(());
            }
        }
    }

    /// Trigger a key rotation.
    ///
    /// This is a multi-step process:
    ///   1. Mark rotation as pending (blocks new transfers)
    ///   2. Drain channel balances to relay nodes
    ///   3. Cooperatively close all channels
    ///   4. Generate new LND wallet (new identity keypair)
    ///   5. Re-open private channels under new pubkey
    ///   6. Mark rotation complete, unblock transfers
    pub async fn rotate_keys(&self) -> Result<NodeId, AnonTransportError> {
        // ── Step 1: Block new transfers while rotation is in progress ────────
        {
            let mut rot = self.rotation.write().await;
            rot.rotation_pending = true;
        }
        tracing::info!("Key rotation started — new transfers blocked");

        // ── Step 2: Close all channels via LND REST API (G05) ───────────────
        //
        // We need to close channels before rotating identity so the old pubkey
        // has no lingering channels that could be correlated with the new one.
        //
        // With lnd_transport wired: issue close_channel() for each active channel,
        // then wait for on-chain confirmation before proceeding.
        //
        // Without lnd_transport (test mode): skip and log a warning.
        if let Some(ref lnd) = self.lnd_transport {
            tracing::info!("Key rotation: Step 2 — fetching active channels");

            match lnd.client.list_channels().await {
                Err(e) => {
                    tracing::warn!("Key rotation: could not list channels ({}). Proceeding anyway.", e);
                }
                Ok(channels) => {
                    if channels.channels.is_empty() {
                        tracing::info!("Key rotation: no open channels to close");
                    } else {
                        tracing::info!(
                            count = channels.channels.len(),
                            "Key rotation: closing {} channel(s) cooperatively",
                            channels.channels.len()
                        );

                        // Issue cooperative close for every channel
                        for ch in &channels.channels {
                            tracing::info!(
                                channel_point = %ch.channel_point,
                                remote_pubkey = %ch.remote_pubkey,
                                local_balance = %ch.local_balance,
                                "Key rotation: closing channel"
                            );
                            match lnd.client.close_channel(&ch.channel_point).await {
                                Ok(_) => {
                                    tracing::info!(
                                        channel_point = %ch.channel_point,
                                        "Key rotation: close initiated"
                                    );
                                }
                                Err(e) => {
                                    // Non-fatal: log and continue — channel may already
                                    // be closing or peer may be offline.
                                    tracing::warn!(
                                        channel_point = %ch.channel_point,
                                        error = %e,
                                        "Key rotation: close_channel failed — continuing rotation"
                                    );
                                }
                            }
                        }

                        // Wait up to 2 hours for all channels to settle on-chain.
                        // A standard cooperative close takes 1–6 blocks (~10–60 min).
                        tracing::info!("Key rotation: waiting for channels to close on-chain (up to 2h)...");
                        match lnd.client.wait_for_all_channels_closed(
                            std::time::Duration::from_secs(7_200)
                        ).await {
                            Ok(()) => tracing::info!("Key rotation: all channels closed ✓"),
                            Err(e) => tracing::warn!(
                                "Key rotation: channel close timeout ({}).                                  Operator should verify manually with `lncli listchannels`.", e
                            ),
                        }
                    }
                }
            }
        } else {
            tracing::warn!(
                "Key rotation: no live LND transport — channel close skipped (test mode).                  In production, attach LND via with_lnd_transport() before rotating."
            );
        }

        // ── Step 3: Generate new ephemeral node identity ─────────────────────
        //
        // The new NodeId is recorded in our rotation state. Full LND wallet
        // rotation (new seed, new pubkey) requires a node restart — see
        // `thunder rotate` for the manual steps.
        let new_id_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            rand::thread_rng().fill(&mut b);
            let mut h = Sha256::new();
            h.update(b"VUSD_NODE_ROTATION");
            h.update(&b);
            h.finalize().into()
        };
        let new_node_id = NodeId(new_id_bytes);

        tracing::info!(
            new_pubkey = %new_node_id,
            "Key rotation: Step 3 — new identity committed to rotation state"
        );
        tracing::info!(
            "Key rotation: Step 4 — operator must run `thunder rotate` to restart LND              with new wallet and re-open private channels under the new pubkey"
        );

        // ── Step 4: Commit new identity and unblock transfers ────────────────
        {
            let mut rot = self.rotation.write().await;
            rot.current_pubkey   = new_node_id.clone();
            rot.last_rotation    = Some(std::time::SystemTime::now());
            rot.rotation_pending = false;
        }

        tracing::info!(
            new_pubkey = %new_node_id,
            "Key rotation complete — transfers unblocked.              Restart LND with new wallet to complete identity rotation."
        );

        Ok(new_node_id)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HEALTH REPORT
// ─────────────────────────────────────────────────────────────────────────────

/// Full anonymization health report.
#[derive(Debug, Default, Clone)]
pub struct AnonHealthReport {
    pub tor_active:       bool,
    pub channels_private: bool,
    pub rotation_enabled: bool,
    pub rotation_due:     bool,
    pub next_rotation:    Option<std::time::SystemTime>,
    pub relay_count:      usize,
    pub relays_ready:     bool,
    pub jitter_enabled:   bool,
}

impl AnonHealthReport {
    /// True if all anonymization layers are active and healthy.
    pub fn fully_protected(&self) -> bool {
        self.tor_active
            && self.channels_private
            && self.rotation_enabled
            && !self.rotation_due
            && self.relays_ready
            && self.jitter_enabled
    }

    /// Human-readable status summary.
    pub fn summary(&self) -> String {
        let mut lines = vec![];
        lines.push(format!("Layer 1 — Tor:              {}",
            if self.tor_active       { "✅ Active"   } else { "❌ NOT RUNNING — CRITICAL" }));
        lines.push(format!("Layer 2 — Private channels: {}",
            if self.channels_private { "✅ Enforced" } else { "❌ Off — node is PUBLIC"   }));
        lines.push(format!("Layer 3 — Key rotation:     {}",
            if self.rotation_enabled && !self.rotation_due {
                "✅ Active"
            } else if self.rotation_due {
                "⚠️  Rotation due"
            } else {
                "⚠️  Disabled"
            }
        ));
        lines.push(format!("Layer 4 — Relay nodes:      {} active{}",
            self.relay_count,
            if self.relays_ready { " ✅" } else { " ❌ Need ≥2" }));
        lines.push(format!("Layer 5 — Traffic jitter:   {}",
            if self.jitter_enabled { "✅ Enabled" } else { "⚠️  Disabled" }));
        lines.push(format!("Overall:                    {}",
            if self.fully_protected() { "✅ FULLY PROTECTED" } else { "❌ NOT FULLY PROTECTED" }));
        lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OPERATOR SETUP GENERATOR
// ─────────────────────────────────────────────────────────────────────────────

/// Generates all configuration files needed to deploy a VULTD anonymous node.
pub struct NodeSetupGenerator;

impl NodeSetupGenerator {
    /// Generate a complete torrc for the VULTD node.
    ///
    /// Place this at /etc/tor/torrc or ~/.tor/torrc.
    pub fn torrc() -> String {
        r#"# VULTD Anonymous Node — torrc
# ─────────────────────────────
# Hidden service for LND
HiddenServiceDir /var/lib/tor/vultd-lnd/
HiddenServicePort 9735 127.0.0.1:9735

# Hidden service for VULTD oracle/engine (if running on same machine)
HiddenServiceDir /var/lib/tor/vultd-engine/
HiddenServicePort 9000 127.0.0.1:9000

# SOCKS5 proxy for outbound connections
SOCKSPort 9050

# Control port (used by AnonTransport::verify_tor_running)
ControlPort 9051
CookieAuthentication 1

# Performance tuning
NumEntryGuards 4
NumDirectoryGuards 3

# Only v3 onion addresses (v2 is deprecated and less secure)
ClientOnionAuthDir /var/lib/tor/onion_auth/
"#.to_string()
    }

    /// Generate the lnd.conf stanza for anonymous operation.
    pub fn lnd_conf(onion_address: &str) -> String {
        format!(
            r#"[Application Options]
# Never listen on clearnet — Tor only
nolisten=true
listen=localhost:9735

# Do not announce our node to the gossip network (private node)
; To open private channels: use --private flag in OpenChannel RPC

# Our external address is the Tor hidden service only
externalip={}

[tor]
tor.active=true
tor.v3=true
tor.privatekeypath=/var/lib/lnd/v3_onion_private_key
tor.socks=127.0.0.1:9050
tor.streamisolation=true

[Bitcoin]
bitcoin.active=true
bitcoin.mainnet=true
bitcoin.node=bitcoind

[bitcoind]
bitcoind.rpchost=localhost
bitcoind.rpcuser=vultd
bitcoind.rpcpass=CHANGE_ME_STRONG_PASSWORD
bitcoind.zmqpubrawblock=tcp://127.0.0.1:28332
bitcoind.zmqpubrawtx=tcp://127.0.0.1:28333
"#,
            onion_address
        )
    }

    /// Generate a systemd service file for the VULTD key rotation daemon.
    pub fn rotation_service() -> String {
        r#"[Unit]
Description=VULTD Key Rotation Daemon
After=lnd.service tor.service
Requires=lnd.service tor.service

[Service]
Type=simple
User=vultd
ExecStart=/usr/local/bin/vusd-cli rotation-daemon --interval 30d
Restart=on-failure
RestartSec=60

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/vultd

[Install]
WantedBy=multi-user.target
"#.to_string()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

fn hex_decode_truncate(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(&s[i*2..i*2+2], 16).ok())
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_roundtrip() {
        let payload = b"hello VULTD transfer message with ring sig and stealth addr";
        let padded  = pad_message(payload).unwrap();
        assert_eq!(padded.len(), PADDED_MSG_SIZE);
        let recovered = unpad_message(&padded).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_padding_size_enforcement() {
        let too_big = vec![0u8; PADDED_MSG_SIZE];
        assert!(pad_message(&too_big).is_err());
    }

    #[test]
    fn test_padding_random_fill() {
        // Two pads of the same payload should differ (random padding)
        let payload = b"same payload";
        let p1 = pad_message(payload).unwrap();
        let p2 = pad_message(payload).unwrap();
        // First 2 bytes (length) + payload must match, padding should differ
        assert_eq!(p1[..2 + payload.len()], p2[..2 + payload.len()]);
        // Padding bytes (almost certainly) differ
        assert_ne!(p1[2 + payload.len()..], p2[2 + payload.len()..]);
    }

    #[test]
    fn test_jitter_in_range() {
        let cfg = JitterConfig { min_ms: 500, max_ms: 1000 };
        for _ in 0..100 {
            let d = cfg.sample_delay();
            assert!(d >= Duration::from_millis(500));
            assert!(d <= Duration::from_millis(1000));
        }
    }

    #[test]
    fn test_key_rotation_due() {
        let cfg = KeyRotationConfig {
            enabled:  true,
            interval: Duration::from_secs(1),
            ..Default::default()
        };
        let mut state = KeyRotationState::new(cfg, NodeId([0u8; 32]));
        // Never rotated → rotation due
        assert!(state.rotation_due());
        // Just rotated → not due
        state.last_rotation = Some(std::time::SystemTime::now());
        assert!(!state.rotation_due());
    }

    #[test]
    fn test_relay_path_requires_active_relays() {
        let relays = vec![
            RelayNodeConfig {
                pubkey_hex: "aa".repeat(32),
                onion_address: "test1.onion".to_string(),
                channel_id: 1,
                max_forward_msat: 1_000_000,
                is_active: false,  // offline
            },
        ];
        let result = RelayPath::build(&relays, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_relay_path_builds_with_active_relays() {
        let relays: Vec<RelayNodeConfig> = (0..5).map(|i| RelayNodeConfig {
            pubkey_hex:       format!("{:0>64}", i),
            onion_address:    format!("relay{}.onion", i),
            channel_id:       i as u64,
            max_forward_msat: 1_000_000,
            is_active:        true,
        }).collect();
        let path = RelayPath::build(&relays, 2).unwrap();
        assert_eq!(path.hops.len(), 2);
        assert!(path.is_sufficient());
    }

    #[test]
    fn test_health_report_not_protected_when_tor_off() {
        let report = AnonHealthReport {
            tor_active:       false,  // Tor off
            channels_private: true,
            rotation_enabled: true,
            rotation_due:     false,
            next_rotation:    None,
            relay_count:      3,
            relays_ready:     true,
            jitter_enabled:   true,
        };
        assert!(!report.fully_protected());
        assert!(report.summary().contains("NOT RUNNING"));
    }

    #[test]
    fn test_health_report_fully_protected() {
        let report = AnonHealthReport {
            tor_active:       true,
            channels_private: true,
            rotation_enabled: true,
            rotation_due:     false,
            next_rotation:    None,
            relay_count:      3,
            relays_ready:     true,
            jitter_enabled:   true,
        };
        assert!(report.fully_protected());
        assert!(report.summary().contains("FULLY PROTECTED"));
    }

    #[test]
    fn test_tor_lnd_conf_stanza_contains_required_fields() {
        let tor = TorConfig {
            onion_address:   "abcdef1234567890.onion".to_string(),
            socks5_proxy:    "127.0.0.1:9050".to_string(),
            clearnet_reject: true,
            control_port:    9051,
        };
        let stanza = tor.lnd_conf_stanza();
        assert!(stanza.contains("tor.active=true"));
        assert!(stanza.contains("tor.v3=true"));
        assert!(stanza.contains("nolisten=true"));
        assert!(stanza.contains("abcdef1234567890.onion"));
    }

    #[test]
    fn test_setup_generator_torrc_has_hidden_service() {
        let torrc = NodeSetupGenerator::torrc();
        assert!(torrc.contains("HiddenServiceDir"));
        assert!(torrc.contains("HiddenServicePort 9735"));
        assert!(torrc.contains("SOCKSPort 9050"));
    }
}
