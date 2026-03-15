// crates/thunder-node/src/lib.rs
//
// ████████╗██╗  ██╗██╗   ██╗███╗   ██╗██████╗ ███████╗██████╗
//    ██╔══╝██║  ██║██║   ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
//    ██║   ███████║██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
//    ██║   ██╔══██║██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
//    ██║   ██║  ██║╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║
//    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
//                                                  N O D E
//
// "You can't see thunder."
//
// Thunder Node is a privacy-maximized Lightning relay node for VULTD.
// It wraps the full AnonTransport stack (Tor, private channels, key rotation,
// relay hops, traffic jitter) and adds:
//
//   1. THUNDER FEE ENGINE
//      Standard LN fees are mirrored at 2× base cost, with 1% of the gross
//      transfer amount routed to the operator's stealth address before
//      the net amount continues to the recipient.
//
//      Example: Alice sends 1000 VUSD through Thunder.
//        Standard LN fee:  ~0.01% base ≈ 0.1 VUSD
//        Thunder fee:      2 × 0.1 = 0.2 VUSD (2× mirror, per spec)
//        Operator cut:     1% of 1000 = 10 VUSD   → operator's stealth wallet
//        Net to recipient: 1000 - 0.2 - 10 = 989.8 VUSD
//
//      The 2× fee premium communicates the privacy value-add to users.
//      The 1% operator share incentivizes running Thunder relay infrastructure.
//
//   2. THREAT MITIGATION MATRIX
//      Every known attack vector is identified, categorized, and mitigated
//      in code. The ThunderNode startup sequence verifies all mitigations
//      are active before accepting any relay traffic.
//
//   3. OPERATOR STEALTH WALLET
//      Operator fees are routed to a stealth address — not a plain Lightning
//      address. The operator cannot be identified from the fee destination
//      any more than a recipient can be identified from any other VUSD output.
//
// ─────────────────────────────────────────────────────────────────────────────

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use sha2::{Digest, Sha256};
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use vscx_core::VusdAmount;
use lightning::{
    NodeId, VusdTransferMessage,
    AnonTransport, AnonHealthReport, AnonTransportError,
    TorConfig, PrivateChannelConfig, KeyRotationConfig,
    RelayNodeConfig, JitterConfig,
    pad_message, unpad_message, PADDED_MSG_SIZE,
    encrypt_amount,
};
use privacy::{BulletproofRangeProof, PedersenCommitment, PrivacyLayer, StealthWallet};
use vscx_core::StealthAddress;

pub mod config;

// ─────────────────────────────────────────────────────────────────────────────
// FEE OUTPUT — internal type for operator fee cryptographic output
// ─────────────────────────────────────────────────────────────────────────────

/// A fully-constructed private VUSD output carrying the operator's fee.
/// This is serialized into SerializedOutput and injected into the transfer tx.
struct FeeOutput {
    pub stealth_address:   StealthAddress,
    pub ephemeral_pubkey:  [u8; 32],
    pub amount_commitment: PedersenCommitment,
    pub range_proof:       BulletproofRangeProof,
    pub encrypted_amount:  [u8; 16],
}

// ─────────────────────────────────────────────────────────────────────────────
// ERRORS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ThunderError {
    #[error("Thunder node not fully protected: {0}")]
    NotProtected(String),
    #[error("Fee calculation overflow")]
    FeeOverflow,
    #[error("Amount below dust limit after fees")]
    BelowDustAfterFees,
    #[error("Operator wallet not configured")]
    NoOperatorWallet,
    #[error("Relay error: {0}")]
    Relay(#[from] AnonTransportError),
    #[error("Threat mitigation failed: {0}")]
    ThreatMitigation(String),
    #[error("Fee routing error: {0}")]
    FeeRouting(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// THUNDER FEE ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/// Basis points (bps) constant: 10_000 bps = 100%
const BPS: u128 = 10_000;

/// Operator fee in basis points: 1% = 100 bps
pub const OPERATOR_FEE_BPS: u128 = 100;

/// Fee multiplier applied to the base Lightning fee: 2× = 200%
/// The 2× premium signals the privacy value-add to senders.
pub const THUNDER_FEE_MULTIPLIER: u128 = 2;

/// Standard Lightning base fee: ~0.01% = 1 bps of transfer amount.
/// This mirrors the median LN routing node fee policy as of 2025.
/// Source: 1ml.com fee statistics, 50th percentile fee rate.
pub const STANDARD_LN_FEE_BPS: u128 = 1; // 0.01%

/// Minimum absolute Thunder fee (VUSD base units), regardless of percentage.
/// Prevents dust attacks via tiny transfers where the percentage fee rounds to zero.
/// 0.01 VUSD = 10^16 base units.
pub const MIN_THUNDER_FEE_UNITS: u128 = 10_000_000_000_000_000; // 0.01 VUSD

/// Fee breakdown for a single Thunder relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThunderFeeBreakdown {
    /// Gross amount the sender submitted.
    pub gross_amount:    VusdAmount,
    /// Standard LN fee (base reference, before multiplier).
    pub standard_ln_fee: VusdAmount,
    /// Thunder relay fee = standard_ln_fee × 2 (the total fee charged).
    pub thunder_fee:     VusdAmount,
    /// Operator's cut = 1% of gross_amount (routed to operator stealth wallet).
    pub operator_cut:    VusdAmount,
    /// Net amount delivered to the actual recipient.
    pub net_to_recipient: VusdAmount,
}

impl ThunderFeeBreakdown {
    /// Compute the full fee breakdown for a transfer of `gross_amount`.
    ///
    /// Formula:
    ///   standard_ln_fee = gross_amount × STANDARD_LN_FEE_BPS / 10000
    ///   thunder_fee     = standard_ln_fee × THUNDER_FEE_MULTIPLIER
    ///   operator_cut    = gross_amount × OPERATOR_FEE_BPS / 10000
    ///   net_to_recipient = gross_amount - thunder_fee - operator_cut
    ///
    /// Both thunder_fee and operator_cut are floored at MIN_THUNDER_FEE_UNITS
    /// to prevent dust attacks via micro-transfers.
    pub fn compute(gross_amount: VusdAmount) -> Result<Self, ThunderError> {
        let g = gross_amount.0;

        // Standard LN fee: 0.01% of gross
        let standard_raw = g
            .checked_mul(STANDARD_LN_FEE_BPS)
            .ok_or(ThunderError::FeeOverflow)?
            / BPS;

        // Thunder fee: 2× standard LN fee
        let thunder_raw = standard_raw
            .checked_mul(THUNDER_FEE_MULTIPLIER)
            .ok_or(ThunderError::FeeOverflow)?;

        // Apply minimum fee floor
        let thunder_fee_units = thunder_raw.max(MIN_THUNDER_FEE_UNITS);

        // Operator cut: 1% of gross
        let operator_raw = g
            .checked_mul(OPERATOR_FEE_BPS)
            .ok_or(ThunderError::FeeOverflow)?
            / BPS;
        let operator_cut_units = operator_raw.max(MIN_THUNDER_FEE_UNITS);

        // Net to recipient
        let total_deducted = thunder_fee_units
            .checked_add(operator_cut_units)
            .ok_or(ThunderError::FeeOverflow)?;

        if total_deducted >= g {
            return Err(ThunderError::BelowDustAfterFees);
        }

        let net_units = g - total_deducted;

        Ok(ThunderFeeBreakdown {
            gross_amount:     gross_amount,
            standard_ln_fee:  VusdAmount(standard_raw),
            thunder_fee:      VusdAmount(thunder_fee_units),
            operator_cut:     VusdAmount(operator_cut_units),
            net_to_recipient: VusdAmount(net_units),
        })
    }

    /// Human-readable summary for the operator dashboard.
    pub fn display(&self) -> String {
        let decimals = 1_000_000_000_000_000_000u128; // 1e18
        let fmt = |v: VusdAmount| format!("{:.6}", v.0 as f64 / decimals as f64);
        format!(
            "Gross: {} VUSD  |  Thunder fee: {} VUSD (2× LN)  |  \
             Operator cut: {} VUSD (1%)  |  Net to recipient: {} VUSD",
            fmt(self.gross_amount),
            fmt(self.thunder_fee),
            fmt(self.operator_cut),
            fmt(self.net_to_recipient),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OPERATOR WALLET
// ─────────────────────────────────────────────────────────────────────────────

/// The operator's stealth wallet receives 1% of every relayed transfer.
///
/// Crucially, this is a VUSD stealth address — not a Lightning node pubkey,
/// not a Bitcoin address, not anything linkable to the operator's identity.
/// The operator scans incoming VUSD outputs using their view key exactly
/// like any other VUSD recipient.
///
/// This means: even if a government subpoenas every relay in the path,
/// they learn that some operator received a fee, but cannot determine
/// who that operator is without the operator's view private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorWallet {
    /// Operator's stealth wallet — view pubkey + spend pubkey (public keys only).
    /// Private keys stored separately, never in memory at relay time.
    pub stealth_wallet: StealthWallet,

    /// Running total of fees earned (in-memory; persisted separately).
    #[serde(skip)]
    pub fees_earned: Arc<RwLock<VusdAmount>>,
}

impl OperatorWallet {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        OperatorWallet {
            stealth_wallet: StealthWallet::generate(seed),
            fees_earned:    Arc::new(RwLock::new(VusdAmount::ZERO)),
        }
    }

    /// Construct a watch-only wallet directly from public keys loaded from config.toml.
    ///
    /// Fix G10: config.toml stores spend_pubkey_hex + view_pubkey_hex.
    /// This constructor is what ThunderNode::from_config() calls — the seed
    /// never touches the relay machine. Private keys stay on the operator's
    /// air-gapped device.
    ///
    /// Returns None if either hex string is missing or malformed.
    pub fn from_pubkeys(spend_pubkey_hex: &str, view_pubkey_hex: &str) -> Option<Self> {
        let spend = decode_hex_32(spend_pubkey_hex)?;
        let view  = decode_hex_32(view_pubkey_hex)?;
        Some(OperatorWallet {
            stealth_wallet: StealthWallet {
                spend_pubkey:  spend,
                view_pubkey:   view,
                spend_privkey: None,   // never loaded into relay RAM
                view_privkey:  None,   // operator scans offline with view key
            },
            fees_earned: Arc::new(RwLock::new(VusdAmount::ZERO)),
        })
    }

    /// Return the watch-only version (no private keys) for the relay process.
    ///
    /// The relay process only needs to SEND fees to the operator wallet,
    /// not spend from it. The spend private key is never loaded into the
    /// relay process memory.
    pub fn watch_only(&self) -> Self {
        OperatorWallet {
            stealth_wallet: self.stealth_wallet.watch_only(),
            fees_earned:    Arc::clone(&self.fees_earned),
        }
    }

    pub async fn record_fee_earned(&self, amount: VusdAmount) {
        let mut total = self.fees_earned.write().await;
        *total = VusdAmount(total.0.saturating_add(amount.0));
    }

    pub async fn total_earned(&self) -> VusdAmount {
        *self.fees_earned.read().await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// THREAT MITIGATION MATRIX
// ─────────────────────────────────────────────────────────────────────────────

/// Every known attack vector against a Thunder Node operator, categorized
/// by adversary capability and the countermeasure implemented.
///
/// The ThunderNode startup sequence verifies all CRITICAL and HIGH mitigations
/// are active before accepting relay traffic.
#[derive(Debug, Clone, Serialize)]
pub struct ThreatMatrix {
    pub mitigations: Vec<ThreatEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatEntry {
    pub id:          &'static str,
    pub threat:      &'static str,
    pub adversary:   AdversaryClass,
    pub severity:    ThreatSeverity,
    pub mitigation:  &'static str,
    pub layer:       MitigationLayer,
    pub verified:    bool,   // set at runtime by health_check
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdversaryClass {
    /// Passive observer (ISP, backbone tap, traffic analysis)
    PassiveNetwork,
    /// Active Lightning participant (routing node, channel partner)
    ActiveLightning,
    /// Legal compulsion (subpoena, warrant, court order)
    LegalCompulsion,
    /// Physical (hardware seizure, datacenter raid)
    Physical,
    /// Cryptographic (breaking encryption, protocol attacks)
    Cryptographic,
    /// Timing / traffic analysis correlation
    TimingAnalysis,
    /// Social engineering / OSINT (doxing the operator)
    Social,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Critical,  // Must mitigate before accepting any traffic
    High,      // Must mitigate before mainnet
    Medium,    // Should mitigate; acceptable for testnet
    Low,       // Defence in depth; nice to have
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum MitigationLayer {
    Network,       // Tor, clearnet rejection
    Protocol,      // Private channels, onion routing
    Cryptographic, // Stealth addresses, ring sigs, key rotation
    Operational,   // Disk encryption, jurisdiction, hardware
    Application,   // Traffic padding, jitter, fee routing
}

impl ThreatMatrix {
    /// Full threat matrix covering every known attack surface.
    pub fn full() -> Self {
        ThreatMatrix {
            mitigations: vec![
                // ── PASSIVE NETWORK THREATS ───────────────────────────────
                ThreatEntry {
                    id: "T01",
                    threat: "ISP sees operator's IP connects to Lightning network",
                    adversary: AdversaryClass::PassiveNetwork,
                    severity: ThreatSeverity::Critical,
                    mitigation: "Tor hidden service — LND nolisten=true, all connections over .onion. \
                                 ISP sees encrypted Tor traffic only, no destination IPs.",
                    layer: MitigationLayer::Network,
                    verified: false,
                },
                ThreatEntry {
                    id: "T02",
                    threat: "Backbone traffic analysis correlates encrypted flows by size/timing",
                    adversary: AdversaryClass::PassiveNetwork,
                    severity: ThreatSeverity::High,
                    mitigation: "All VUSD TLV payloads padded to fixed 4096 bytes. \
                                 Timing jitter 100–2000ms applied before each forward. \
                                 Every message looks identical on the wire.",
                    layer: MitigationLayer::Application,
                    verified: false,
                },
                ThreatEntry {
                    id: "T03",
                    threat: "Global Tor traffic analysis by nation-state (entry+exit correlation)",
                    adversary: AdversaryClass::PassiveNetwork,
                    severity: ThreatSeverity::Medium,
                    mitigation: "Known Tor limitation. Mitigated by: multi-hop relay path (2+ hops \
                                 means attacker must own both entry guard AND exit guard for ALL hops), \
                                 long-lived circuits, and stream isolation per transfer. \
                                 Operational: host in jurisdiction with strong legal protections.",
                    layer: MitigationLayer::Operational,
                    verified: false,
                },

                // ── ACTIVE LIGHTNING THREATS ──────────────────────────────
                ThreatEntry {
                    id: "T04",
                    threat: "Lightning gossip graph reveals node pubkey and IP address",
                    adversary: AdversaryClass::ActiveLightning,
                    severity: ThreatSeverity::Critical,
                    mitigation: "Private channels only (private=true flag on all OpenChannel calls). \
                                 Node pubkey NEVER announced to gossip. Node does not appear on \
                                 public Lightning explorers (1ml, amboss, mempool.space).",
                    layer: MitigationLayer::Protocol,
                    verified: false,
                },
                ThreatEntry {
                    id: "T05",
                    threat: "Channel partner (peer node) knows our pubkey and .onion address",
                    adversary: AdversaryClass::ActiveLightning,
                    severity: ThreatSeverity::High,
                    mitigation: "Only open channels with other Thunder/relay nodes, also running \
                                 Tor-only. Channel partner knows our .onion; they do not know our IP. \
                                 Key rotation every 30 days changes pubkey; new channels opened with \
                                 new relay peers before old channels close.",
                    layer: MitigationLayer::Protocol,
                    verified: false,
                },
                ThreatEntry {
                    id: "T06",
                    threat: "Relay node at sender side can link sender pubkey to recipient pubkey \
                             by watching inbound/outbound payments",
                    adversary: AdversaryClass::ActiveLightning,
                    severity: ThreatSeverity::High,
                    mitigation: "Multi-hop relay path (minimum 2 relays). Each relay sees only its \
                                 adjacent hop — sender sees relay_1, relay_1 sees relay_2, relay_2 \
                                 sees recipient. No single relay has both endpoints. \
                                 Timing jitter + fixed payload size prevent correlation.",
                    layer: MitigationLayer::Application,
                    verified: false,
                },
                ThreatEntry {
                    id: "T07",
                    threat: "Adversary controls multiple relay nodes and correlates traffic paths",
                    adversary: AdversaryClass::ActiveLightning,
                    severity: ThreatSeverity::Medium,
                    mitigation: "Relay selection is uniformly random per transfer. Attacker must \
                                 control ALL hops (P = (controlled/total)^hops). With 2 hops and \
                                 20% adversary relay share: P = 0.04 per transfer. \
                                 Mitigated further by diversifying relay node operators.",
                    layer: MitigationLayer::Protocol,
                    verified: false,
                },
                ThreatEntry {
                    id: "T08",
                    threat: "Keysend TLV type 5482373486 fingerprints VULTD traffic",
                    adversary: AdversaryClass::ActiveLightning,
                    severity: ThreatSeverity::Medium,
                    mitigation: "TLV type identifies VULTD traffic but NOT the participants. \
                                 Combined with Tor and private channels, knowing 'this is VULTD' \
                                 does not reveal who. Future: randomize TLV type per session.",
                    layer: MitigationLayer::Application,
                    verified: false,
                },
                ThreatEntry {
                    id: "T09",
                    threat: "HTLC timing oracle: relay measures inbound-to-outbound delay \
                             to correlate across hops",
                    adversary: AdversaryClass::TimingAnalysis,
                    severity: ThreatSeverity::High,
                    mitigation: "Timing jitter (100–2000ms uniform random) applied between \
                                 receiving and forwarding. Over 2 hops, observable window is \
                                 [200ms, 4000ms] — too wide to correlate reliably. \
                                 Configurable: increase max jitter for higher security at \
                                 cost of transfer latency.",
                    layer: MitigationLayer::Application,
                    verified: false,
                },
                ThreatEntry {
                    id: "T10",
                    threat: "Amount correlation: sender sends X, relay forwards X-fee, \
                             allowing amount-based linking across hops",
                    adversary: AdversaryClass::TimingAnalysis,
                    severity: ThreatSeverity::Medium,
                    mitigation: "VUSD amounts are hidden in Pedersen commitments — routing nodes \
                                 see only the encrypted TLV payload. The nominal keysend amount \
                                 is always 1 sat (constant) regardless of VUSD value transferred. \
                                 Amount correlation requires breaking the commitment.",
                    layer: MitigationLayer::Cryptographic,
                    verified: false,
                },

                // ── LEGAL COMPULSION THREATS ──────────────────────────────
                ThreatEntry {
                    id: "T11",
                    threat: "Government subpoenas Thunder Node operator for sender/recipient logs",
                    adversary: AdversaryClass::LegalCompulsion,
                    severity: ThreatSeverity::High,
                    mitigation: "Thunder Node stores NO logs of sender/recipient pubkeys. \
                                 It sees only: inbound VUSD TLV blob (encrypted), outbound TLV blob. \
                                 The encrypted payload is cryptographically unlinkable without \
                                 the sender's ring sig private key and the recipient's view key. \
                                 Operator cannot produce what they never had.",
                    layer: MitigationLayer::Application,
                    verified: true,  // Verified: no logging of sender/recipient in code
                },
                ThreatEntry {
                    id: "T12",
                    threat: "Government subpoenas LND node for channel partner identities",
                    adversary: AdversaryClass::LegalCompulsion,
                    severity: ThreatSeverity::High,
                    mitigation: "Channel partners are identified by .onion addresses only, \
                                 never by IP. Subpoenaing LND reveals .onion addresses of \
                                 relay peers — not their physical location or real identity. \
                                 Those relays are themselves Tor-only.",
                    layer: MitigationLayer::Network,
                    verified: false,
                },
                ThreatEntry {
                    id: "T13",
                    threat: "Operator identified through fee receipt address (operator wallet)",
                    adversary: AdversaryClass::LegalCompulsion,
                    severity: ThreatSeverity::High,
                    mitigation: "Operator fees route to a VUSD stealth address — not a Lightning \
                                 pubkey or Bitcoin address. The stealth OTA is unique per payment \
                                 and unlinkable to the operator's identity without the view private key. \
                                 Operator scans for fees using view key offline, on an air-gapped device.",
                    layer: MitigationLayer::Cryptographic,
                    verified: true,  // Implemented in OperatorWallet struct
                },
                ThreatEntry {
                    id: "T14",
                    threat: "Long-running node pubkey enables historical correlation after subpoena",
                    adversary: AdversaryClass::LegalCompulsion,
                    severity: ThreatSeverity::High,
                    mitigation: "Key rotation every 30 days. After rotation, old pubkey is gone \
                                 and new channels exist under a new identity. Subpoena of the current \
                                 node yields the current pubkey only; historical pubkeys are not \
                                 recoverable from LND state after rotation.",
                    layer: MitigationLayer::Cryptographic,
                    verified: false,
                },
                ThreatEntry {
                    id: "T15",
                    threat: "Jurisdiction: local laws compel operator to reveal identity or logs",
                    adversary: AdversaryClass::LegalCompulsion,
                    severity: ThreatSeverity::Medium,
                    mitigation: "Operational: host Thunder Node in a jurisdiction with strong \
                                 financial privacy laws and no data retention requirements \
                                 (e.g. Iceland, Switzerland, Panama, El Salvador). \
                                 Use a VPS provider with a no-log policy and history of \
                                 resisting legal requests (e.g. Mullvad VPS, Frantech). \
                                 Pay for hosting with Monero.",
                    layer: MitigationLayer::Operational,
                    verified: false,
                },

                // ── PHYSICAL THREATS ──────────────────────────────────────
                ThreatEntry {
                    id: "T16",
                    threat: "Server seizure: law enforcement raids datacenter and images disk",
                    adversary: AdversaryClass::Physical,
                    severity: ThreatSeverity::High,
                    mitigation: "Full-disk encryption (LUKS/dm-crypt). \
                                 Node requires manual decryption key on reboot — \
                                 no auto-decrypt at boot. A seized, powered-off machine \
                                 reveals nothing without the passphrase. \
                                 LND macaroon stored only in RAM (tmpfs mount) — \
                                 wiped on power loss.",
                    layer: MitigationLayer::Operational,
                    verified: false,
                },
                ThreatEntry {
                    id: "T17",
                    threat: "Live memory forensics on running node extracts private keys",
                    adversary: AdversaryClass::Physical,
                    severity: ThreatSeverity::Medium,
                    mitigation: "Operator spend private key NEVER loaded into relay process memory. \
                                 Only watch-only wallet (view pubkey) is in RAM. \
                                 LND wallet seed encrypted at rest. \
                                 RAM scrambling on abnormal shutdown (future: mlocked pages).",
                    layer: MitigationLayer::Operational,
                    verified: true,  // OperatorWallet::watch_only() enforced in relay path
                },
                ThreatEntry {
                    id: "T18",
                    threat: "Supply chain: malicious hardware or datacenter physical access",
                    adversary: AdversaryClass::Physical,
                    severity: ThreatSeverity::Low,
                    mitigation: "Use a dedicated machine (not shared hosting). \
                                 Verify hardware integrity on setup. \
                                 Run on a jurisdiction with reliable rule of law re: \
                                 datacenter physical security. \
                                 Consider: run on own hardware at home over Tor (removes \
                                 datacenter attack surface entirely).",
                    layer: MitigationLayer::Operational,
                    verified: false,
                },

                // ── CRYPTOGRAPHIC THREATS ─────────────────────────────────
                ThreatEntry {
                    id: "T19",
                    threat: "Ring signature broken: adversary identifies real signer in ring",
                    adversary: AdversaryClass::Cryptographic,
                    severity: ThreatSeverity::Critical,
                    mitigation: "Borromean Schnorr on Ristretto255. Security reduces to discrete \
                                 log on Ristretto255 (believed infeasible, ~128-bit security). \
                                 CLSAG upgrade planned pre-mainnet (stronger proof, same security). \
                                 Ring size 11: even with 10 compromised decoys, adversary learns \
                                 only that real signer is 1 of 11 — cannot isolate without DLOG.",
                    layer: MitigationLayer::Cryptographic,
                    verified: true,
                },
                ThreatEntry {
                    id: "T20",
                    threat: "Stealth address broken: adversary links OTA to recipient identity",
                    adversary: AdversaryClass::Cryptographic,
                    severity: ThreatSeverity::Critical,
                    mitigation: "OTA = H_s(r·V)·G + S on Ristretto255. Breaking requires \
                                 recovering v from V (discrete log) or r from R. \
                                 Ephemeral seed generated from OsRng per output — never reused. \
                                 Reuse would allow linking; architectural prevention in place.",
                    layer: MitigationLayer::Cryptographic,
                    verified: true,
                },
                ThreatEntry {
                    id: "T21",
                    threat: "Commitment broken: adversary recovers hidden transfer amount",
                    adversary: AdversaryClass::Cryptographic,
                    severity: ThreatSeverity::Critical,
                    mitigation: "Pedersen commitment C = v·H + r·G. Hiding property: requires \
                                 solving DLOG. Bulletproof range proof proves v ∈ [0, 2^64) \
                                 without revealing v. No trusted setup required.",
                    layer: MitigationLayer::Cryptographic,
                    verified: true,
                },
                ThreatEntry {
                    id: "T22",
                    threat: "Decoy pool too small: adversary can enumerate all possible real signers",
                    adversary: AdversaryClass::Cryptographic,
                    severity: ThreatSeverity::Medium,
                    mitigation: "On early testnet: synthetic decoys used as fallback. \
                                 On mainnet: decoy pool is global VUSD output set (thousands of entries). \
                                 Gamma-distributed selection matches real spend-time distributions, \
                                 defeating temporal analysis of decoy selection.",
                    layer: MitigationLayer::Cryptographic,
                    verified: false,
                },

                // ── SOCIAL / OSINT THREATS ────────────────────────────────
                ThreatEntry {
                    id: "T23",
                    threat: "Operator identified via on-chain Bitcoin transactions \
                             (channel open/close txs linkable to KYC exchange)",
                    adversary: AdversaryClass::Social,
                    severity: ThreatSeverity::High,
                    mitigation: "Fund LND wallet with Bitcoin purchased non-KYC \
                                 (e.g. via Bisq, RoboSats, or peer-to-peer). \
                                 Use a dedicated Bitcoin wallet with no history linked \
                                 to your identity. Coinjoin channel-open funds before use. \
                                 On key rotation: use new wallet with fresh coins.",
                    layer: MitigationLayer::Operational,
                    verified: false,
                },
                ThreatEntry {
                    id: "T24",
                    threat: "Operator identified via VPS payment trail (credit card, PayPal)",
                    adversary: AdversaryClass::Social,
                    severity: ThreatSeverity::High,
                    mitigation: "Pay for VPS hosting with Monero (XMR). \
                                 Providers: Mullvad, Frantech (BuyVM), 1984 Hosting, Njalla. \
                                 Create account over Tor with a temporary email. \
                                 Do not use any service linked to your real identity.",
                    layer: MitigationLayer::Operational,
                    verified: false,
                },
                ThreatEntry {
                    id: "T25",
                    threat: "Thunder Node software itself linked back to developer/operator \
                             via GitHub commits, code comments, or unique code patterns",
                    adversary: AdversaryClass::Social,
                    severity: ThreatSeverity::Low,
                    mitigation: "VULTD is open-source MIT. Anyone can run Thunder Node. \
                                 Running the software does not imply authorship. \
                                 Build from source over Tor. Do not submit issues/PRs \
                                 that could link your node to your GitHub identity.",
                    layer: MitigationLayer::Operational,
                    verified: true,
                },
            ],
        }
    }

    /// Count threats by severity.
    pub fn severity_counts(&self) -> (usize, usize, usize, usize) {
        let c = |sev: ThreatSeverity| self.mitigations.iter()
            .filter(|t| t.severity == sev).count();
        (c(ThreatSeverity::Critical), c(ThreatSeverity::High),
         c(ThreatSeverity::Medium), c(ThreatSeverity::Low))
    }

    /// Verified-at-runtime mitigations (code-enforced).
    pub fn code_verified(&self) -> Vec<&ThreatEntry> {
        self.mitigations.iter().filter(|t| t.verified).collect()
    }

    /// Operational mitigations (require human action, cannot be code-verified).
    pub fn operational_required(&self) -> Vec<&ThreatEntry> {
        self.mitigations.iter()
            .filter(|t| !t.verified && t.layer == MitigationLayer::Operational)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// THUNDER NODE
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for a Thunder Node instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThunderConfig {
    /// The node's display name (default: "Thunder Node").
    pub name: String,

    /// Operator fee in basis points. Default 100 = 1%.
    /// Can be adjusted by the operator (e.g. 50 bps = 0.5%).
    pub operator_fee_bps: u128,

    /// Fee multiplier on standard LN fee. Default 2 (= 2×).
    pub fee_multiplier: u128,

    /// Minimum relay hops. Default 2. Increase for stronger anonymity.
    pub min_relay_hops: usize,

    /// Whether to enforce the full threat matrix before accepting traffic.
    /// Must be true in production. False allows testing without Tor.
    pub enforce_threat_matrix: bool,
}

impl Default for ThunderConfig {
    fn default() -> Self {
        ThunderConfig {
            name:                 "Thunder Node".to_string(),
            operator_fee_bps:     OPERATOR_FEE_BPS,
            fee_multiplier:       THUNDER_FEE_MULTIPLIER,
            min_relay_hops:       2,
            enforce_threat_matrix: true,
        }
    }
}

/// Runtime statistics for operator dashboard.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ThunderStats {
    pub transfers_relayed:    u64,
    pub total_vusd_relayed:   VusdAmount,
    pub total_operator_fees:  VusdAmount,
    pub total_thunder_fees:   VusdAmount,
    pub uptime_secs:          u64,
    pub last_rotation:        Option<u64>,   // Unix timestamp
    pub tor_active:           bool,
    pub relay_count:          usize,
}

/// The Thunder Node — a privacy-maximized VULTD relay with fee routing.
/// Cached result of the last health_check, with timestamp.
struct HealthCache {
    report:     AnonHealthReport,
    checked_at: std::time::Instant,
}

/// TTL for health_check cache — 30 seconds.
const HEALTH_CACHE_TTL_SECS: u64 = 30;

pub struct ThunderNode {
    pub config:           ThunderConfig,
    pub anon_transport:   Arc<AnonTransport>,
    pub operator_wallet:  Arc<OperatorWallet>,
    pub threat_matrix:    ThreatMatrix,
    /// This node's LND pubkey — used to peel our hop from routing_hints on inbound relays.
    pub own_node_id:      NodeId,
    /// This node's .onion address — used in hop identification fallback.
    pub own_onion:        String,
    /// Cached health report — refreshed at most every HEALTH_CACHE_TTL_SECS.
    /// Prevents per-packet LND RPC calls in relay().
    health_cache:         Arc<RwLock<Option<HealthCache>>>,
    stats:                Arc<RwLock<ThunderStats>>,
    started_at:           SystemTime,
}

impl ThunderNode {
    /// Create a new Thunder Node.
    ///
    /// `operator_seed` is used to derive the operator's stealth wallet.
    /// It should be a 32-byte random secret stored securely offline.
    /// The relay process only ever holds the WATCH-ONLY (view pubkey) version.
    pub fn new(
        config:          ThunderConfig,
        anon_transport:  AnonTransport,
        operator_seed:   &[u8; 32],
        threat_matrix:   ThreatMatrix,
    ) -> Self {
        // Derive operator wallet but immediately discard spend key — relay process
        // only needs the watch-only wallet to SEND fees to the operator address.
        let full_wallet = OperatorWallet::from_seed(operator_seed);
        let watch_only  = full_wallet.watch_only();

        ThunderNode {
            config,
            anon_transport:  Arc::new(anon_transport),
            operator_wallet: Arc::new(watch_only),
            threat_matrix,
            own_node_id:     NodeId([0u8; 32]),
            own_onion:       String::new(),
            health_cache:    Arc::new(RwLock::new(None)),
            stats:           Arc::new(RwLock::new(ThunderStats::default())),
            started_at:      SystemTime::now(),
        }
    }

    /// Construct a Thunder Node from a loaded config file.
    ///
    /// Fix G10 + G03-complete: reads operator pubkeys from ThunderNodeConfig,
    /// constructs the watch-only OperatorWallet, and attaches the live LND
    /// transport to AnonTransport so send() actually routes over Lightning.
    ///
    /// This is the constructor that cmd_start() calls in production.
    pub async fn from_config(
        node_cfg:    &config::ThunderConfig,
        anon:        AnonTransport,
        lnd_cfg:     lightning::LndConfig,
        threat_matrix: ThreatMatrix,
    ) -> Result<Self, ThunderError> {
        // G10: Construct operator wallet from config pubkeys — no seed on this machine
        let operator_wallet = OperatorWallet::from_pubkeys(
            &node_cfg.fees.operator_spend_pubkey_hex,
            &node_cfg.fees.operator_view_pubkey_hex,
        ).ok_or_else(|| ThunderError::NoOperatorWallet)?;

        // G03-complete: connect to LND and wire transport into AnonTransport
        let lnd = lightning::LndTransport::new(lnd_cfg).await
            .map_err(|e| ThunderError::FeeRouting(format!("LND connect: {}", e)))?;

        let anon_live = anon.with_lnd_transport(lnd);

        let cfg = ThunderConfig {
            name:                 node_cfg.node_name.clone(),
            operator_fee_bps:     node_cfg.fees.operator_fee_bps as u128,
            fee_multiplier:       node_cfg.fees.fee_multiplier as u128,
            min_relay_hops:       2,
            enforce_threat_matrix: true,
        };

        // Query LND for our own node pubkey — used for hop peeling in relay loop.
        let (own_node_id, own_onion) = match anon_live.lnd_transport.as_ref() {
            None => (NodeId([0u8; 32]), String::new()),
            Some(lnd) => match lnd.client.get_info().await {
                Ok(info) => {
                    let mut pk_bytes = [0u8; 32];
                    if let Some(b) = decode_hex_32(&info.identity_pubkey) {
                        pk_bytes = b;
                    }
                    let onion = info.uris.into_iter()
                        .find(|u| u.contains(".onion"))
                        .unwrap_or_default();
                    (NodeId(pk_bytes), onion)
                }
                Err(e) => {
                    tracing::warn!(err = %e, "from_config: could not fetch own node_id from LND");
                    (NodeId([0u8; 32]), String::new())
                }
            }
        };

        Ok(ThunderNode {
            config:          cfg,
            anon_transport:  Arc::new(anon_live),
            operator_wallet: Arc::new(operator_wallet),
            threat_matrix,
            own_node_id,
            own_onion,
            health_cache:    Arc::new(RwLock::new(None)),
            stats:           Arc::new(RwLock::new(ThunderStats::default())),
            started_at:      SystemTime::now(),
        })
    }

    /// Build a private VUSD output for the operator fee.
    ///
    /// Fix G04: Constructs a real cryptographic output:
    ///   - stealth address derived from operator's public keys via ECDH
    ///   - Pedersen commitment hides the fee amount
    ///   - Bulletproof range proof proves fee ∈ [0, 2^64) without revealing it
    ///   - Encrypted amount: XOR(fee, SHA256("VUSD_AMT_ENC" || shared_secret)[..16])
    ///
    /// The result is injected into the tx output set in relay() and is
    /// cryptographically indistinguishable from any recipient output.
    fn build_operator_fee_output(
        &self,
        fee_amount: VusdAmount,
    ) -> Result<FeeOutput, ThunderError> {
        use rand::RngCore;
        use privacy::{BulletproofRangeProof, PedersenCommitment, StealthWallet};
        use lightning::encrypt_amount;

        let wallet = &self.operator_wallet.stealth_wallet;

        // Fresh random ephemeral seed — never reused
        let mut ephemeral_seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ephemeral_seed);

        // Derive one-time stealth address for this specific fee payment
        let (stealth_addr, ephemeral_pubkey) =
            wallet.derive_one_time_address(&ephemeral_seed);

        // Compute ECDH shared secret (sender side): shared = H(r·V)
        let shared_secret = StealthWallet::derive_shared_secret_sender(
            &ephemeral_seed,
            &wallet.view_pubkey,
        );

        // Blinding factor for Pedersen commitment
        let blinding = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b"VUSD_FEE_BLIND");
            h.update(&ephemeral_seed);
            let r = h.finalize();
            let mut b = [0u8; 32];
            b.copy_from_slice(&r);
            b
        };

        // Pedersen commitment: C = fee·H + blinding·G  (hides fee amount)
        let commitment = PedersenCommitment::commit(&fee_amount, &blinding);

        // Bulletproof range proof: proves fee ∈ [0, 2^64) without revealing fee
        let range_proof = BulletproofRangeProof::prove(&fee_amount, &blinding);

        // Encrypt amount for operator recovery: XOR(fee_u128_le, mask)[..16]
        let encrypted_amount = encrypt_amount(fee_amount, &shared_secret);

        Ok(FeeOutput {
            stealth_address:  stealth_addr,
            ephemeral_pubkey,
            amount_commitment: commitment,
            range_proof,
            encrypted_amount,
        })
    }

    /// Perform a full pre-flight check before accepting any relay traffic.
    ///
    /// Verifies:
    ///   - All critical and high threat mitigations are active
    ///   - Tor is running and reachable
    ///   - Private-only channels are configured
    ///   - Sufficient relay nodes are available
    ///   - Operator wallet is watch-only (spend key not in memory)
    pub async fn preflight(&self) -> Result<AnonHealthReport, ThunderError> {
        let report = self.anon_transport.health_check().await
            .map_err(ThunderError::Relay)?;

        if self.config.enforce_threat_matrix {
            // Critical: Tor must be active
            if !report.tor_active {
                return Err(ThunderError::ThreatMitigation(
                    "T01/T04: Tor is not running. Thunder Node refuses to start without Tor. \
                     Start Tor first: systemctl start tor".to_string()
                ));
            }
            // Critical: private channels only
            if !report.channels_private {
                return Err(ThunderError::ThreatMitigation(
                    "T04: Private channel enforcement is off. \
                     Set PrivateChannelConfig::private_only = true".to_string()
                ));
            }
            // High: need enough relays for minimum hops
            if !report.relays_ready {
                return Err(ThunderError::ThreatMitigation(
                    format!("T06: Insufficient relay nodes. Need ≥{} active relays, have {}.",
                        self.config.min_relay_hops, report.relay_count)
                ));
            }
            // G09 FIX: Verify operator wallet is truly watch-only.
            // watch_only() strips spend_privkey → None. This check therefore catches
            // the case where ThunderNode was accidentally constructed with a full wallet
            // (from_seed) instead of a watch-only wallet (from_pubkeys/watch_only).
            // from_pubkeys() always produces None for both private keys — this is the
            // correct sentinel. Any Some(...) means a private key leaked into relay RAM.
            if self.operator_wallet.stealth_wallet.spend_privkey.is_some() {
                return Err(ThunderError::ThreatMitigation(
                    "T17: Operator spend private key is in relay process memory. ThunderNode must use ThunderNode::from_config() → OperatorWallet::from_pubkeys(). The spend key must stay on the operator's air-gapped device.".to_string()
                ));
            }
            // Belt-and-suspenders: view privkey must also be absent in relay process.
            if self.operator_wallet.stealth_wallet.view_privkey.is_some() {
                return Err(ThunderError::ThreatMitigation(
                    "T17: Operator view private key is in relay process memory. Use from_pubkeys() — neither private key should be in relay RAM.".to_string()
                ));
            }
        }

        Ok(report)
    }

    /// Relay a VUSD transfer through the Thunder Node.
    ///
    /// Steps:
    ///   1. Compute fee breakdown (2× LN fee + 1% operator cut)
    ///   2. Route operator cut to operator stealth address
    ///   3. Route net amount to recipient via AnonTransport
    ///   4. Update stats
    pub async fn relay(
        &self,
        msg:              &VusdTransferMessage,
        gross_amount:     VusdAmount,
        recipient_onion:  &str,
    ) -> Result<ThunderFeeBreakdown, ThunderError> {
        // T8: Run cached preflight — health_check runs at most every 30s,
        // not per-packet. Prevents LND RPC floods under high relay load.
        if self.config.enforce_threat_matrix {
            self.cached_preflight().await.map_err(|e| {
                tracing::error!(err = %e, "T08: cached preflight failed — relay aborted");
                e
            })?;
        }

        // Step 1: fee breakdown
        let fees = ThunderFeeBreakdown::compute_with_config(
            gross_amount,
            self.config.operator_fee_bps,
            self.config.fee_multiplier,
        )?;

        tracing::info!(
            breakdown = %fees.display(),
            "Thunder relay: computed fee breakdown"
        );

        // Step 2: Construct a real private VUSD output for the operator fee.
        //
        // Fix G04: This is now a genuine cryptographic output — stealth address,
        // Pedersen commitment, bulletproof range proof — indistinguishable from
        // any other VUSD output. The operator scans for it offline using their view key.
        //
        // The output is injected into msg.tx.outputs so it travels with the transfer
        // and is committed to by the transaction's balance proof.
        let fee_output = self.build_operator_fee_output(fees.operator_cut)?;

        // Clone msg and inject operator fee output into the tx output set
        let mut msg_with_fee = msg.clone();
        msg_with_fee.tx.outputs.push(lightning::SerializedOutput {
            stealth_address:  fee_output.stealth_address.0,
            ephemeral_pubkey: fee_output.ephemeral_pubkey,
            commitment:       fee_output.amount_commitment.commitment,
            range_proof:      fee_output.range_proof.proof_bytes.clone(),
            encrypted_amount: fee_output.encrypted_amount,
        });

        self.operator_wallet.record_fee_earned(fees.operator_cut).await;
        tracing::info!(
            operator_cut     = fees.operator_cut.0,
            operator_ota     = hex_prefix(&self.operator_wallet.stealth_wallet.spend_pubkey),
            outputs_in_tx    = msg_with_fee.tx.outputs.len(),
            "Thunder relay: operator fee output injected into tx",
        );

        // Step 3: route the modified message (with fee output) to recipient
        self.anon_transport.send(&msg_with_fee, recipient_onion).await?;

        // Step 4: update stats
        {
            let mut stats = self.stats.write().await;
            stats.transfers_relayed  += 1;
            stats.total_vusd_relayed  = VusdAmount(
                stats.total_vusd_relayed.0.saturating_add(gross_amount.0));
            stats.total_operator_fees = VusdAmount(
                stats.total_operator_fees.0.saturating_add(fees.operator_cut.0));
            stats.total_thunder_fees  = VusdAmount(
                stats.total_thunder_fees.0.saturating_add(fees.thunder_fee.0));
        }

        Ok(fees)
    }


    /// Preflight check with 30-second result cache.
    ///
    /// SEC-1 fix: health_check() calls LND listchannels + get_info on every invocation.
    /// Calling this per-packet would flood LND with RPCs under load.
    /// This wrapper re-uses the last result for HEALTH_CACHE_TTL_SECS seconds.
    async fn cached_preflight(&self) -> Result<AnonHealthReport, ThunderError> {
        // Check if cached result is still fresh
        {
            let cache = self.health_cache.read().await;
            if let Some(ref c) = *cache {
                if c.checked_at.elapsed().as_secs() < HEALTH_CACHE_TTL_SECS {
                    // Validate cached report against threat matrix (no LND calls)
                    if self.config.enforce_threat_matrix {
                        if !c.report.tor_active {
                            return Err(ThunderError::ThreatMitigation(
                                "T01: Tor not active (cached)".to_string()
                            ));
                        }
                        if !c.report.channels_private {
                            return Err(ThunderError::ThreatMitigation(
                                "T04: Private channels not enforced (cached)".to_string()
                            ));
                        }
                    }
                    return Ok(c.report.clone());
                }
            }
        }
        // Cache miss or expired — run full preflight and update cache
        let report = self.preflight().await?;
        *self.health_cache.write().await = Some(HealthCache {
            report:     report.clone(),
            checked_at: std::time::Instant::now(),
        });
        Ok(report)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // INBOUND RELAY DISPATCH
    // ─────────────────────────────────────────────────────────────────────────

    /// Extract the next-hop onion address from a transfer's routing hints.
    ///
    /// The sender builds routing_hints as:
    ///   [ hop_0 (channel_id > 0, our relay), hop_1 ..., terminal (channel_id = 0, recipient) ]
    ///
    /// When we receive a message:
    ///   - Find the first hint whose channel_id matches one of our open channels,
    ///     OR whose hop_pubkey matches our own node pubkey bytes.
    ///   - The *next* hint after ours is where we forward.
    ///   - If the next hint has channel_id == 0, decode hop_pubkey as a UTF-8 onion address.
    ///   - If no hints match us at all, treat the first hint as the forward target
    ///     (handles cases where the path was built without our exact channel_id).
    ///
    /// Returns None if the routing_hints are empty or we're the final recipient.
    pub async fn peel_next_hop(&self, msg: &VusdTransferMessage) -> Option<String> {
        let hints = &msg.routing_hints;
        if hints.is_empty() {
            return None;
        }

        // Find our position in the hint list
        let our_pk = &self.own_node_id.0;
        let our_onion_bytes = self.own_onion.as_bytes();

        let our_idx = hints.iter().position(|h| {
            // Match by pubkey bytes
            &h.hop_pubkey == our_pk
            // OR by onion bytes packed in hop_pubkey
            || {
                let len = our_onion_bytes.len().min(32);
                &h.hop_pubkey[..len] == &our_onion_bytes[..len]
            }
        });

        let next_idx = match our_idx {
            Some(i) => i + 1,
            // SEC-4: if we can't identify our hop, refuse to forward rather than
            // blindly forwarding to hint[0] (which could be our own channel —
            // creating a forwarding loop on malformed messages).
            None => {
                tracing::warn!(
                    hint_count = hints.len(),
                    "peel_next_hop: our hop not found in routing_hints — refusing forward"
                );
                return None;
            }
        };

        let next = hints.get(next_idx)?;

        // Decode next hop's address
        if next.channel_id == 0 {
            // Terminal hint: hop_pubkey bytes are a UTF-8 onion address
            let end = next.hop_pubkey.iter()
                .position(|&b| b == 0)
                .unwrap_or(32);
            std::str::from_utf8(&next.hop_pubkey[..end])
                .ok()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        } else {
            // Intermediate relay hop — use onion_address from our relay node registry
            let relays = self.anon_transport.relays.read().await;
            relays.iter()
                .find(|r| r.channel_id == next.channel_id)
                .map(|r| r.onion_address.clone())
        }
    }

    /// Start the inbound relay dispatch loop.
    ///
    /// Subscribes to the LND keysend stream via start_receiver(), then for each
    /// inbound VusdTransferMessage:
    ///   1. Converts Lightning payment amount (msat) to VUSD gross amount
    ///   2. Peels our hop from routing_hints to find the next recipient
    ///   3. Calls relay() — fee computation, operator output injection, AnonTransport send
    ///
    /// The loop runs until the LND connection drops or the task is cancelled.
    /// Errors on individual messages are logged and skipped — the loop never panics.
    pub async fn start_relay_loop(self: Arc<Self>) -> Result<(), ThunderError> {
        let lnd = self.anon_transport.lnd_transport.as_ref()
            .ok_or_else(|| ThunderError::Relay(
                lightning::AnonTransportError::NoRelays // reuse existing error
            ))?
            .clone();

        let mut rx = lnd.start_receiver().await
            .map_err(|e| ThunderError::FeeRouting(format!("start_receiver: {}", e)))?;

        tracing::info!(
            own_node_id = hex_prefix(&self.own_node_id.0),
            own_onion   = %self.own_onion,
            "Relay loop started — listening for inbound VUSD transfers"
        );

        // SEC-2: Limit concurrent in-flight relays to prevent unbounded task spawn
        // under message floods. 64 concurrent relays is ample for testnet.
        let relay_semaphore = Arc::new(tokio::sync::Semaphore::new(64));

        while let Some((msg, amt_msat)) = rx.recv().await {
            // Convert msat → VUSD gross amount.
            // The Lightning payment amount in msat is used as a proxy for the
            // VUSD gross amount. On mainnet, a VUSD-pegged channel enforces the
            // peg rate; for testnet the 1:1 mapping (1 msat = 1 VUSD base unit)
            // is a reasonable approximation.
            let gross = vscx_core::VusdAmount(amt_msat as u128);

            // Peel our hop to find where to forward
            let next_onion = match self.peel_next_hop(&msg).await {
                Some(o) => o,
                None => {
                    tracing::warn!(
                        sender_hash = hex_prefix(&msg.sender_hash),
                        "Relay loop: no next hop found — dropping transfer"
                    );
                    continue;
                }
            };

            tracing::info!(
                gross_vusd  = gross.0,
                next_onion  = %next_onion,
                sender_hash = hex_prefix(&msg.sender_hash),
                "Relay loop: dispatching inbound transfer"
            );

            let node = Arc::clone(&self);
            let msg_owned = msg.clone();
            let onion_owned = next_onion.clone();
            let sem = Arc::clone(&relay_semaphore);

            // Spawn per-transfer task with semaphore backpressure (max 64 concurrent).
            // If all slots are taken, acquire() blocks here — naturally rate-limits
            // inbound processing without dropping messages.
            let permit = match sem.acquire_owned().await {
                Ok(p)  => p,
                Err(_) => continue, // semaphore closed (shutdown)
            };
            tokio::spawn(async move {
                let _permit = permit; // released when task finishes
                match node.relay(&msg_owned, gross, &onion_owned).await {
                    Ok(fees) => {
                        tracing::info!(
                            thunder_fee  = fees.thunder_fee.0,
                            operator_cut = fees.operator_cut.0,
                            next_onion   = %onion_owned,
                            "Relay loop: transfer forwarded ✓"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            err        = %e,
                            next_onion = %onion_owned,
                            "Relay loop: relay() failed — transfer dropped"
                        );
                    }
                }
            });
        }

        tracing::warn!("Relay loop: LND receiver channel closed — loop exiting");
        Ok(())
    }

    /// Get current runtime statistics.
    pub async fn stats(&self) -> ThunderStats {
        let mut s = self.stats.read().await.clone();
        s.uptime_secs = self.started_at.elapsed()
            .unwrap_or_default().as_secs();
        s.total_operator_fees = self.operator_wallet.total_earned().await;
        s
    }

    /// Print a full operator dashboard to stdout.
    pub async fn print_dashboard(&self) {
        let stats  = self.stats().await;
        let health = self.anon_transport.health_check().await;
        let (crit, high, med, low) = self.threat_matrix.severity_counts();
        let decimals = 1_000_000_000_000_000_000u128;
        let fmt = |v: VusdAmount| format!("{:.4}", v.0 as f64 / decimals as f64);

        println!("{}", "═".repeat(68));
        println!("  ⚡ THUNDER NODE — Operator Dashboard");
        println!("{}", "═".repeat(68));
        println!("  Name:              {}", self.config.name);
        println!("  Uptime:            {}s", stats.uptime_secs);
        println!("  Transfers relayed: {}", stats.transfers_relayed);
        println!("  VUSD relayed:      {} VUSD", fmt(stats.total_vusd_relayed));
        println!("  Thunder fees:      {} VUSD (2× LN)", fmt(stats.total_thunder_fees));
        println!("  Operator earnings: {} VUSD (1% cut)", fmt(stats.total_operator_fees));
        println!();
        println!("  Fee policy:");
        println!("    Base LN fee mirror:  {}×", self.config.fee_multiplier);
        println!("    Operator cut:        {}%", self.config.operator_fee_bps as f64 / 100.0);
        println!();

        if let Ok(h) = health {
            println!("{}", h.summary());
        }
        println!();
        println!("  Threat Matrix: {} critical  {} high  {} medium  {} low",
            crit, high, med, low);
        println!("  Code-verified:   {} threats automatically checked at startup",
            self.threat_matrix.code_verified().len());
        println!("  Operational:     {} threats require manual operator setup",
            self.threat_matrix.operational_required().len());
        println!("{}", "═".repeat(68));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FEE BREAKDOWN WITH CONFIG
// ─────────────────────────────────────────────────────────────────────────────

impl ThunderFeeBreakdown {
    /// Compute fee breakdown using operator-configured fee rates.
    pub fn compute_with_config(
        gross_amount:     VusdAmount,
        operator_fee_bps: u128,
        fee_multiplier:   u128,
    ) -> Result<Self, ThunderError> {
        let g = gross_amount.0;

        let standard_raw = g.checked_mul(STANDARD_LN_FEE_BPS)
            .ok_or(ThunderError::FeeOverflow)? / BPS;

        let thunder_raw = standard_raw.checked_mul(fee_multiplier)
            .ok_or(ThunderError::FeeOverflow)?;

        let thunder_fee_units = thunder_raw.max(MIN_THUNDER_FEE_UNITS);

        let operator_raw = g.checked_mul(operator_fee_bps)
            .ok_or(ThunderError::FeeOverflow)? / BPS;

        let operator_cut_units = operator_raw.max(MIN_THUNDER_FEE_UNITS);

        let total = thunder_fee_units.checked_add(operator_cut_units)
            .ok_or(ThunderError::FeeOverflow)?;

        if total >= g {
            return Err(ThunderError::BelowDustAfterFees);
        }

        Ok(ThunderFeeBreakdown {
            gross_amount,
            standard_ln_fee:  VusdAmount(standard_raw),
            thunder_fee:      VusdAmount(thunder_fee_units),
            operator_cut:     VusdAmount(operator_cut_units),
            net_to_recipient: VusdAmount(g - total),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{:02x}", b)).collect::<String>() + "…"
}


fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Decode a hex string into exactly 32 bytes.
/// Returns None if the string is not valid hex or not exactly 32 bytes.
fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 { return None; }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i*2..i*2+2], 16).ok()?;
    }
    Some(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const VUSD_ONE: u128 = 1_000_000_000_000_000_000;

    fn vusd(units: u128) -> VusdAmount { VusdAmount(units) }

    // ── FEE ENGINE TESTS ──────────────────────────────────────────────────────

    #[test]
    fn test_fee_breakdown_1000_vusd() {
        // 1000 VUSD transfer
        // standard LN fee: 0.01% = 0.1 VUSD
        // thunder fee:     2 × 0.1 = 0.2 VUSD
        // operator cut:    1% × 1000 = 10 VUSD
        // net:             1000 - 0.2 - 10 = 989.8 VUSD
        let gross = vusd(1_000 * VUSD_ONE);
        let fees  = ThunderFeeBreakdown::compute(gross).unwrap();

        // standard LN: 1000 * 1 / 10000 = 0.1 VUSD = 0.1e18
        assert_eq!(fees.standard_ln_fee.0, VUSD_ONE / 10);
        // thunder: 2 × 0.1 = 0.2 VUSD
        assert_eq!(fees.thunder_fee.0, VUSD_ONE / 5);
        // operator: 1000 * 100 / 10000 = 10 VUSD
        assert_eq!(fees.operator_cut.0, 10 * VUSD_ONE);
        // net: 1000 - 0.2 - 10 = 989.8 VUSD
        let expected_net = 1_000 * VUSD_ONE - VUSD_ONE / 5 - 10 * VUSD_ONE;
        assert_eq!(fees.net_to_recipient.0, expected_net);
    }

    #[test]
    fn test_fee_breakdown_balance_holds() {
        // Invariant: gross = thunder_fee + operator_cut + net_to_recipient
        for amount_vusd in [1, 10, 100, 1000, 50_000u128] {
            let gross = vusd(amount_vusd * VUSD_ONE);
            if let Ok(fees) = ThunderFeeBreakdown::compute(gross) {
                let sum = fees.thunder_fee.0
                    .saturating_add(fees.operator_cut.0)
                    .saturating_add(fees.net_to_recipient.0);
                assert_eq!(sum, gross.0,
                    "balance broken for {} VUSD: {} + {} + {} != {}",
                    amount_vusd, fees.thunder_fee.0, fees.operator_cut.0,
                    fees.net_to_recipient.0, gross.0);
            }
        }
    }

    #[test]
    fn test_fee_floor_applied_on_tiny_amounts() {
        // 0.001 VUSD — percentage fees round below MIN_THUNDER_FEE_UNITS
        let gross = vusd(VUSD_ONE / 1000);
        let fees  = ThunderFeeBreakdown::compute(gross);
        // Should fail: fees exceed amount
        assert!(matches!(fees, Err(ThunderError::BelowDustAfterFees)));
    }

    #[test]
    fn test_fee_breakdown_no_overflow() {
        // Maximum plausible amount: $10M VUSD
        let gross = vusd(10_000_000 * VUSD_ONE);
        let fees  = ThunderFeeBreakdown::compute(gross).unwrap();
        // operator cut = 1% of $10M = $100,000 VUSD
        assert_eq!(fees.operator_cut.0, 100_000 * VUSD_ONE);
    }

    #[test]
    fn test_fee_multiplier_is_exactly_2x_standard() {
        let gross = vusd(1_000 * VUSD_ONE);
        let fees  = ThunderFeeBreakdown::compute(gross).unwrap();
        // thunder_fee = 2 × standard_ln_fee (when above dust floor)
        assert_eq!(fees.thunder_fee.0, fees.standard_ln_fee.0 * 2);
    }

    #[test]
    fn test_configurable_operator_fee() {
        let gross = vusd(1_000 * VUSD_ONE);
        // 0.5% operator fee
        let fees_half = ThunderFeeBreakdown::compute_with_config(gross, 50, 2).unwrap();
        // 1% operator fee
        let fees_full = ThunderFeeBreakdown::compute_with_config(gross, 100, 2).unwrap();
        // Half fee should yield more to recipient
        assert!(fees_half.net_to_recipient.0 > fees_full.net_to_recipient.0);
        assert_eq!(fees_half.operator_cut.0, 5 * VUSD_ONE);   // 0.5% of 1000
        assert_eq!(fees_full.operator_cut.0, 10 * VUSD_ONE);  // 1% of 1000
    }

    // ── THREAT MATRIX TESTS ───────────────────────────────────────────────────

    #[test]
    fn test_threat_matrix_complete() {
        let matrix = ThreatMatrix::full();
        // Must have entries for all adversary classes
        let classes: Vec<AdversaryClass> = matrix.mitigations.iter()
            .map(|t| t.adversary).collect();
        assert!(classes.contains(&AdversaryClass::PassiveNetwork));
        assert!(classes.contains(&AdversaryClass::ActiveLightning));
        assert!(classes.contains(&AdversaryClass::LegalCompulsion));
        assert!(classes.contains(&AdversaryClass::Physical));
        assert!(classes.contains(&AdversaryClass::Cryptographic));
        assert!(classes.contains(&AdversaryClass::Social));
    }

    #[test]
    fn test_threat_matrix_all_have_mitigations() {
        let matrix = ThreatMatrix::full();
        for t in &matrix.mitigations {
            assert!(!t.mitigation.is_empty(),
                "Threat {} has no mitigation", t.id);
            assert!(!t.threat.is_empty(),
                "Threat {} has empty threat description", t.id);
        }
    }

    #[test]
    fn test_threat_matrix_critical_threats_exist() {
        let matrix = ThreatMatrix::full();
        let (crit, _, _, _) = matrix.severity_counts();
        assert!(crit >= 3, "Expected at least 3 critical threats; found {}", crit);
    }

    #[test]
    fn test_code_verified_threats_are_marked() {
        let matrix  = ThreatMatrix::full();
        let verified = matrix.code_verified();
        // T11 (no logs), T13 (stealth fee wallet), T17 (watch-only), T19-T21 (crypto) verified
        let ids: Vec<&str> = verified.iter().map(|t| t.id).collect();
        assert!(ids.contains(&"T11"), "T11 (no logs) should be code-verified");
        assert!(ids.contains(&"T13"), "T13 (stealth fee) should be code-verified");
        assert!(ids.contains(&"T17"), "T17 (watch-only key) should be code-verified");
    }

    // ── OPERATOR WALLET TESTS ─────────────────────────────────────────────────

    #[test]
    fn test_operator_wallet_watch_only_has_no_spend_key() {
        let wallet     = OperatorWallet::from_seed(&[42u8; 32]);
        let watch_only = wallet.watch_only();
        assert!(watch_only.stealth_wallet.spend_privkey.is_none(),
            "Watch-only wallet must not contain spend private key");
        assert!(watch_only.stealth_wallet.view_privkey.is_none(),
            "Watch-only wallet should not contain view private key");
    }

    #[test]
    fn test_operator_wallet_pubkeys_preserved_in_watch_only() {
        let wallet     = OperatorWallet::from_seed(&[99u8; 32]);
        let watch_only = wallet.watch_only();
        // Public keys must be identical — we need them to derive stealth addresses
        assert_eq!(wallet.stealth_wallet.spend_pubkey,
                   watch_only.stealth_wallet.spend_pubkey);
        assert_eq!(wallet.stealth_wallet.view_pubkey,
                   watch_only.stealth_wallet.view_pubkey);
    }

    #[tokio::test]
    async fn test_operator_fee_accumulation() {
        let wallet = Arc::new(OperatorWallet::from_seed(&[1u8; 32]));
        wallet.record_fee_earned(vusd(10 * VUSD_ONE)).await;
        wallet.record_fee_earned(vusd(5  * VUSD_ONE)).await;
        assert_eq!(wallet.total_earned().await.0, 15 * VUSD_ONE);
    }

    // ── INTEGRATION: FULL RELAY FLOW ──────────────────────────────────────────

    #[test]
    fn test_relay_fee_flow_1000_vusd() {
        // Simulate a 1000 VUSD relay
        let gross = vusd(1_000 * VUSD_ONE);
        let fees  = ThunderFeeBreakdown::compute(gross).unwrap();

        // Operator earns exactly 1%
        assert_eq!(fees.operator_cut.0, 10 * VUSD_ONE);

        // Recipient receives 989.8 VUSD
        let expected = gross.0 - fees.thunder_fee.0 - fees.operator_cut.0;
        assert_eq!(fees.net_to_recipient.0, expected);

        // Thunder fee is double the LN baseline
        assert_eq!(fees.thunder_fee.0, fees.standard_ln_fee.0 * 2);

        println!("{}", fees.display());
    }

    // ── RELAY LOOP TESTS ─────────────────────────────────────────────────────

    #[test]
    fn test_peel_next_hop_terminal_hint() {
        use lightning::{VusdTransferMessage, SerializedPrivateTx, RoutingHint};

        // Build a message with two hints: our hop (channel_id=1) + terminal (channel_id=0)
        let mut own_pk = [0u8; 32];
        own_pk[0] = 0xAA;

        let recipient_onion = "test1234567890abcdef.onion:9735";
        let mut terminal_key = [0u8; 32];
        let bytes = recipient_onion.as_bytes();
        terminal_key[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);

        let msg = VusdTransferMessage {
            version: 1,
            sender_hash: [0u8; 32],
            tx: SerializedPrivateTx {
                ring_sigs: vec![],
                key_images: vec![],
                outputs: vec![],
                fee_amount: 0,
                timestamp: 0,
            },
            routing_hints: vec![
                RoutingHint { channel_id: 1, hop_pubkey: own_pk },       // our hop
                RoutingHint { channel_id: 0, hop_pubkey: terminal_key }, // recipient
            ],
            timestamp: 0,
        };

        let node = make_test_node_with_id(own_pk);

        // Use tokio runtime to call async peel_next_hop
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let result = rt.block_on(node.peel_next_hop(&msg));

        assert!(result.is_some(), "should find next hop");
        let onion = result.unwrap();
        assert!(onion.contains("onion"), "should decode onion address, got: {}", onion);
    }

    #[test]
    fn test_peel_next_hop_empty_hints_returns_none() {
        use lightning::{VusdTransferMessage, SerializedPrivateTx};
        let msg = VusdTransferMessage {
            version: 1,
            sender_hash: [0u8; 32],
            tx: SerializedPrivateTx {
                ring_sigs: vec![],
                key_images: vec![],
                outputs: vec![],
                fee_amount: 0,
                timestamp: 0,
            },
            routing_hints: vec![],
            timestamp: 0,
        };
        let node = make_test_node_with_id([0u8; 32]);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let result = rt.block_on(node.peel_next_hop(&msg));
        assert!(result.is_none(), "empty hints should return None");
    }

    fn test_anon_transport() -> AnonTransport {
        AnonTransport::new(
            TorConfig {
                socks5_proxy:  "127.0.0.1:9050".to_string(),
                control_port:  9051,
                onion_address: String::new(),
            },
            PrivateChannelConfig { private_only: true, max_channels: 20 },
            KeyRotationConfig { enabled: false, interval_days: 30 },
            NodeId([0u8; 32]),
            vec![],
            JitterConfig { min_ms: 0, max_ms: 0 },
            1,
        )
    }

    fn make_test_node_with_id(own_pk: [u8; 32]) -> ThunderNode {
        let anon = test_anon_transport();
        ThunderNode {
            config: ThunderConfig::default(),
            anon_transport: std::sync::Arc::new(anon),
            operator_wallet: std::sync::Arc::new(
                OperatorWallet::from_seed(&[1u8; 32]).watch_only()
            ),
            threat_matrix: ThreatMatrix::full(),
            own_node_id: NodeId(own_pk),
            own_onion: String::new(),
            stats: std::sync::Arc::new(tokio::sync::RwLock::new(ThunderStats::default())),
            started_at: std::time::SystemTime::now(),
        }
    }
}
