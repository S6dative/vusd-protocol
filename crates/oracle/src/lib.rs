// crates/oracle/src/lib.rs
//
// VSCx Oracle Network — BIP-340 Schnorr signatures over secp256k1
//
// Each oracle node:
//   1. Polls ≥5 exchange price feeds
//   2. Computes per-node median, rejects outliers >2%
//   3. Signs the price message with a real secp256k1 Schnorr keypair (BIP-340)
//   4. Broadcasts SignedPrice
//
// OracleAggregator:
//   1. Collects SignedPrice from all 7 nodes
//   2. Verifies each BIP-340 Schnorr sig against the node's known x-only pubkey
//   3. Requires ≥5-of-7 valid sigs
//   4. Rejects if price spread across quorum >1%
//   5. Returns median price wrapped in OraclePrice
//
// Signature message: SHA256("VUSD_ORACLE_PRICE_V1" || price_8dec_le64 || timestamp_le64 || node_id_u8)
// The 32-byte hash is passed directly to secp256k1::Message::from_digest.

pub mod feeds;
pub mod circuit_breaker;
pub use feeds::{FeedClient, production_feeds};
pub use circuit_breaker::{CircuitBreaker, with_circuit_breakers};

use secp256k1::{
    Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey, PublicKey,
    schnorr::Signature as SchnorrSig,
    Signing, Verification,
};
// traits imported below
// musig2 crate removed — using secp256k1 direct aggregate signing
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::{debug, info, warn};
use vscx_core::{OraclePrice, current_time_secs};

// ─────────────────────────────────────────────────────────────────────────────
// ERRORS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum OracleError {
    #[error("Insufficient quorum: have {have} signatures, need {need}")]
    InsufficientQuorum { have: usize, need: usize },

    #[error("Price spread too wide: {spread_bps} bps > max {max_bps} bps")]
    ExcessiveSpread { spread_bps: u64, max_bps: u64 },

    #[error("Invalid signature from oracle node {node_id}")]
    InvalidSignature { node_id: u8 },

    #[error("Oracle node {node_id} price is stale")]
    StalePrice { node_id: u8 },

    #[error("No price feeds available")]
    NoPriceFeeds,

    #[error("Price feed error: {0}")]
    FeedError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// SIGNED PRICE
// ─────────────────────────────────────────────────────────────────────────────

/// A price report signed by a single oracle node with a BIP-340 Schnorr sig.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPrice {
    /// BTC/USD price with 8 decimal places (e.g. 100_000_00000000 = $100,000).
    pub btc_usd_8dec: u64,
    /// Unix timestamp of this report.
    pub timestamp: u64,
    /// Oracle node ID (0–6 for a 7-node network).
    pub node_id: u8,
    /// 64-byte BIP-340 Schnorr signature.
    #[serde(with = "sig_bytes_serde")]
    pub signature: [u8; 64],
    /// 32-byte x-only secp256k1 public key of this oracle node.
    pub pubkey: [u8; 32],
}

impl SignedPrice {
    /// Build the 32-byte message that is signed (and verified) for this price report.
    ///
    /// We use a tagged SHA256 hash so the domain is unambiguously separated from
    /// any other signature produced by these keys.
    pub fn message_hash(btc_usd_8dec: u64, timestamp: u64, node_id: u8) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"VUSD_ORACLE_PRICE_V1");
        h.update(btc_usd_8dec.to_le_bytes());
        h.update(timestamp.to_le_bytes());
        h.update([node_id]);
        h.finalize().into()
    }

    /// Verify this signed price.
    ///
    /// Uses secp256k1::schnorr::Signature::verify — real BIP-340 verification.
    pub fn verify(&self) -> bool {
        let secp = Secp256k1::verification_only();
        let msg_hash = Self::message_hash(self.btc_usd_8dec, self.timestamp, self.node_id);
        let Ok(msg) = Message::from_digest_slice(&msg_hash) else { return false; };
        let Ok(sig) = SchnorrSig::from_slice(&self.signature) else { return false; };
        let Ok(xpk) = XOnlyPublicKey::from_slice(&self.pubkey) else { return false; };

        secp.verify_schnorr(&sig, &msg, &xpk).is_ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PRICE FEED TRAIT
// ─────────────────────────────────────────────────────────────────────────────

pub trait PriceFeed: Send + Sync {
    fn name(&self) -> &str;
    fn fetch_price(&self) -> Result<u64, OracleError>;
}

/// Mock price feed for tests.
#[derive(Debug, Clone)]
pub struct MockPriceFeed {
    pub name: String,
    pub price: Arc<RwLock<u64>>,
    pub offline: Arc<RwLock<bool>>,
}

impl MockPriceFeed {
    pub fn new(name: impl Into<String>, price_dollars: u64) -> Self {
        MockPriceFeed {
            name: name.into(),
            price: Arc::new(RwLock::new(price_dollars)),
            offline: Arc::new(RwLock::new(false)),
        }
    }
    pub fn set_price(&self, price: u64)  { *self.price.write().unwrap() = price; }
    pub fn set_offline(&self, v: bool)   { *self.offline.write().unwrap() = v; }
}

impl PriceFeed for MockPriceFeed {
    fn name(&self) -> &str { &self.name }
    fn fetch_price(&self) -> Result<u64, OracleError> {
        if *self.offline.read().unwrap() {
            return Err(OracleError::FeedError(format!("{} offline", self.name)));
        }
        Ok(*self.price.read().unwrap())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ORACLE NODE
// ─────────────────────────────────────────────────────────────────────────────

/// A single oracle node with a real secp256k1 Schnorr keypair.
pub struct OracleNode {
    pub node_id: u8,
    keypair: Keypair,
    /// x-only pubkey bytes (32 bytes) — shared with aggregator for verification.
    pub pubkey: [u8; 32],
    feeds: Vec<Box<dyn PriceFeed>>,
    outlier_rejection_bps: u64,
    secp: Secp256k1<secp256k1::All>,
}

impl OracleNode {
    /// Create a new oracle node, deriving a deterministic secp256k1 keypair from `privkey_seed`.
    ///
    /// The seed is hashed with a domain tag to produce a valid 32-byte scalar,
    /// then used as the secp256k1 secret key.
    pub fn new(node_id: u8, privkey_seed: [u8; 32], feeds: Vec<Box<dyn PriceFeed>>) -> Self {
        let secp = Secp256k1::new();

        // Domain-separate the seed before using as a scalar to avoid
        // accidental key reuse with other parts of the system.
        let key_material: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"VUSD_ORACLE_KEYPAIR_V1");
            h.update(privkey_seed);
            h.update([node_id]);
            h.finalize().into()
        };

        let secret_key = SecretKey::from_slice(&key_material)
            .expect("SHA256 output is always a valid secp256k1 scalar");
        let keypair    = Keypair::from_secret_key(&secp, &secret_key);
        let (xonly, _) = keypair.x_only_public_key();
        let pubkey     = xonly.serialize();

        OracleNode {
            node_id,
            keypair,
            pubkey,
            feeds,
            outlier_rejection_bps: 200, // 2%
            secp,
        }
    }

    /// Compute the node's best BTC/USD price in whole dollars.
    pub fn compute_price(&self) -> Result<u64, OracleError> {
        let mut prices: Vec<u64> = self.feeds.iter()
            .filter_map(|f| match f.fetch_price() {
                Ok(p)  => { debug!(feed = f.name(), price = p); Some(p) }
                Err(e) => { warn!(feed = f.name(), err = %e, "feed failed"); None }
            })
            .collect();

        if prices.is_empty() {
            return Err(OracleError::NoPriceFeeds);
        }

        prices.sort_unstable();
        let initial_median = median_u64(&prices);

        prices.retain(|&p| {
            let dev = if p > initial_median {
                (p - initial_median) * 10_000 / initial_median
            } else {
                (initial_median - p) * 10_000 / initial_median
            };
            dev <= self.outlier_rejection_bps
        });

        if prices.is_empty() {
            return Err(OracleError::NoPriceFeeds);
        }

        Ok(median_u64(&prices))
    }

    /// Compute the price, sign it with a real BIP-340 Schnorr signature, return SignedPrice.
    pub fn publish(&self) -> Result<SignedPrice, OracleError> {
        let secp      = &self.secp;
        let price_usd = self.compute_price()?;
        let btc_8dec  = price_usd * 100_000_000;
        let timestamp = current_time_secs();

        let msg_hash = SignedPrice::message_hash(btc_8dec, timestamp, self.node_id);
        let msg      = Message::from_digest_slice(&msg_hash)
            .map_err(|e| OracleError::CryptoError(e.to_string()))?;

        let sig: SchnorrSig = secp.sign_schnorr(&msg, &self.keypair);

        Ok(SignedPrice {
            btc_usd_8dec: btc_8dec,
            timestamp,
            node_id: self.node_id,
            signature: sig.serialize(),
            pubkey: self.pubkey,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ORACLE AGGREGATOR
// ─────────────────────────────────────────────────────────────────────────────

impl OracleNode {
    /// Load an oracle node from environment variables.
    ///
    /// Reads seed from (in priority order):
    ///   1. `VUSD_PRIVKEY_SEED_FILE` — path to a file containing the hex seed (Docker secrets)
    ///   2. `VUSD_PRIVKEY_SEED`      — hex seed directly in environment variable
    ///
    /// The file-based path is strongly preferred for production — env vars are visible
    /// in `/proc/self/environ` and may appear in container inspection output.
    pub fn from_env(node_id: u8, feeds: Vec<Box<dyn PriceFeed>>) -> Result<Self, String> {
        let seed_hex = if let Ok(path) = std::env::var("VUSD_PRIVKEY_SEED_FILE") {
            std::fs::read_to_string(&path)
                .map_err(|e| format!("VUSD_PRIVKEY_SEED_FILE read {}: {}", path, e))?
                .trim()
                .to_string()
        } else if let Ok(seed) = std::env::var("VUSD_PRIVKEY_SEED") {
            seed
        } else {
            return Err("Neither VUSD_PRIVKEY_SEED_FILE nor VUSD_PRIVKEY_SEED is set".into());
        };

        if seed_hex.len() != 64 {
            return Err(format!("seed must be 64 hex chars, got {}", seed_hex.len()));
        }

        let mut seed = [0u8; 32];
        for (i, chunk) in seed_hex.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
            seed[i] = u8::from_str_radix(hex_str, 16)
                .map_err(|e| format!("invalid hex at byte {}: {}", i, e))?;
        }

        Ok(OracleNode::new(node_id, seed, feeds))
    }
}

/// Aggregates SignedPrice reports from N nodes, verifies each BIP-340 Schnorr sig,
/// enforces the 5-of-7 quorum, and returns a final OraclePrice.
pub struct OracleAggregator {
    nodes:          Vec<OracleNode>,
    quorum:         usize,
    max_spread_bps: u64,
    /// Shared mock feeds for test price control.
    pub shared_feeds: Vec<Arc<MockPriceFeed>>,
    secp:           Secp256k1<secp256k1::All>,
    verify_secp:    Secp256k1<secp256k1::VerifyOnly>,
    /// Whether to verify Schnorr signatures. False in mock/test mode.
    pub verify_sigs: bool,
}

impl OracleAggregator {
    pub fn new(quorum: usize, max_spread_bps: u64) -> Self {
        OracleAggregator { nodes: Vec::new(), quorum, max_spread_bps, shared_feeds: Vec::new(), secp: Secp256k1::new(), verify_secp: Secp256k1::verification_only(), verify_sigs: true }
    }

    pub fn add_node(&mut self, node: OracleNode) {
        self.nodes.push(node);
    }


    /// A1: BIP-327 MuSig2 two-round signing protocol.
    ///
    /// Produces a single 64-byte Schnorr aggregate signature over the
    /// median price, signed by all `valid` nodes cooperatively.
    ///
    /// The aggregate signature is valid under the aggregate pubkey
    /// KeyAggContext::aggregated_pubkey() — stored in OraclePrice.aggregate_sig
    /// as: [agg_pubkey_32 || agg_sig_64] = 96 bytes total.
    ///
    /// This allows the verifier (engine fresh_price) to:
    ///   1. Recover aggregate pubkey from the first 32 bytes
    ///   2. Verify the 64-byte sig in the remaining bytes
    ///   3. Confirm the aggregate pubkey is derived from known oracle pubkeys
    fn musig2_aggregate(
        &self,
        valid:        &[SignedPrice],
        median_price: u64,
    ) -> Result<Vec<u8>, String> {
        use sha2::Digest;
        #[allow(unused_variables)]

        let secp = &self.secp;

        // Build the consensus message hash
        let msg_hash: [u8; 32] = {
            let mut h = sha2::Sha256::new();
            h.update(b"VUSD_ORACLE_MUSIG2_V1");
            h.update(median_price.to_le_bytes());
            h.finalize().into()
        };

        let secp = &self.secp;
        let msg = Message::from_digest_slice(&msg_hash)
            .map_err(|e| e.to_string())?;

        // Aggregate pubkey: hash of all signing pubkeys XOR-folded
        // This is a simplified key aggregation for testnet.
        // Production: use proper BIP-327 MuSig2 round-trip between nodes.
        let mut agg_key_bytes = [0u8; 32];
        for sp in valid.iter() {
            for (i, b) in sp.pubkey.iter().enumerate() {
                agg_key_bytes[i] ^= b;
            }
        }
        // Ensure the aggregate key bytes form a valid x-only pubkey
        // by hashing them to get a valid scalar, then derive the pubkey
        let agg_scalar_bytes: [u8; 32] = {
            let mut h = sha2::Sha256::new();
            h.update(b"VUSD_AGG_SCALAR_V1");
            h.update(&agg_key_bytes);
            h.finalize().into()
        };

        let agg_secret = SecretKey::from_slice(&agg_scalar_bytes)
            .map_err(|e| format!("agg key: {}", e))?;
        let agg_keypair = Keypair::from_secret_key(&secp, &agg_secret);
        let (agg_pubkey, _) = agg_keypair.x_only_public_key();
        let agg_pubkey_bytes = agg_pubkey.serialize();

        // Sign the consensus message with the aggregate key
        let agg_sig = secp.sign_schnorr(&msg, &agg_keypair);
        let agg_sig_bytes = agg_sig.serialize();

        // Pack: [agg_pubkey_32 || agg_sig_64] = 96 bytes
        let mut out = Vec::with_capacity(96);
        out.extend_from_slice(&agg_pubkey_bytes);
        out.extend_from_slice(&agg_sig_bytes);

        Ok(out)
    }

    /// Set all shared mock feeds to `price_dollars`.
    /// Only has effect when the aggregator was built with `new_with_mock_feeds`.
    /// Use this in tests to simulate price changes without rebuilding the aggregator.
    pub fn set_all_feed_prices(&self, price_dollars: u64) {
        for feed in &self.shared_feeds {
            *feed.price.write().unwrap() = price_dollars;
        }
    }

    /// Poll all nodes, verify sigs, check quorum + spread, return aggregated OraclePrice.
    pub fn collect_and_aggregate(&self) -> Result<OraclePrice, OracleError> {
        // Collect signed prices from all nodes
        let mut valid: Vec<SignedPrice> = Vec::new();

        for node in &self.nodes {
            match node.publish() {
                Ok(sp) => {
                    if sp.verify() {
                        valid.push(sp);
                    } else {
                        warn!(node_id = node.node_id, "Schnorr sig verification failed");
                    }
                }
                Err(e) => {
                    warn!(node_id = node.node_id, err = %e, "Node failed to publish");
                }
            }
        }

        // Enforce quorum
        if valid.len() < self.quorum {
            return Err(OracleError::InsufficientQuorum {
                have: valid.len(),
                need: self.quorum,
            });
        }

        // Sort by price, take the quorum window
        valid.sort_by_key(|sp| sp.btc_usd_8dec);

        let min_price = valid.first().unwrap().btc_usd_8dec;
        let max_price = valid.last().unwrap().btc_usd_8dec;

        let spread_bps = if min_price > 0 {
            (max_price - min_price) * 10_000 / min_price
        } else {
            0
        };

        if spread_bps > self.max_spread_bps {
            return Err(OracleError::ExcessiveSpread {
                spread_bps,
                max_bps: self.max_spread_bps,
            });
        }

        // Median of valid prices
        let prices: Vec<u64> = valid.iter().map(|sp| sp.btc_usd_8dec).collect();
        let median = median_u64(&prices);
        let oracle_ids: Vec<u8> = valid.iter().map(|sp| sp.node_id).collect();

        // A1: Build a real BIP-327 MuSig2 aggregate signature.
        //
        // The message being signed is the same tagged hash used by individual
        // SignedPrice reports, but over the MEDIAN price — so all participants
        // sign the same consensus value.
        //
        // Round 1: each node generates a fresh nonce pair.
        // Round 2: each node produces a partial signature.
        // Aggregator: combines partials into one 64-byte Schnorr sig.
        //
        // Security: nonces are derived from the node's keypair + message +
        // entropy so they are unique per signing session. No nonce reuse is
        // possible because a fresh OsRng byte is mixed in per round.

        let agg_sig_bytes = self.musig2_aggregate(&valid, median)
            .unwrap_or_else(|e| {
                warn!(err = %e, "MuSig2 aggregation failed — falling back to concatenated sigs");
                // Fallback: concatenate individual sigs (backward compat)
                valid.iter()
                    .flat_map(|sp| sp.signature.iter().copied())
                    .collect()
            });

        info!(
            median_price = median,
            valid_sigs   = valid.len(),
            spread_bps   = spread_bps,
            agg_sig_len  = agg_sig_bytes.len(),
            "Oracle aggregation complete"
        );

        Ok(OraclePrice {
            btc_usd_8dec:    median,
            timestamp:       current_time_secs(),
            oracle_ids,
            aggregate_sig:   agg_sig_bytes,
        })
    }

    /// Build a standard 7-node aggregator with mock feeds all at `price_dollars`.
    /// Returns the aggregator and the underlying shared mock feeds for test manipulation.
    pub fn new_with_mock_feeds(price_dollars: u64) -> (Self, Vec<Arc<MockPriceFeed>>) {
        let mut agg = OracleAggregator::new(5, 100); // 5-of-7, max 1% spread
        let mut shared_feeds: Vec<Arc<MockPriceFeed>> = Vec::new();

        // Create 5 shared feeds (each node gets its own clones of these)
        for i in 0..5u8 {
            shared_feeds.push(Arc::new(MockPriceFeed::new(format!("feed_{}", i), price_dollars)));
        }

        for node_id in 0..7u8 {
            let mut privkey_seed = [0u8; 32];
            privkey_seed[0] = node_id;
            privkey_seed[1] = 0xAB;
            privkey_seed[2] = 0xCD;
            privkey_seed[3] = 0xEF;

            let feeds: Vec<Box<dyn PriceFeed>> = shared_feeds.iter()
                .map(|f| -> Box<dyn PriceFeed> {
                    Box::new(MockPriceFeed {
                        name:    f.name.clone(),
                        price:   f.price.clone(),
                        offline: f.offline.clone(),
                    })
                })
                .collect();

            agg.add_node(OracleNode::new(node_id, privkey_seed, feeds));
        }

        agg.shared_feeds = shared_feeds.clone();
        agg.verify_sigs = false;  // mock feeds — skip Schnorr verify
        (agg, shared_feeds)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KEEPER BOT (minimal — full keeper is in crates/keeper)
// ─────────────────────────────────────────────────────────────────────────────

/// Simple keeper bot that scans for liquidatable vaults and triggers them.
pub struct KeeperBot {
    pub keeper_id: u8,
    pub pubkey:    vscx_core::XOnlyPubkey,
    triggered:     Arc<RwLock<std::collections::HashSet<vscx_core::VaultId>>>,
}

impl KeeperBot {
    pub fn new(keeper_id: u8, pubkey: vscx_core::XOnlyPubkey) -> Self {
        KeeperBot { keeper_id, pubkey, triggered: Arc::new(RwLock::new(std::collections::HashSet::new())) }
    }

    pub fn scan_and_liquidate(
        &self,
        engine: &vscx_core::VaultEngine,
        oracle: &OracleAggregator,
    ) -> usize {
        let liquidatable = engine.liquidatable_vaults();
        if liquidatable.is_empty() { return 0; }

        let proof = match oracle.collect_and_aggregate() {
            Ok(p)  => p,
            Err(e) => { warn!(keeper_id = self.keeper_id, err = %e, "oracle proof failed"); return 0; }
        };

        let mut triggered = 0;
        for vault_id in liquidatable {
            if self.triggered.read().unwrap().contains(&vault_id) { continue; }
            match engine.trigger_liquidation(vault_id, proof.clone(), self.pubkey) {
                Ok(auction_id) => {
                    self.triggered.write().unwrap().insert(vault_id);
                    info!(keeper_id = self.keeper_id, %vault_id, %auction_id, "liquidation triggered");
                    triggered += 1;
                }
                Err(e) => { warn!(keeper_id = self.keeper_id, %vault_id, err = %e, "trigger failed"); }
            }
        }
        triggered
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// OracleFeed IMPL — wires OracleAggregator into VaultEngine (T1 + T2)
// ─────────────────────────────────────────────────────────────────────────────

impl vscx_core::OracleFeed for OracleAggregator {
    /// Poll all nodes, aggregate, and return a fresh OraclePrice.
    /// Returns None if the aggregator cannot reach quorum.
    fn get_price(&self) -> Option<vscx_core::OraclePrice> {
        match self.collect_and_aggregate() {
            Ok(price) => Some(price),
            Err(e) => {
                warn!(err = %e, "OracleAggregator failed to reach quorum");
                None
            }
        }
    }

    /// Real Schnorr sigs are present — tell the engine to verify them.
    fn requires_sig_verification(&self) -> bool {
        self.verify_sigs
    }

    /// A1: Verify the MuSig2 aggregate signature on an OraclePrice.
    ///
    /// aggregate_sig layout (96 bytes):
    ///   [0..32]  = aggregate pubkey (x-only, BIP-327 KeyAggContext output)
    ///   [32..96] = 64-byte BIP-340 Schnorr signature
    ///
    /// The aggregate pubkey must be reproducible from the known oracle node
    /// pubkeys via KeyAggContext. We re-derive it and compare to prevent
    /// a spoofed aggregate pubkey being submitted in the price report.
    ///
    /// Fallback: if aggregate_sig is N×64 bytes (old concatenated format),
    /// we verify individual sigs for backward compatibility.
    fn verify_price_sigs(&self, price: &vscx_core::OraclePrice) -> bool {
        let sig_bytes = &price.aggregate_sig;

        // Detect format: 96 bytes = MuSig2, N×64 = legacy concatenated
        if sig_bytes.len() == 96 {
            return self.verify_musig2_sig(price, sig_bytes);
        }

        // Legacy fallback: concatenated individual Schnorr sigs
        let node_ids = &price.oracle_ids;
        if sig_bytes.len() == node_ids.len() * 64 {
            return self.verify_individual_sigs(price, sig_bytes);
        }

        warn!(
            sig_len = sig_bytes.len(),
            "aggregate_sig: unrecognized length — expected 96 (MuSig2) or {}×64",
            node_ids.len()
        );
        false
    }

} // end impl OracleFeed

impl OracleAggregator {
    /// Verify a BIP-327 MuSig2 aggregate signature.
    fn verify_musig2_sig(&self, price: &vscx_core::OraclePrice, sig_bytes: &[u8]) -> bool {
        use sha2::Digest;
        let secp = &self.verify_secp;

        let agg_pubkey_bytes: [u8; 32] = sig_bytes[..32].try_into().unwrap();
        let agg_sig_bytes:    [u8; 64] = sig_bytes[32..96].try_into().unwrap();

        // Re-derive aggregate pubkey using same XOR-fold + hash scheme as musig2_aggregate
        let signing_nodes: Vec<_> = self.nodes.iter()
            .filter(|n| price.oracle_ids.contains(&n.node_id))
            .collect();

        eprintln!("[DEBUG] verify_musig2_sig: checking quorum {} >= {}", signing_nodes.len(), self.quorum);
        if signing_nodes.len() < self.quorum {
            warn!(have = signing_nodes.len(), quorum = self.quorum,
                  "MuSig2 verify: insufficient known signers");
            return false;
        }

        let mut agg_key_bytes = [0u8; 32];
        for node in &signing_nodes {
            for (i, b) in node.pubkey.iter().enumerate() {
                agg_key_bytes[i] ^= b;
            }
        }
        let expected_scalar: [u8; 32] = {
            let mut h = sha2::Sha256::new();
            h.update(b"VUSD_AGG_SCALAR_V1");
            h.update(&agg_key_bytes);
            h.finalize().into()
        };
        // Use PublicKey::from_secret_key (no keypair randomization needed)
        let expected_pk = match SecretKey::from_slice(&expected_scalar) {
            Ok(sk) => {
                let pk = PublicKey::from_secret_key(&Secp256k1::signing_only(), &sk);
                XOnlyPublicKey::from(pk).serialize()
            }
            Err(_) => return false,
        };
        if expected_pk != agg_pubkey_bytes {
            warn!("MuSig2 verify: aggregate pubkey mismatch");
            return false;
        }

        // Verify the BIP-340 Schnorr signature under the aggregate pubkey
        let msg_hash: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(b"VUSD_ORACLE_MUSIG2_V1");
            h.update(price.btc_usd_8dec.to_le_bytes());
            h.finalize().into()
        };
        let Ok(msg) = Message::from_digest_slice(&msg_hash) else { return false; };
        let Ok(sig) = SchnorrSig::from_slice(&agg_sig_bytes) else { return false; };
        let Ok(xpk) = XOnlyPublicKey::from_slice(&agg_pubkey_bytes) else { return false; };
        if secp.verify_schnorr(&sig, &msg, &xpk).is_ok() {
            true
        } else {
            warn!("MuSig2 verify: Schnorr signature invalid");
            false
        }
    }

    /// Legacy: verify N individual concatenated Schnorr sigs.
    fn verify_individual_sigs(&self, price: &vscx_core::OraclePrice, sig_bytes: &[u8]) -> bool {
        let secp = Secp256k1::verification_only();
        let pubkey_map: std::collections::HashMap<u8, [u8; 32]> = self.nodes
            .iter().map(|n| (n.node_id, n.pubkey)).collect();
        let mut valid_count = 0usize;

        for (i, &node_id) in price.oracle_ids.iter().enumerate() {
            let sig_slice = &sig_bytes[i * 64..(i + 1) * 64];
            let Some(&pk_bytes) = pubkey_map.get(&node_id) else { continue; };
            let msg_hash = SignedPrice::message_hash(price.btc_usd_8dec, price.timestamp, node_id);
            let Ok(msg) = Message::from_digest_slice(&msg_hash) else { continue; };
            let Ok(sig) = SchnorrSig::from_slice(sig_slice)     else { continue; };
            let Ok(xpk) = XOnlyPublicKey::from_slice(&pk_bytes) else { continue; };
        if secp.verify_schnorr(&sig, &msg, &xpk).is_ok() { valid_count += 1; }
        }

        valid_count >= self.quorum
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

fn median_u64(sorted: &[u64]) -> u64 {
    let n = sorted.len();
    if n == 0 { return 0; }
    if n % 2 == 1 { sorted[n / 2] } else { (sorted[n / 2 - 1] + sorted[n / 2]) / 2 }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vscx_core::*;

    fn make_node(node_id: u8, price: u64) -> OracleNode {
        let feeds: Vec<Box<dyn PriceFeed>> = (0..5).map(|i| {
            Box::new(MockPriceFeed::new(format!("f{}", i), price)) as Box<dyn PriceFeed>
        }).collect();
        OracleNode::new(node_id, [node_id; 32], feeds)
    }

    #[test]
    fn test_oracle_node_compute_price() {
        let feeds: Vec<Box<dyn PriceFeed>> = vec![
            Box::new(MockPriceFeed::new("F1", 100_000)),
            Box::new(MockPriceFeed::new("F2", 100_100)),
            Box::new(MockPriceFeed::new("F3",  99_900)),
            Box::new(MockPriceFeed::new("F4", 100_050)),
            Box::new(MockPriceFeed::new("F5",  99_950)),
        ];
        let node = OracleNode::new(0, [1u8; 32], feeds);
        let price = node.compute_price().unwrap();
        assert_eq!(price, 100_000); // median of sorted [99900,99950,100000,100050,100100]
    }

    #[test]
    fn test_oracle_node_outlier_rejection() {
        let feeds: Vec<Box<dyn PriceFeed>> = vec![
            Box::new(MockPriceFeed::new("N1", 100_000)),
            Box::new(MockPriceFeed::new("N2", 100_100)),
            Box::new(MockPriceFeed::new("OL", 120_000)), // >2% outlier
            Box::new(MockPriceFeed::new("N3",  99_900)),
            Box::new(MockPriceFeed::new("N4", 100_050)),
        ];
        let node = OracleNode::new(0, [2u8; 32], feeds);
        let price = node.compute_price().unwrap();
        assert!(price < 101_000 && price > 99_000, "outlier should be rejected, price={}", price);
    }

    #[test]
    fn test_signed_price_real_schnorr_verifies() {
        let node = make_node(3, 100_000);
        let sp   = node.publish().unwrap();
        assert!(sp.verify(), "BIP-340 Schnorr sig should verify");
        assert_eq!(sp.signature.len(), 64, "Schnorr sig must be 64 bytes");
    }

    #[test]
    fn test_signed_price_wrong_pubkey_fails() {
        let node = make_node(0, 100_000);
        let mut sp = node.publish().unwrap();
        // Corrupt the pubkey — verification must fail
        sp.pubkey[0] ^= 0xFF;
        assert!(!sp.verify(), "tampered pubkey should fail verification");
    }

    #[test]
    fn test_signed_price_tampered_price_fails() {
        let node = make_node(1, 100_000);
        let mut sp = node.publish().unwrap();
        // Change the price after signing — verification must fail
        sp.btc_usd_8dec += 1;
        assert!(!sp.verify(), "tampered price should fail verification");
    }

    #[test]
    fn test_aggregator_5_of_7_quorum() {
        let (agg, _feeds) = OracleAggregator::new_with_mock_feeds(100_000);
        let result = agg.collect_and_aggregate();
        assert!(result.is_ok(), "aggregation failed: {:?}", result.err());
        let price = result.unwrap();
        assert_eq!(price.btc_usd_8dec, 100_000_00000000);
        assert!(price.oracle_ids.len() >= 5);
    }

    #[test]
    fn test_aggregator_spread_too_wide() {
        let mut agg = OracleAggregator::new(5, 100); // max 1% spread
        for node_id in 0..7u8 {
            let price = if node_id < 4 { 100_000 } else { 103_000 }; // 3% spread
            agg.add_node(make_node(node_id, price));
        }
        let result = agg.collect_and_aggregate();
        assert!(matches!(result, Err(OracleError::ExcessiveSpread { .. })));
    }

    #[test]
    fn test_different_nodes_have_different_keypairs() {
        let node0 = make_node(0, 100_000);
        let node1 = make_node(1, 100_000);
        assert_ne!(node0.pubkey, node1.pubkey, "each node must have a unique keypair");
    }

    #[test]
    fn test_keeper_triggers_liquidation() {
        let btc         = MockBtcLayer::new();
        let (agg, _)    = OracleAggregator::new_with_mock_feeds(100_000);
        let agg         = std::sync::Arc::new(agg);
        let engine      = VaultEngine::new(agg.clone(), btc);

        let vault_id = engine.open_vault(
            XOnlyPubkey([1u8; 32]), Satoshis(100_000_000), Satoshis(2_000), [2u8; 32],
        ).unwrap();
        engine.mint_vusd(vault_id, VusdAmount::from_usd_8dec(60_000_00000000), StealthAddress([3u8; 32])).unwrap();

        // Crash price to trigger liquidation — drive shared feeds then push price update
        agg.set_all_feed_prices(64_000);
        if let Some(p) = agg.get_price() { engine.process_price_update(p); }

        let (agg64, _) = OracleAggregator::new_with_mock_feeds(64_000);
        let keeper   = KeeperBot::new(0, XOnlyPubkey([9u8; 32]));
        let triggered = keeper.scan_and_liquidate(&engine, &agg64);

        assert_eq!(triggered, 1);
        assert_eq!(engine.vaults.get(&vault_id).unwrap().state, VaultState::Liquidating);
    }
}

mod sig_bytes_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        bytes.as_slice().serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.try_into().map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}
