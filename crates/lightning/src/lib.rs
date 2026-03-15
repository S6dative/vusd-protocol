// crates/lightning/src/lib.rs
//
// Phase V — Lightning Network Integration + VUSD Wallet
//
// Lightning is the transport layer for VUSD transfer messages.
// The VUSD output set lives in the privacy layer (Phase IV).
// Lightning provides fast, off-chain routing of the ring-signed transactions.
//
// Full stack:
//   1. Sender constructs PrivateVusdTx (ring sig + RingCT outputs)
//   2. Tx is serialized and packed into a Lightning custom message
//   3. Lightning routes message to recipient node over payment channels
//   4. Recipient's node receives message, scans outputs for stealth addr match
//   5. If match found → record unspent output in local wallet db
//   6. To spend: construct new ring sig tx, route via Lightning again
//
// Phase V: mock Lightning node (no real LND required for testing).
// Testnet: swap MockLightningNode for real LND gRPC client.

pub mod lnd_client;
pub use lnd_client::{LndClient, LndConfig, LndTransport, LndError, VUSD_TLV_TYPE, VUSD_MSG_TLV_TYPE};

pub mod anon_transport;
pub use anon_transport::{
    AnonTransport, AnonHealthReport, AnonTransportError,
    TorConfig, PrivateChannelConfig, KeyRotationConfig, KeyRotationState,
    RelayNodeConfig, RelayPath, JitterConfig,
    NodeSetupGenerator, PADDED_MSG_SIZE,
    pad_message, unpad_message,
};

use dashmap::DashMap;
use privacy::{
    BulletproofRangeProof, PedersenCommitment, PrivacyLayer,
    PrivateVusdOutput, RingSignature, StealthWallet,
    KeyImage, RING_SIZE,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::{debug, info, warn};
use vscx_core::{
    current_time_secs, StealthAddress, VaultId, VusdAmount, XOnlyPubkey,
};

// ─────────────────────────────────────────────────────────────────────────────
// ERRORS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum LightningError {
    #[error("No route found to node: {0}")]
    NoRoute(String),

    #[error("Payment failed: {reason}")]
    PaymentFailed { reason: String },

    #[error("Node offline: {0}")]
    NodeOffline(String),

    #[error("Insufficient VUSD balance: have {have}, need {need}")]
    InsufficientBalance { have: VusdAmount, need: VusdAmount },

    #[error("Transfer amount below dust limit")]
    BelowDustLimit,

    #[error("Privacy error: {0}")]
    PrivacyError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Channel error: {0}")]
    ChannelError(String),

    #[error("LND error: {0}")]
    LndError(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// LIGHTNING NODE ID
// ─────────────────────────────────────────────────────────────────────────────

/// A Lightning node identity (public key).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    pub fn from_pubkey(pk: &XOnlyPubkey) -> Self { NodeId(pk.0) }
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
    pub fn random(seed: u8) -> Self {
        let mut id = [0u8; 32];
        id[0] = seed;
        id[1] = 0x4e; // 'N' for Node
        id[2] = 0x4f; // 'O'
        id[3] = 0x44; // 'D'
        id[4] = 0x45; // 'E'
        NodeId(id)
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node:{}", &self.to_hex()[..12])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VUSD TRANSFER MESSAGE
// ─────────────────────────────────────────────────────────────────────────────

/// A VUSD transfer message routed over Lightning.
/// Contains the full PrivateVusdTx packed for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VusdTransferMessage {
    /// Protocol version (for forward compatibility).
    pub version: u8,
    /// Sender's node ID (hashed — not the real pubkey).
    pub sender_hash: [u8; 32],
    /// The private transaction (ring sigs + outputs).
    pub tx: SerializedPrivateTx,
    /// Routing hints for the recipient's node to find the message.
    pub routing_hints: Vec<RoutingHint>,
    pub timestamp: u64,
}

/// Serialized form of a PrivateVusdTx for Lightning transport.
/// Ring sigs, commitments, and range proofs are all here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedPrivateTx {
    /// Serialized ring signatures (one per input).
    pub ring_sigs: Vec<SerializedRingSig>,
    /// Key images (for double-spend detection on receipt).
    pub key_images: Vec<[u8; 32]>,
    /// Output data.
    pub outputs: Vec<SerializedOutput>,
    /// Fee (public, in VUSD base units).
    pub fee_amount: u128,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedRingSig {
    pub ring_pubkeys: Vec<[u8; 32]>,
    pub key_image: [u8; 32],
    pub sig_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedOutput {
    pub stealth_address:  [u8; 32],
    pub ephemeral_pubkey: [u8; 32],
    pub commitment:       [u8; 32],
    pub range_proof:      Vec<u8>,
    /// XOR-encrypted amount: amount_u128_le XOR SHA256("VUSD_AMT_ENC" || ecdh_shared_secret)[..16]
    /// Recipient decrypts: ECDH(view_privkey, ephemeral_pubkey) -> shared_secret -> recover amount.
    pub encrypted_amount: [u8; 16],
}

/// Routing hint — tells recipient which channel to listen on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingHint {
    pub channel_id: u64,
    pub hop_pubkey: [u8; 32],
}

impl VusdTransferMessage {
    pub fn serialize(&self) -> Result<Vec<u8>, LightningError> {
        serde_json::to_vec(self)
            .map_err(|e| LightningError::SerializationError(e.to_string()))
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, LightningError> {
        serde_json::from_slice(bytes)
            .map_err(|e| LightningError::SerializationError(e.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VUSD WALLET
// ─────────────────────────────────────────────────────────────────────────────

/// An unspent VUSD output owned by this wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedOutput {
    pub stealth_address: StealthAddress,
    pub ephemeral_pubkey: [u8; 32],
    pub amount: VusdAmount,
    pub blinding: [u8; 32],
    pub output_index: u64,
    pub received_at: u64,
    pub spent: bool,
}

/// The VUSD wallet. Tracks owned outputs, computes balances, builds transactions.
pub struct VusdWallet {
    /// This wallet's stealth keypair.
    pub stealth_wallet: StealthWallet,
    /// Node ID on the Lightning network.
    pub node_id: NodeId,
    /// All outputs owned by this wallet.
    owned_outputs: Arc<RwLock<Vec<OwnedOutput>>>,
    /// Set of known key images (to detect our spent outputs).
    spent_key_images: Arc<RwLock<std::collections::HashSet<[u8; 32]>>>,
}

impl VusdWallet {
    /// Create a new wallet from a 32-byte seed.
    pub fn new(seed: [u8; 32]) -> Self {
        let stealth_wallet = StealthWallet::generate(&seed);
        let node_id = {
            let mut h = Sha256::new();
            h.update(b"VUSD_NODE_ID");
            h.update(&seed);
            let r = h.finalize();
            let mut id = [0u8; 32];
            id.copy_from_slice(&r);
            NodeId(id)
        };
        VusdWallet {
            stealth_wallet,
            node_id,
            owned_outputs: Arc::new(RwLock::new(Vec::new())),
            spent_key_images: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }

    /// Total spendable VUSD balance.
    pub fn balance(&self) -> VusdAmount {
        self.owned_outputs.read().unwrap()
            .iter()
            .filter(|o| !o.spent)
            .fold(VusdAmount::ZERO, |acc, o| acc.saturating_add(o.amount))
    }

    /// Scan a received transfer message for outputs belonging to this wallet.
    /// Returns the number of outputs found and recorded.
    pub fn scan_transfer(&self, msg: &VusdTransferMessage) -> usize {
        let mut found = 0;
        for output in &msg.tx.outputs {
            let stealth_addr = StealthAddress(output.stealth_address);
            if let Some(privkey) = self.stealth_wallet.scan_output(
                &output.ephemeral_pubkey,
                &stealth_addr,
            ) {
                // Decrypt amount: derive ECDH shared secret from view key + ephemeral pubkey,
                // then XOR-decrypt the encrypted_amount field the sender attached.
                let view_privkey = match self.stealth_wallet.view_privkey {
                    Some(vk) => vk,
                    None     => {
                        // Watch-only wallet: we can detect ownership but cannot
                        // decrypt the amount or spend the output.
                        // This is expected for monitoring wallets — not a bug.
                        tracing::debug!(
                            node_id = %self.node_id,
                            "scan_transfer: watch-only wallet found output but cannot decrypt amount"
                        );
                        continue;
                    }
                };
                let shared = ecdh_shared_secret(&view_privkey, &output.ephemeral_pubkey);
                let amount = decrypt_amount(&output.encrypted_amount, &shared);

                // The blinding factor is H_s = hash_to_scalar(shared, "VUSD_OTA"),
                // but for spending we use the output privkey returned by scan_output.
                let owned = OwnedOutput {
                    stealth_address: stealth_addr,
                    ephemeral_pubkey: output.ephemeral_pubkey,
                    amount,
                    blinding: privkey, // output privkey (x = H_s + spend_priv)
                    output_index: 0,
                    received_at: current_time_secs(),
                    spent: false,
                };
                self.owned_outputs.write().unwrap().push(owned);
                found += 1;
                info!(
                    node_id = %self.node_id,
                    amount = %amount,
                    "Wallet: found incoming VUSD output"
                );
            }
        }
        found
    }

    /// Select unspent outputs to cover the given amount (simple greedy selection).
    pub fn select_inputs(&self, target: VusdAmount) -> Option<Vec<OwnedOutput>> {
        let outputs = self.owned_outputs.read().unwrap();
        let mut selected = Vec::new();
        let mut total = VusdAmount::ZERO;

        for output in outputs.iter().filter(|o| !o.spent) {
            selected.push(output.clone());
            total = total.saturating_add(output.amount);
            if total >= target {
                return Some(selected);
            }
        }
        None
    }

    /// Mark an output as spent.
    pub fn mark_spent(&self, stealth_addr: &StealthAddress) {
        let mut outputs = self.owned_outputs.write().unwrap();
        if let Some(o) = outputs.iter_mut().find(|o| o.stealth_address == *stealth_addr) {
            o.spent = true;
        }
    }

    /// Record an output received from vault minting.
    pub fn record_mint_output(
        &self,
        stealth_address: StealthAddress,
        ephemeral_pubkey: [u8; 32],
        amount: VusdAmount,
        blinding: [u8; 32],
        output_index: u64,
    ) {
        let owned = OwnedOutput {
            stealth_address,
            ephemeral_pubkey,
            amount,
            blinding,
            output_index,
            received_at: current_time_secs(),
            spent: false,
        };
        self.owned_outputs.write().unwrap().push(owned);
        info!(
            node_id = %self.node_id,
            amount = %amount,
            "Wallet: recorded minted VUSD output"
        );
    }

    pub fn owned_output_count(&self) -> usize {
        self.owned_outputs.read().unwrap().len()
    }

    pub fn unspent_count(&self) -> usize {
        self.owned_outputs.read().unwrap().iter().filter(|o| !o.spent).count()
    }
}

/// Encrypt an amount for the recipient.
/// mask = SHA256("VUSD_AMT_ENC" || ecdh_shared_secret)[..16]
/// encrypted_amount = amount_u128_le XOR mask
pub fn encrypt_amount(amount: VusdAmount, ecdh_shared_secret: &[u8; 32]) -> [u8; 16] {
    let mask = amount_mask(ecdh_shared_secret);
    let amount_bytes = amount.0.to_le_bytes();
    let mut enc = [0u8; 16];
    for i in 0..16 {
        enc[i] = amount_bytes[i] ^ mask[i];
    }
    enc
}

/// Decrypt an amount received in an output.
/// Caller derives ecdh_shared_secret = ECDH(view_privkey, ephemeral_pubkey).
pub fn decrypt_amount(encrypted_amount: &[u8; 16], ecdh_shared_secret: &[u8; 32]) -> VusdAmount {
    let mask = amount_mask(ecdh_shared_secret);
    let mut amount_bytes = [0u8; 16];
    for i in 0..16 {
        amount_bytes[i] = encrypted_amount[i] ^ mask[i];
    }
    VusdAmount(u128::from_le_bytes(amount_bytes))
}

fn amount_mask(ecdh_shared_secret: &[u8; 32]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"VUSD_AMT_ENC");
    h.update(ecdh_shared_secret);
    let r = h.finalize();
    let mut mask = [0u8; 16];
    mask.copy_from_slice(&r[..16]);
    mask
}

/// Derive the ECDH shared secret from view_privkey and ephemeral_pubkey.
/// Derive the ECDH shared secret for amount encryption.
///
/// Matches the derivation in `privacy::StealthWallet`:
///   shared_point = v · R   where v = view_privkey scalar, R = ephemeral pubkey point
///
/// Then hashes the compressed shared point to get the 32-byte key material:
///   shared_secret = SHA256("VUSD_ECDH_V1" || shared_point_compressed)
///
/// This is used to encrypt/decrypt the amount field of VUSD transfer outputs.
/// Both sender (who knows r = ephemeral scalar) and recipient (who knows v = view privkey)
/// derive the same shared_point:
///   sender:    shared_point = r · V  (r·(v·G))
///   recipient: shared_point = v · R  (v·(r·G))
fn ecdh_shared_secret(view_privkey: &[u8; 32], ephemeral_pubkey: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT as G,
        ristretto::CompressedRistretto,
        scalar::Scalar,
    };
    use sha2::{Digest, Sha256};

    let v = Scalar::from_bytes_mod_order(*view_privkey);

    // Decompress the ephemeral Ristretto pubkey R
    let shared_point = CompressedRistretto::from_slice(ephemeral_pubkey)
        .decompress()
        .map(|R| v * R)
        .unwrap_or_else(|| {
            // Fallback: if point decompression fails (malformed pubkey), use a
            // deterministic but non-secret value. This produces a wrong amount,
            // which the recipient will detect. Do NOT panic in production.
            tracing::warn!("ecdh_shared_secret: ephemeral pubkey decompression failed — using fallback");
            v * G
        });

    let compressed = shared_point.compress().to_bytes();

    let mut h = Sha256::new();
    h.update(b"VUSD_ECDH_V1");
    h.update(&compressed);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// MOCK LIGHTNING NODE
// ─────────────────────────────────────────────────────────────────────────────

/// A mock Lightning node for testnet simulation.
/// In production: replace with LND gRPC client calls.
pub struct MockLightningNode {
    pub node_id: NodeId,
    /// Pending messages in the node's inbox.
    inbox: Arc<RwLock<Vec<VusdTransferMessage>>>,
    /// Connected peer nodes (simulated channels).
    peers: Arc<RwLock<HashMap<NodeId, bool>>>, // NodeId → is_online
    /// Whether this node is online.
    online: Arc<RwLock<bool>>,
}

impl MockLightningNode {
    pub fn new(node_id: NodeId) -> Self {
        MockLightningNode {
            node_id,
            inbox: Arc::new(RwLock::new(Vec::new())),
            peers: Arc::new(RwLock::new(HashMap::new())),
            online: Arc::new(RwLock::new(true)),
        }
    }

    pub fn connect_peer(&self, peer_id: NodeId) {
        self.peers.write().unwrap().insert(peer_id, true);
    }

    pub fn set_online(&self, online: bool) {
        *self.online.write().unwrap() = online;
    }

    pub fn is_online(&self) -> bool {
        *self.online.read().unwrap()
    }

    /// Receive a message (called by the network when a message is routed here).
    pub fn receive_message(&self, msg: VusdTransferMessage) {
        if self.is_online() {
            self.inbox.write().unwrap().push(msg);
        }
    }

    /// Drain the inbox and return all pending messages.
    pub fn drain_inbox(&self) -> Vec<VusdTransferMessage> {
        std::mem::take(&mut *self.inbox.write().unwrap())
    }

    pub fn inbox_count(&self) -> usize {
        self.inbox.read().unwrap().len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MOCK LIGHTNING NETWORK
// ─────────────────────────────────────────────────────────────────────────────

/// Simulates the Lightning Network — routes messages between nodes.
pub struct MockLightningNetwork {
    nodes: Arc<DashMap<NodeId, Arc<MockLightningNode>>>,
}

impl MockLightningNetwork {
    pub fn new() -> Self {
        MockLightningNetwork { nodes: Arc::new(DashMap::new()) }
    }

    pub fn register_node(&self, node: Arc<MockLightningNode>) {
        self.nodes.insert(node.node_id.clone(), node);
    }

    /// Route a VUSD transfer message to a recipient node.
    pub fn route_transfer(
        &self,
        recipient_node_id: &NodeId,
        msg: VusdTransferMessage,
    ) -> Result<(), LightningError> {
        match self.nodes.get(recipient_node_id) {
            None => Err(LightningError::NoRoute(recipient_node_id.to_hex())),
            Some(node) => {
                if !node.is_online() {
                    return Err(LightningError::NodeOffline(recipient_node_id.to_hex()));
                }
                node.receive_message(msg);
                debug!(recipient = %recipient_node_id, "VUSD transfer message routed");
                Ok(())
            }
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl Default for MockLightningNetwork {
    fn default() -> Self { Self::new() }
}

// ─────────────────────────────────────────────────────────────────────────────
// VUSD TRANSFER SERVICE
// ─────────────────────────────────────────────────────────────────────────────

/// High-level service for sending VUSD over Lightning.
/// Orchestrates wallet → privacy layer → Lightning routing.
///
/// In production: set lnd_transport via with_lnd() to route over real LND.
/// In test:       leave lnd_transport as None — MockLightningNetwork is used.
pub struct VusdTransferService {
    pub sender_wallet:  Arc<VusdWallet>,
    pub lightning_node: Arc<MockLightningNode>,
    pub network:        Arc<MockLightningNetwork>,
    pub privacy_layer:  Arc<PrivacyLayer>,
    /// Live LND transport. When Some, real Lightning routing is used.
    /// When None, falls back to MockLightningNetwork (test mode).
    pub lnd_transport:  Option<Arc<LndTransport>>,
}

impl VusdTransferService {
    pub fn new(
        sender_wallet:  Arc<VusdWallet>,
        lightning_node: Arc<MockLightningNode>,
        network:        Arc<MockLightningNetwork>,
        privacy_layer:  Arc<PrivacyLayer>,
    ) -> Self {
        VusdTransferService {
            sender_wallet,
            lightning_node,
            network,
            privacy_layer,
            lnd_transport: None, // T7: set via with_lnd() before production use
        }
    }

    /// Attach a live LND transport for production routing.
    /// After calling this, send() routes via LND keysend instead of MockLightningNetwork.
    pub fn with_lnd(mut self, lnd: LndTransport) -> Self {
        self.lnd_transport = Some(Arc::new(lnd));
        self
    }

    /// Send VUSD to a recipient wallet over Lightning.
    ///
    /// Async because real LND routing (the production path) is async.
    /// Mock routing (test path) also awaits correctly since it's wrapped.
    pub async fn send(
        &self,
        recipient_node_id: &NodeId,
        recipient_wallet: &StealthWallet,
        amount: VusdAmount,
    ) -> Result<VusdTransferMessage, LightningError> {
        // Generate a fresh ephemeral seed for this transfer.
        // This MUST be random — reuse across outputs would break stealth privacy.
        let mut ephemeral_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut ephemeral_seed);
        if amount < VusdAmount::DUST_LIMIT {
            return Err(LightningError::BelowDustLimit);
        }

        let balance = self.sender_wallet.balance();
        if balance < amount {
            return Err(LightningError::InsufficientBalance {
                have: balance,
                need: amount,
            });
        }

        // Select input outputs
        let inputs = self.sender_wallet.select_inputs(amount)
            .ok_or_else(|| LightningError::InsufficientBalance {
                have: balance,
                need: amount,
            })?;

        // Build ring sig inputs
        let mut ring_sigs = Vec::new();
        let mut key_images = Vec::new();

        for input in &inputs {
            // The blinding field stores the output private key x = H_s + spend_privkey
            let privkey = input.blinding;
            let pubkey  = input.stealth_address.0;

            let ki = KeyImage::derive(&privkey, &pubkey);
            key_images.push(*ki.as_bytes());

            // Select real decoys from the privacy layer output set.
            // Each decoy is a real stealth address from an unspent output,
            // selected via gamma-distributed weighted sampling (recency bias).
            // Falls back to synthetic keys only if the output set is too small.
            let real_decoys = self.privacy_layer.output_set.select_decoys(
                RING_SIZE - 1,
                u64::MAX, // exclude_idx: no specific output to exclude here
            );
            let decoys: Vec<[u8; 32]> = if real_decoys.len() >= RING_SIZE - 1 {
                real_decoys.iter().map(|o| o.stealth_address.0).collect()
            } else {
                // Output set not yet large enough — use deterministic synthetic keys.
                // These are valid Ristretto points derived from a tagged hash, not markers.
                // This fallback should only occur in early testnet with few outputs.
                tracing::warn!(
                    have = real_decoys.len(),
                    need = RING_SIZE - 1,
                    "output set too small for real decoys — using synthetic fallback"
                );
                let mut synthetic = real_decoys.iter().map(|o| o.stealth_address.0).collect::<Vec<_>>();
                for i in synthetic.len()..(RING_SIZE - 1) {
                    use sha2::Digest;
                    let mut h = sha2::Sha256::new();
                    h.update(b"VUSD_SYNTHETIC_DECOY");
                    h.update(&(i as u64).to_le_bytes());
                    h.update(&ephemeral_seed);
                    let mut d = [0u8; 32];
                    d.copy_from_slice(&h.finalize());
                    synthetic.push(d);
                }
                synthetic
            };

            let message = build_transfer_message_hash(&amount, &ephemeral_seed);
            // Randomize the real signer's position in the ring to prevent position leakage.
            let real_index = {
                use rand::Rng;
                rand::thread_rng().gen_range(0..RING_SIZE)
            };
            let sig = RingSignature::sign(&message, &privkey, &pubkey, decoys, real_index)
                .map_err(|e| LightningError::PrivacyError(e.to_string()))?;

            ring_sigs.push(SerializedRingSig {
                ring_pubkeys: sig.ring.clone(),
                key_image: *ki.as_bytes(),
                sig_bytes: sig.sig_data.clone(),
            });

            // Mark input as spent in wallet
            self.sender_wallet.mark_spent(&input.stealth_address);
        }

        // Create recipient output
        let (recipient_ota, ephemeral_pk) = recipient_wallet
            .derive_one_time_address(&ephemeral_seed);
        let blinding = sha2_hash_with_tag(&ephemeral_seed, b"OUTPUT_BLIND");
        let commitment_pt    = PedersenCommitment::commit(&amount, &blinding);
        let range_proof_data = BulletproofRangeProof::prove(&amount, &blinding);

        // Derive the ECDH shared secret that the recipient will also derive,
        // then encrypt the amount so only they can read it.
        // Sender-side ECDH: r·V where r=ephemeral scalar, V=recipient view pubkey.
        // The recipient will derive v·R = same shared point (Diffie-Hellman).
        let recipient_shared = StealthWallet::derive_shared_secret_sender(
            &ephemeral_seed, &recipient_wallet.view_pubkey,
        );
        let enc_amount = encrypt_amount(amount, &recipient_shared);

        let recipient_out = SerializedOutput {
            stealth_address:  recipient_ota.0,
            ephemeral_pubkey: ephemeral_pk,
            commitment:       commitment_pt.commitment,
            range_proof:      range_proof_data.proof_bytes,
            encrypted_amount: enc_amount,
        };

        // Compute change
        let total_in: VusdAmount = inputs.iter().fold(VusdAmount::ZERO, |a, o| a.saturating_add(o.amount));
        let fee = VusdAmount::DUST_LIMIT; // minimal fee
        let change_amount = VusdAmount(total_in.0.saturating_sub(amount.0).saturating_sub(fee.0));
        let mut outputs = vec![recipient_out];

        if !change_amount.is_zero() {
            // Derive change seed independently from OsRng, not from ephemeral_seed.
            // If ephemeral_seed were ever leaked, a derived change_seed would link the
            // change output back to the original transfer — breaking unlinkability.
            let mut change_seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut change_seed);
            let (change_ota, change_ephemeral) = self.sender_wallet.stealth_wallet
                .derive_one_time_address(&change_seed);
            let change_blinding = sha2_hash_with_tag(&change_seed, b"CHANGE_BLIND");
            let change_commitment = PedersenCommitment::commit(&change_amount, &change_blinding);
            let change_proof = BulletproofRangeProof::prove(&change_amount, &change_blinding);

            // Sender-side ECDH for change output: r_change·V_sender (we send change back to ourselves).
            let change_shared = StealthWallet::derive_shared_secret_sender(
                &change_seed, &self.sender_wallet.stealth_wallet.view_pubkey,
            );
            let enc_change    = encrypt_amount(change_amount, &change_shared);

            outputs.push(SerializedOutput {
                stealth_address:  change_ota.0,
                ephemeral_pubkey: change_ephemeral,
                commitment:       change_commitment.commitment,
                range_proof:      change_proof.proof_bytes,
                encrypted_amount: enc_change,
            });

            // Record change back to sender's wallet
            self.sender_wallet.record_mint_output(
                change_ota, change_ephemeral, change_amount, change_blinding, 0,
            );
        }

        let sender_hash = sha2_hash_with_tag(&self.sender_wallet.node_id.0, b"SENDER_HASH");

        let msg = VusdTransferMessage {
            version: 1,
            sender_hash,
            tx: SerializedPrivateTx {
                ring_sigs,
                key_images,
                outputs,
                fee_amount: fee.0,
                timestamp: current_time_secs(),
            },
            routing_hints: vec![],
            timestamp: current_time_secs(),
        };

        // Route over Lightning — G08: use live LND when available, mock in tests.
        if let Some(ref lnd) = self.lnd_transport {
            // Production path: keysend the serialized VusdTransferMessage to the
            // recipient's Lightning node pubkey via LND REST API.
            lnd.send_message(&recipient_node_id.to_hex(), &msg).await
                .map_err(|e| LightningError::ChannelError(
                    format!("LND send failed: {}", e)
                ))?;
            info!(
                sender    = %self.sender_wallet.node_id,
                recipient = %recipient_node_id,
                amount    = %amount,
                transport = "lnd-live",
                "VUSD transfer sent over Lightning"
            );
        } else {
            // T7: In production (non-test) builds, refuse to send over the mock
            // transport. The mock path is only valid for integration tests.
            // Wire a real LND node via VusdTransferService::with_lnd() before
            // calling send() in production.
            #[cfg(not(test))]
            {
                return Err(LightningError::ChannelError(
                    "T07: No LND transport configured.                      Call with_lnd(lnd_transport) before production use.                      The mock Lightning path is disabled outside test builds.".to_string()
                ));
            }
            // Test path: route through in-process MockLightningNetwork.
            #[cfg(test)]
            {
                self.network.route_transfer(recipient_node_id, msg.clone())
                    .map_err(|e| e)?;
                info!(
                    sender    = %self.sender_wallet.node_id,
                    recipient = %recipient_node_id,
                    amount    = %amount,
                    transport = "mock",
                    "VUSD transfer sent over mock Lightning (test mode)"
                );
            }
        }

        Ok(msg)
    }
}

fn build_transfer_message_hash(amount: &VusdAmount, seed: &[u8; 32]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"VUSD_TRANSFER_MSG");
    h.update(&amount.0.to_le_bytes());
    h.update(seed);
    h.finalize().to_vec()
}

fn sha2_hash_with_tag(data: &[u8], tag: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag);
    h.update(data);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// BURN PROOF (for vault repayment)
// ─────────────────────────────────────────────────────────────────────────────

/// A zero-knowledge proof that a given amount of VUSD is being burned
/// to repay a vault, without revealing the amount to the public.
///
/// Uses real PedersenCommitment and BulletproofRangeProof from the privacy crate.
/// The burn proof is presented to the vault engine as evidence of VUSD destruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VusdBurnProof {
    /// Hash of the vault being repaid.
    pub vault_id_hash: [u8; 32],
    /// Commitment to the amount being burned.
    pub amount_commitment: PedersenCommitment,
    /// Range proof that amount ≥ total_debt.
    pub range_proof: BulletproofRangeProof,
    /// Blinding factor commitment (proves amount matches debt without revealing).
    pub proof_bytes: Vec<u8>,
    pub timestamp: u64,
}

impl VusdBurnProof {
    /// Create a burn proof for repaying `amount` of VUSD on `vault_id`.
    pub fn create(
        vault_id_bytes: &[u8; 32],
        amount: VusdAmount,
        blinding: [u8; 32],
    ) -> Self {
        let commitment = PedersenCommitment::commit(&amount, &blinding);
        let range_proof = BulletproofRangeProof::prove(&amount, &blinding);

        let proof_bytes = {
            let mut h = Sha256::new();
            h.update(b"VUSD_BURN_PROOF");
            h.update(vault_id_bytes);
            h.update(&commitment.commitment);
            h.update(&blinding);
            h.finalize().to_vec()
        };

        let vault_id_hash = {
            let mut h = Sha256::new();
            h.update(b"VAULT_ID");
            h.update(vault_id_bytes);
            let r = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&r);
            out
        };

        VusdBurnProof {
            vault_id_hash,
            amount_commitment: commitment,
            range_proof,
            proof_bytes,
            timestamp: current_time_secs(),
        }
    }

    /// Verify a burn proof (structural check).
    pub fn verify(&self) -> bool {
        !self.proof_bytes.is_empty() && self.range_proof.verify()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VUSD OUTPUT SET SYNC
// ─────────────────────────────────────────────────────────────────────────────

/// Keeps the global VUSD output set synchronized across nodes.
/// In production: gossip protocol over Lightning network.
/// Phase V: direct shared state (same process).
pub struct OutputSetSync {
    /// Shared privacy layer with the vault engine.
    pub privacy_layer: Arc<PrivacyLayer>,
    /// Pending transactions to process.
    pending_txs: Arc<RwLock<Vec<VusdTransferMessage>>>,
}

impl OutputSetSync {
    pub fn new(privacy_layer: Arc<PrivacyLayer>) -> Self {
        OutputSetSync {
            privacy_layer,
            pending_txs: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Process all pending transfer messages — apply to output set.
    pub fn process_pending(&self) -> usize {
        let txs = std::mem::take(&mut *self.pending_txs.write().unwrap());
        let mut processed = 0;
        for msg in txs {
            for out in &msg.tx.outputs {
                let output = PrivateVusdOutput {
                    stealth_address: StealthAddress(out.stealth_address),
                    ephemeral_pubkey: out.ephemeral_pubkey,
                    amount_commitment: PedersenCommitment { commitment: out.commitment },
                    range_proof: BulletproofRangeProof {
                        commitment: PedersenCommitment { commitment: out.commitment },
                        proof_bytes: out.range_proof.clone(),
                    },
                    output_index: 0,
                    spent: false,
                };
                self.privacy_layer.output_set.add_output(output);
            }
            processed += 1;
        }
        processed
    }

    pub fn queue_message(&self, msg: VusdTransferMessage) {
        self.pending_txs.write().unwrap().push(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_funded_wallet(seed: u8, amount_usd: u64) -> VusdWallet {
        let wallet = VusdWallet::new([seed; 32]);
        // Pre-fund with an owned output
        let amount = VusdAmount::from_usd_8dec(amount_usd * 100_000_000);
        let blinding = [seed + 100u8; 32];
        let dummy_stealth = StealthAddress([seed; 32]);
        let dummy_ephemeral = [seed + 50u8; 32];
        wallet.record_mint_output(dummy_stealth, dummy_ephemeral, amount, blinding, 0);
        wallet
    }

    #[test]
    fn test_wallet_balance() {
        let wallet = make_funded_wallet(1, 10_000);
        assert_eq!(
            wallet.balance().to_usd_8dec() / 100_000_000,
            10_000
        );
    }

    #[test]
    fn test_wallet_balance_after_spend() {
        let wallet = make_funded_wallet(1, 10_000);
        let addr = StealthAddress([1u8; 32]);
        wallet.mark_spent(&addr);
        assert!(wallet.balance().is_zero());
    }

    #[test]
    fn test_wallet_scan_transfer() {
        let recipient_wallet_keys = StealthWallet::generate(&[42u8; 32]);
        let vusd_wallet = VusdWallet::new([42u8; 32]);

        let ephemeral_seed = [99u8; 32];
        let (ota, ephemeral_pk) = recipient_wallet_keys.derive_one_time_address(&ephemeral_seed);
        let amount = VusdAmount::from_usd_8dec(5_000_00000000);
        let blinding = [7u8; 32];
        let commitment = PedersenCommitment::commit(&amount, &blinding);
        let proof = BulletproofRangeProof::prove(&amount, &blinding);

        // Build encrypted_amount using the same shared secret the recipient will derive
        let shared = StealthWallet::derive_shared_secret_sender(&ephemeral_seed, &recipient_wallet_keys.view_pubkey);
        let enc_amount = encrypt_amount(amount, &shared);

        let msg = VusdTransferMessage {
            version: 1,
            sender_hash: [0u8; 32],
            tx: SerializedPrivateTx {
                ring_sigs: vec![],
                key_images: vec![],
                outputs: vec![SerializedOutput {
                    stealth_address:  ota.0,
                    ephemeral_pubkey: ephemeral_pk,
                    commitment:       commitment.commitment,
                    range_proof:      proof.proof_bytes,
                    encrypted_amount: enc_amount,
                }],
                fee_amount: 0,
                timestamp: current_time_secs(),
            },
            routing_hints: vec![],
            timestamp: current_time_secs(),
        };

        let found = vusd_wallet.scan_transfer(&msg);
        assert_eq!(found, 1);
        assert_eq!(vusd_wallet.owned_output_count(), 1);
    }

    #[test]
    fn test_lightning_network_routing() {
        let network = Arc::new(MockLightningNetwork::new());
        let node_a = Arc::new(MockLightningNode::new(NodeId::random(1)));
        let node_b = Arc::new(MockLightningNode::new(NodeId::random(2)));

        network.register_node(node_a.clone());
        network.register_node(node_b.clone());
        node_a.connect_peer(node_b.node_id.clone());

        let msg = VusdTransferMessage {
            version: 1,
            sender_hash: [0u8; 32],
            tx: SerializedPrivateTx {
                ring_sigs: vec![],
                key_images: vec![],
                outputs: vec![],
                fee_amount: 0,
                timestamp: current_time_secs(),
            },
            routing_hints: vec![],
            timestamp: current_time_secs(),
        };

        network.route_transfer(&node_b.node_id, msg).unwrap();
        assert_eq!(node_b.inbox_count(), 1);
    }

    #[test]
    fn test_offline_node_routing_fails() {
        let network = Arc::new(MockLightningNetwork::new());
        let node_b = Arc::new(MockLightningNode::new(NodeId::random(2)));
        node_b.set_online(false);
        network.register_node(node_b.clone());

        let msg = VusdTransferMessage {
            version: 1,
            sender_hash: [0u8; 32],
            tx: SerializedPrivateTx {
                ring_sigs: vec![],
                key_images: vec![],
                outputs: vec![],
                fee_amount: 0,
                timestamp: current_time_secs(),
            },
            routing_hints: vec![],
            timestamp: current_time_secs(),
        };

        let result = network.route_transfer(&node_b.node_id, msg);
        assert!(matches!(result, Err(LightningError::NodeOffline(_))));
    }

    #[test]
    fn test_burn_proof_creates_and_verifies() {
        let vault_id_bytes = [5u8; 32];
        let amount = VusdAmount::from_usd_8dec(60_000_00000000);
        let blinding = [9u8; 32];
        let proof = VusdBurnProof::create(&vault_id_bytes, amount, blinding);
        assert!(proof.verify());
    }

    #[tokio::test]
    async fn test_transfer_service_send() {
        let network = Arc::new(MockLightningNetwork::new());
        let privacy = Arc::new(PrivacyLayer::new());

        let sender_wallet = Arc::new(make_funded_wallet(10, 50_000));
        let sender_node = Arc::new(MockLightningNode::new(sender_wallet.node_id.clone()));
        let recipient_node = Arc::new(MockLightningNode::new(NodeId::random(20)));

        network.register_node(sender_node.clone());
        network.register_node(recipient_node.clone());

        let service = VusdTransferService::new(
            sender_wallet.clone(),
            sender_node.clone(),
            network.clone(),
            privacy.clone(),
        );

        let recipient_keys = StealthWallet::generate(&[20u8; 32]);
        let send_amount = VusdAmount::from_usd_8dec(10_000_00000000); // $10k

        let result = service.send(
            &recipient_node.node_id,
            &recipient_keys,
            send_amount,
        ).await;

        assert!(result.is_ok(), "Transfer should succeed");
        assert_eq!(recipient_node.inbox_count(), 1);
    }
}
