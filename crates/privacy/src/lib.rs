// crates/privacy/src/lib.rs
//
// VUSD Privacy Rails — production cryptography
//
// Uses curve25519-dalek v3 (pinned to match bulletproofs v4 dependency).
//
// 1. STEALTH ADDRESSES (dual-key, Monero-style)
//    OTA = H_s(r·V)·G + S
//    where r = ephemeral scalar, V = recipient view pubkey, S = recipient spend pubkey.
//    All arithmetic on Ristretto255 (curve25519-dalek v3).
//
// 2. PEDERSEN COMMITMENTS
//    C = v·H + r·G  on Ristretto255.
//    H = hash_to_ristretto("VUSD_PEDERSEN_H_GENERATOR") — independent generator.
//    Homomorphic: C(v1,r1) + C(v2,r2) = C(v1+v2, r1+r2).
//
// 3. KEY IMAGES
//    I = x · H_p(P)  where H_p = RistrettoPoint::hash_from_bytes(P).
//    Same (x,P) → same I → double-spend detection.
//
// 4. RING SIGNATURES (Borromean Schnorr ring — MLSAG-compatible interface)
//    1 real signer + RING_SIZE-1 decoys.
//    Full ring closure check in verify().
//
// 5. BULLETPROOFS (range proofs)
//    Proves v ∈ [0, 2^64) without revealing v.
//    Uses bulletproofs v4 + merlin v3 (Ristretto-based).

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use merlin::Transcript;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use vscx_core::{VusdAmount, StealthAddress, current_time_secs};

// ─────────────────────────────────────────────────────────────────────────────
// ERRORS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PrivacyError {
    #[error("Double spend detected: key image already used")]
    DoubleSpend,
    #[error("Ring signature invalid")]
    InvalidRingSignature,
    #[error("Pedersen commitment balance check failed")]
    CommitmentImbalance,
    #[error("Bulletproof range proof invalid")]
    InvalidRangeProof,
    #[error("Insufficient decoys: have {have}, need {need}")]
    InsufficientDecoys { have: usize, need: usize },
    #[error("Stealth address derivation failed")]
    StealthAddressError,
    #[error("Cannot scan: missing view key")]
    MissingViewKey,
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// STEALTH ADDRESSES
// ─────────────────────────────────────────────────────────────────────────────

/// Dual-key stealth wallet (spend key + view key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthWallet {
    pub spend_pubkey:  [u8; 32],
    pub view_pubkey:   [u8; 32],
    #[serde(skip)]
    pub spend_privkey: Option<[u8; 32]>,
    #[serde(skip)]
    pub view_privkey:  Option<[u8; 32]>,
}

impl StealthWallet {
    pub fn generate(seed: &[u8; 32]) -> Self {
        let spend_scalar = hash_to_scalar(seed, b"VUSD_SPEND_KEY");
        let view_scalar  = hash_to_scalar(seed, b"VUSD_VIEW_KEY");
        let spend_pubkey = (spend_scalar * G).compress().to_bytes();
        let view_pubkey  = (view_scalar  * G).compress().to_bytes();
        StealthWallet {
            spend_pubkey,
            view_pubkey,
            spend_privkey: Some(spend_scalar.to_bytes()),
            view_privkey:  Some(view_scalar.to_bytes()),
        }
    }

    /// Recipient-side ECDH: derive shared secret from view privkey + ephemeral pubkey.
    /// shared = SHA256("VUSD_ECDH_V1" || compress(v · R))
    /// where v = view_privkey scalar, R = ephemeral pubkey point.
    pub fn derive_shared_secret(view_privkey: &[u8; 32], ephemeral_pubkey: &[u8; 32]) -> [u8; 32] {
        let v = Scalar::from_bytes_mod_order(*view_privkey);
        let shared_point = decompress_point(ephemeral_pubkey)
            .map(|R| v * R)
            .unwrap_or(v * G);
        let compressed = shared_point.compress().to_bytes();
        let mut h = sha2::Sha256::new();
        sha2::Digest::update(&mut h, b"VUSD_ECDH_V1");
        sha2::Digest::update(&mut h, &compressed);
        sha2::Digest::finalize(h).into()
    }

    /// Sender-side ECDH: derive shared secret from ephemeral seed + recipient's view pubkey.
    /// shared = SHA256("VUSD_ECDH_V1" || compress(r · V))
    /// where r = ephemeral scalar derived from seed, V = recipient's view pubkey point.
    ///
    /// This produces the same shared secret as `derive_shared_secret(view_privkey, R)` on
    /// the recipient side, because r·(v·G) = v·(r·G) by commutativity of scalar mult.
    pub fn derive_shared_secret_sender(ephemeral_seed: &[u8; 32], recipient_view_pubkey: &[u8; 32]) -> [u8; 32] {
        let r = hash_to_scalar(ephemeral_seed, b"VUSD_EPHEMERAL_KEY");
        let V = decompress_point(recipient_view_pubkey).unwrap_or(G);
        let shared_point = r * V;
        let compressed = shared_point.compress().to_bytes();
        let mut h = sha2::Sha256::new();
        sha2::Digest::update(&mut h, b"VUSD_ECDH_V1");
        sha2::Digest::update(&mut h, &compressed);
        sha2::Digest::finalize(h).into()
    }

    pub fn watch_only(&self) -> Self {
        StealthWallet {
            spend_pubkey:  self.spend_pubkey,
            view_pubkey:   self.view_pubkey,
            spend_privkey: None,
            view_privkey:  self.view_privkey,
        }
    }

    /// Sender: derive one-time address.
    /// OTA = H_s(r·V)·G + S
    pub fn derive_one_time_address(&self, ephemeral_seed: &[u8; 32]) -> (StealthAddress, [u8; 32]) {
        let r = hash_to_scalar(ephemeral_seed, b"VUSD_EPHEMERAL_KEY");
        let R = (r * G).compress().to_bytes(); // ephemeral pubkey

        let V      = decompress_point(&self.view_pubkey).unwrap_or(G);
        let shared = (r * V).compress().to_bytes();
        let H_s    = hash_to_scalar(&shared, b"VUSD_OTA");
        let S      = decompress_point(&self.spend_pubkey).unwrap_or(G);
        let OTA    = ((H_s * G) + S).compress().to_bytes();
        (StealthAddress(OTA), R)
    }

    /// Recipient: scan output to check ownership.
    /// Returns private key x = H_s + spend_privkey if output is ours.
    pub fn scan_output(
        &self,
        ephemeral_pubkey: &[u8; 32],
        output_address:   &StealthAddress,
    ) -> Option<[u8; 32]> {
        let view_bytes = self.view_privkey?;
        let v          = Scalar::from_bytes_mod_order(view_bytes);
        let R          = decompress_point(ephemeral_pubkey)?;
        let shared     = (v * R).compress().to_bytes();
        let H_s        = hash_to_scalar(&shared, b"VUSD_OTA");
        let S          = decompress_point(&self.spend_pubkey)?;
        let expected   = ((H_s * G) + S).compress().to_bytes();
        if expected != output_address.0 { return None; }
        let s = Scalar::from_bytes_mod_order(self.spend_privkey?);
        Some((H_s + s).to_bytes())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PEDERSEN COMMITMENTS
// ─────────────────────────────────────────────────────────────────────────────

/// C = v·H + r·G on Ristretto255. Homomorphic and hiding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    pub commitment: [u8; 32],
}

impl PedersenCommitment {
    pub fn commit(amount: &VusdAmount, blinding: &[u8; 32]) -> Self {
        // Use bulletproofs' PedersenGens so our commitments are identical to
        // the ones produced by BulletproofRangeProof::prove(). Both use:
        //   C = v·B_blinding + r·B   (bulletproofs convention: value·H + blinding·G)
        //
        // Safety: VusdAmount.0 is u128 but Ristretto scalars and bulletproofs
        // both work with u64 amounts. We assert the high bits are zero — amounts
        // above u64::MAX (~$1.8 billion at 18 decimals) are not supported and
        // indicate a bug upstream. The 64-bit range proof also covers [0, 2^64).
        assert!(
            amount.0 <= u64::MAX as u128,
            "VusdAmount overflow: {} exceeds u64::MAX — vault amounts must be < $1.8B",
            amount.0
        );
        let pc_gens = PedersenGens::default();
        let v = Scalar::from(amount.0 as u64);
        let r = Scalar::from_bytes_mod_order(*blinding);
        let C = pc_gens.commit(v, r);
        PedersenCommitment { commitment: C.compress().to_bytes() }
    }

    /// Verify sum(input_blindings) = sum(output_blindings) + fee_blinding.
    /// This is a fast check that the prover knows the correct blinding factors.
    pub fn verify_balance(
        input_blindings:  &[[u8; 32]],
        output_blindings: &[[u8; 32]],
        fee_blinding:     &[u8; 32],
    ) -> bool {
        let sum_in: Scalar = input_blindings.iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .fold(Scalar::zero(), |acc, s| acc + s);
        let sum_out: Scalar = output_blindings.iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .fold(Scalar::zero(), |acc, s| acc + s);
        let fee_s = Scalar::from_bytes_mod_order(*fee_blinding);
        sum_in == sum_out + fee_s
    }

    /// Verify that sum(input_commitments) = sum(output_commitments) + fee_commitment.
    ///
    /// This is the true RingCT balance check — verifies on elliptic curve points
    /// without knowledge of underlying amounts or blinding factors.
    /// The fee commitment is built as `fee_blinding·G` (no amount component —
    /// fees are public and subtracted from the point sum separately).
    ///
    /// Use this in transaction verification, NOT verify_balance().
    /// verify_balance() is only for the prover to sanity-check their own blindings.
    pub fn verify_commitment_sum(
        input_commitments:  &[&PedersenCommitment],
        output_commitments: &[&PedersenCommitment],
        fee_commitment:     &PedersenCommitment,
    ) -> bool {
        // Sum all input commitments on the curve.
        // Any decompression failure returns None → false.
        let sum_points = |commitments: &[&PedersenCommitment]| -> Option<RistrettoPoint> {
            commitments.iter().try_fold(
                // Identity element: 0·G = neutral element of the Ristretto group
                Scalar::zero() * G,
                |acc, c| decompress_point(&c.commitment).map(|p| acc + p),
            )
        };

        let sum_in  = sum_points(input_commitments);
        let sum_out = sum_points(output_commitments);
        let fee_pt  = decompress_point(&fee_commitment.commitment);

        match (sum_in, sum_out, fee_pt) {
            (Some(si), Some(so), Some(fee)) => si == so + fee,
            _ => false, // any decompression failed → invalid commitment bytes
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KEY IMAGE
// ─────────────────────────────────────────────────────────────────────────────

/// I = x · H_p(P) — deterministic, prevents double-spending.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyImage([u8; 32]);

impl KeyImage {
    pub fn derive(privkey: &[u8; 32], pubkey: &[u8; 32]) -> Self {
        let x   = Scalar::from_bytes_mod_order(*privkey);
        let H_p = hash_to_point(pubkey);
        KeyImage((x * H_p).compress().to_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

// ─────────────────────────────────────────────────────────────────────────────
// RING SIGNATURE (Borromean Schnorr ring)
// ─────────────────────────────────────────────────────────────────────────────

pub const RING_SIZE: usize = 11;

/// A Borromean-style Schnorr ring signature over RING_SIZE keys.
/// Interface matches MLSAG/CLSAG — swap in Monero's CLSAG as a drop-in.
///
/// Stored as: c_0 (32 bytes) || s_0..s_{n-1} (32 bytes each) = (RING_SIZE+1)*32 bytes total.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingSignature {
    pub ring:      Vec<[u8; 32]>,
    pub key_image: KeyImage,
    pub sig_data:  Vec<u8>,
}

impl RingSignature {
    pub fn sign(
        message:       &[u8],
        real_privkey:  &[u8; 32],
        real_pubkey:   &[u8; 32],
        decoy_pubkeys: Vec<[u8; 32]>,
        real_index:    usize,
    ) -> Result<RingSignature, PrivacyError> {
        if decoy_pubkeys.len() + 1 != RING_SIZE {
            return Err(PrivacyError::InsufficientDecoys {
                have: decoy_pubkeys.len(),
                need: RING_SIZE - 1,
            });
        }

        let mut ring = decoy_pubkeys;
        let real_idx = real_index.min(ring.len());
        ring.insert(real_idx, *real_pubkey);

        let key_image = KeyImage::derive(real_privkey, real_pubkey);
        let n = RING_SIZE;
        let x = Scalar::from_bytes_mod_order(*real_privkey);

        let mut rng = rand::thread_rng();

        // Step 1: sample random k, compute R_π = k·G
        let k = {
            let mut bytes = [0u8; 64];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
            Scalar::from_bytes_mod_order_wide(&bytes)
        };
        let R_pi = (k * G).compress().to_bytes();

        // Step 2: build c values walking around the ring
        let mut c = vec![Scalar::zero(); n];
        let mut s = vec![Scalar::zero(); n];

        c[(real_idx + 1) % n] = ring_hash(message, &R_pi, key_image.as_bytes());

        for step in 1..n {
            let i  = (real_idx + step) % n;
            let i1 = (i + 1) % n;
            s[i] = {
                let mut bytes = [0u8; 64];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
                Scalar::from_bytes_mod_order_wide(&bytes)
            };
            let P_i = match decompress_point(&ring[i]) {
                Some(p) => p,
                None    => return Err(PrivacyError::CryptoError(format!("bad ring point {}", i))),
            };
            let R_i = ((s[i] * G) + (c[i] * P_i)).compress().to_bytes();
            c[i1]   = ring_hash(message, &R_i, key_image.as_bytes());
        }

        // Step 3: close ring at real signer
        s[real_idx] = k - c[real_idx] * x;

        // Pack: c_0 || s_0..s_{n-1}
        let mut sig_data = Vec::with_capacity((n + 1) * 32);
        sig_data.extend_from_slice(c[0].as_bytes());
        for si in &s { sig_data.extend_from_slice(si.as_bytes()); }

        Ok(RingSignature { ring, key_image, sig_data })
    }

    pub fn verify(&self, message: &[u8]) -> bool {
        if self.ring.len() != RING_SIZE { return false; }
        if self.sig_data.len() != (RING_SIZE + 1) * 32 { return false; }

        let n  = RING_SIZE;
        let c0 = match scalar_from_bytes(&self.sig_data[..32]) {
            Some(s) => s,
            None    => return false,
        };
        let mut s = Vec::with_capacity(n);
        for i in 0..n {
            let off = 32 + i * 32;
            match scalar_from_bytes(&self.sig_data[off..off+32]) {
                Some(si) => s.push(si),
                None     => return false,
            }
        }

        let mut c = c0;
        for i in 0..n {
            let P_i = match decompress_point(&self.ring[i]) {
                Some(p) => p,
                None    => return false,
            };
            let R_i = ((s[i] * G) + (c * P_i)).compress().to_bytes();
            c = ring_hash(message, &R_i, self.key_image.as_bytes());
        }

        c == c0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BULLETPROOF RANGE PROOF
// ─────────────────────────────────────────────────────────────────────────────

/// Range proof: proves v ∈ [0, 2^64) without revealing v.
/// Uses bulletproofs v4 (Ristretto, Merlin transcript).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulletproofRangeProof {
    pub commitment:  PedersenCommitment,
    pub proof_bytes: Vec<u8>,
}

impl BulletproofRangeProof {
    pub fn prove(amount: &VusdAmount, blinding: &[u8; 32]) -> Self {
        // Bounds check: bulletproofs proves v ∈ [0, 2^64). VusdAmount is u128.
        // Amounts above u64::MAX are not representable in a 64-bit range proof.
        assert!(
            amount.0 <= u64::MAX as u128,
            "BulletproofRangeProof: amount {} exceeds u64::MAX",
            amount.0
        );
        let bp_gens = BulletproofGens::new(64, 1);
        let pc_gens = PedersenGens::default();
        let v       = amount.0 as u64;
        let r       = Scalar::from_bytes_mod_order(*blinding);

        let (proof, compressed) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut Transcript::new(b"VUSD_RANGE_PROOF"),
            v,
            &r,
            64,
        ).expect("bulletproof proving failed");

        BulletproofRangeProof {
            commitment:  PedersenCommitment { commitment: compressed.to_bytes() },
            proof_bytes: proof.to_bytes(),
        }
    }

    pub fn verify(&self) -> bool {
        let bp_gens = BulletproofGens::new(64, 1);
        let pc_gens = PedersenGens::default();

        let compressed = CompressedRistretto::from_slice(&self.commitment.commitment);
        let proof = match RangeProof::from_bytes(&self.proof_bytes) {
            Ok(p)  => p,
            Err(_) => return false,
        };

        proof.verify_single(
            &bp_gens,
            &pc_gens,
            &mut Transcript::new(b"VUSD_RANGE_PROOF"),
            &compressed,
            64,
        ).is_ok()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVATE VUSD OUTPUT / TRANSACTION
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateVusdOutput {
    pub stealth_address:   StealthAddress,
    pub ephemeral_pubkey:  [u8; 32],
    pub amount_commitment: PedersenCommitment,
    pub range_proof:       BulletproofRangeProof,
    pub output_index:      u64,
    pub spent:             bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateVusdTx {
    pub inputs:                  Vec<RingSignature>,
    pub key_images:              Vec<KeyImage>,
    pub outputs:                 Vec<PrivateVusdOutput>,
    pub fee:                     VusdAmount,
    pub balance_blindings_proof: Vec<u8>,
    pub timestamp:               u64,
    /// The message that all ring signatures in `inputs` were signed over.
    /// Stored so apply_transaction() can verify without knowing the plain amounts.
    pub signed_message:          Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// VUSD OUTPUT SET
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct VusdOutputSet {
    inner: Arc<RwLock<OutputSetInner>>,
}

#[derive(Debug, Default)]
struct OutputSetInner {
    outputs:         Vec<PrivateVusdOutput>,
    used_key_images: HashSet<[u8; 32]>,
    next_index:      u64,
}

impl VusdOutputSet {
    pub fn new() -> Self {
        VusdOutputSet { inner: Arc::new(RwLock::new(OutputSetInner::default())) }
    }

    pub fn add_output(&self, mut output: PrivateVusdOutput) {
        let mut inner = self.inner.write().unwrap();
        output.output_index = inner.next_index;
        inner.next_index += 1;
        inner.outputs.push(output);
    }

    pub fn mark_spent(&self, ki: KeyImage) -> Result<(), PrivacyError> {
        let mut inner = self.inner.write().unwrap();
        if inner.used_key_images.contains(ki.as_bytes()) {
            return Err(PrivacyError::DoubleSpend);
        }
        inner.used_key_images.insert(*ki.as_bytes());
        Ok(())
    }

    pub fn is_key_image_used(&self, ki: &KeyImage) -> bool {
        self.inner.read().unwrap().used_key_images.contains(ki.as_bytes())
    }

    pub fn select_decoys(&self, count: usize, exclude_idx: u64) -> Vec<PrivateVusdOutput> {
        let inner = self.inner.read().unwrap();
        let candidates: Vec<&PrivateVusdOutput> = inner.outputs.iter()
            .filter(|o| !o.spent && o.output_index != exclude_idx)
            .collect();

        if candidates.len() <= count {
            return candidates.into_iter().cloned().collect();
        }

        // Gamma-distributed decoy selection (Monero-style).
        //
        // Monero's gamma distribution selects outputs whose age follows a real
        // spend-time distribution, making timing analysis harder.
        // We approximate this by biasing towards recent outputs (lower index = older,
        // higher index = newer). The gamma shape (a=19.28, b=1/1.61) is tuned
        // to match real transaction age distributions.
        //
        // Implementation: use the inverse CDF of a simplified gamma via
        // repeated sampling with rejection, biased toward high indices.
        // For testnet we use a simpler power-law approximation.
        gamma_select_decoys(&candidates, count, exclude_idx)
    }

    pub fn output_count(&self) -> usize {
        self.inner.read().unwrap().outputs.len()
    }

    pub fn unspent_count(&self) -> usize {
        self.inner.read().unwrap().outputs.iter().filter(|o| !o.spent).count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIVACY LAYER
// ─────────────────────────────────────────────────────────────────────────────

pub struct PrivacyLayer {
    pub output_set: VusdOutputSet,
}

impl PrivacyLayer {
    pub fn new() -> Self {
        PrivacyLayer { output_set: VusdOutputSet::new() }
    }

    pub fn create_mint_output(
        &self,
        amount:           VusdAmount,
        recipient_wallet: &StealthWallet,
    ) -> Result<PrivateVusdOutput, PrivacyError> {
        // Always generate a fresh random ephemeral seed from OsRng.
        // Never accept ephemeral seeds from the caller — reuse would break stealth privacy.
        let mut ephemeral_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ephemeral_seed);
        let (stealth_addr, ephemeral_pubkey) =
            recipient_wallet.derive_one_time_address(&ephemeral_seed);
        let blinding    = hash_to_scalar(&ephemeral_seed, b"VUSD_OUTPUT_BLIND").to_bytes();
        let range_proof = BulletproofRangeProof::prove(&amount, &blinding);
        let output = PrivateVusdOutput {
            stealth_address:   stealth_addr,
            ephemeral_pubkey,
            amount_commitment: range_proof.commitment.clone(),
            range_proof,
            output_index:      0,
            spent:             false,
        };
        self.output_set.add_output(output.clone());
        Ok(output)
    }

    pub fn create_transfer(
        &self,
        input_output:     &PrivateVusdOutput,
        input_privkey:    &[u8; 32],
        input_blinding:   &[u8; 32],
        recipient_wallet: &StealthWallet,
        amount:           VusdAmount,
        fee:              VusdAmount,
    ) -> Result<PrivateVusdTx, PrivacyError> {
        // Always generate a fresh random ephemeral seed from OsRng.
        let mut ephemeral_seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut ephemeral_seed);
        let decoys = self.output_set.select_decoys(RING_SIZE - 1, input_output.output_index);
        if decoys.len() < RING_SIZE - 1 {
            return Err(PrivacyError::InsufficientDecoys {
                have: decoys.len(),
                need: RING_SIZE - 1,
            });
        }

        let decoy_pubkeys: Vec<[u8; 32]> = decoys.iter().map(|d| d.stealth_address.0).collect();
        let message  = compute_tx_message(&amount, &fee);
        // Randomize the real signer's position in the ring.
        let real_index = {
            use rand::Rng;
            rand::thread_rng().gen_range(0..RING_SIZE)
        };
        let ring_sig = RingSignature::sign(
            &message, input_privkey, &input_output.stealth_address.0, decoy_pubkeys, real_index,
        )?;
        let key_image = KeyImage::derive(input_privkey, &input_output.stealth_address.0);

        let (recipient_addr, ephemeral_pk) = recipient_wallet.derive_one_time_address(&ephemeral_seed);
        let out_blinding  = hash_to_scalar(&ephemeral_seed, b"VUSD_OUT_BLIND").to_bytes();
        let range_proof   = BulletproofRangeProof::prove(&amount, &out_blinding);
        let recipient_out = PrivateVusdOutput {
            stealth_address:   recipient_addr,
            ephemeral_pubkey:  ephemeral_pk,
            amount_commitment: range_proof.commitment.clone(),
            range_proof,
            output_index:      0,
            spent:             false,
        };

        let fee_blinding = hash_to_scalar(&ephemeral_seed, b"VUSD_FEE_BLIND").to_bytes();

        Ok(PrivateVusdTx {
            inputs:                  vec![ring_sig],
            key_images:              vec![key_image],
            outputs:                 vec![recipient_out],
            fee,
            balance_blindings_proof: fee_blinding.to_vec(),
            timestamp:               current_time_secs(),
            signed_message:          message,
        })
    }

    pub fn apply_transaction(&self, tx: &PrivateVusdTx) -> Result<(), PrivacyError> {
        // Use the stored signed_message — do NOT reconstruct from amounts.
        // The message was committed at signing time; reconstructing with wrong values
        // (e.g., ZERO amounts) would cause all ring sig verifications to fail.
        let message = &tx.signed_message;
        for sig in &tx.inputs {
            if !sig.verify(message) { return Err(PrivacyError::InvalidRingSignature); }
        }
        for ki in &tx.key_images {
            if self.output_set.is_key_image_used(ki) { return Err(PrivacyError::DoubleSpend); }
        }
        for output in &tx.outputs {
            if !output.range_proof.verify() { return Err(PrivacyError::InvalidRangeProof); }
        }
        for ki in tx.key_images.clone() {
            self.output_set.mark_spent(ki)?;
        }
        for output in &tx.outputs {
            self.output_set.add_output(output.clone());
        }
        Ok(())
    }
}

impl Default for PrivacyLayer {
    fn default() -> Self { Self::new() }
}


// ─────────────────────────────────────────────────────────────────────────────
// GAMMA-DISTRIBUTED DECOY SELECTION
// ─────────────────────────────────────────────────────────────────────────────

/// Select `count` decoys from `candidates` using a power-law age bias.
///
/// Monero uses a gamma distribution to model the probability that a given
/// output age matches a real spend. We approximate this with a power-law:
///   P(selecting output at position i from end) ∝ (i+1)^(-alpha)
/// where alpha ≈ 1.0 gives mild recency bias (recent outputs slightly preferred).
///
/// This prevents the timing correlation of sequential selection while keeping
/// the implementation simple and auditable. Replace with full gamma CDF before mainnet.
fn gamma_select_decoys(
    candidates: &[&PrivateVusdOutput],
    count:      usize,
    _exclude:   u64,
) -> Vec<PrivateVusdOutput> {
    use rand::Rng;
    let n = candidates.len();
    if n == 0 || count == 0 { return Vec::new(); }

    let mut rng = rand::thread_rng();
    let mut selected_indices = std::collections::HashSet::new();
    let mut result = Vec::with_capacity(count);

    // Build cumulative weights biased toward higher indices (more recent outputs).
    // Weight for index i (0 = oldest, n-1 = newest): w_i = (i+1)^alpha
    // alpha = 1.0 → linear recency bias (simple to verify)
    let weights: Vec<f64> = (0..n).map(|i| (i as f64 + 1.0)).collect();
    let total_weight: f64 = weights.iter().sum();

    let max_attempts = count * 20; // prevent infinite loop on small output sets
    let mut attempts = 0;

    while result.len() < count && attempts < max_attempts {
        attempts += 1;

        // Sample a uniform float, map to weighted index
        let sample: f64 = rng.gen_range(0.0..total_weight);
        let mut cumulative = 0.0;
        let mut selected = n - 1; // default to last if loop overshoots
        for (i, w) in weights.iter().enumerate() {
            cumulative += w;
            if sample < cumulative {
                selected = i;
                break;
            }
        }

        if selected_indices.insert(selected) {
            result.push(candidates[selected].clone());
        }
    }

    result
}

// ─────────────────────────────────────────────────────────────────────────────
// CRYPTO PRIMITIVES (curve25519-dalek v3)
// ─────────────────────────────────────────────────────────────────────────────

/// Hash input+tag to a Ristretto scalar via wide reduction from SHA-512.
fn hash_to_scalar(input: &[u8], tag: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(tag);
    h.update(input);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

/// Hash-to-point for key images: H_p(P).
fn hash_to_point(point_bytes: &[u8]) -> RistrettoPoint {
    // Use from_uniform_bytes with a SHA-512 hash to avoid digest version conflicts
    {
        use sha2::Digest;
        let mut h = sha2::Sha512::new();
        h.update(point_bytes);
        let hash_bytes: [u8; 64] = h.finalize().into();
        RistrettoPoint::from_uniform_bytes(&hash_bytes)
    }
}

/// Decompress a 32-byte Ristretto point.
/// In dalek v3, from_slice is infallible (panics on wrong length), decompress returns Option.
fn decompress_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes).decompress()
}

/// Hash (message || R_i || key_image) to scalar for ring construction.
fn ring_hash(message: &[u8], R_i: &[u8; 32], key_image: &[u8; 32]) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"VUSD_RING_HASH");
    h.update(message);
    h.update(R_i);
    h.update(key_image);
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

fn scalar_from_bytes(bytes: &[u8]) -> Option<Scalar> {
    if bytes.len() != 32 { return None; }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Some(Scalar::from_bytes_mod_order(arr))
}

fn compute_tx_message(amount: &VusdAmount, fee: &VusdAmount) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"VUSD_TX_MESSAGE");
    h.update(amount.0.to_le_bytes());
    h.update(fee.0.to_le_bytes());
    h.finalize().to_vec()
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_sender_recipient_symmetry() {
        // The ECDH shared secret must be identical for sender and recipient.
        // Sender computes: r·V where r = hash(seed, "VUSD_EPHEMERAL_KEY"), V = view_pubkey
        // Recipient computes: v·R where v = view_privkey, R = r·G (ephemeral pubkey)
        // These are equal by commutativity: r·(v·G) = v·(r·G)
        let wallet = StealthWallet::generate(&[55u8; 32]);
        let ephemeral_seed = [77u8; 32];

        // Get the ephemeral pubkey R = r·G
        let (_, ephemeral_pubkey_R) = wallet.derive_one_time_address(&ephemeral_seed);

        // Sender-side: r·V
        let sender_secret = StealthWallet::derive_shared_secret_sender(
            &ephemeral_seed,
            &wallet.view_pubkey,
        );

        // Recipient-side: v·R  
        let recipient_secret = StealthWallet::derive_shared_secret(
            &wallet.view_privkey.unwrap(),
            &ephemeral_pubkey_R,
        );

        assert_eq!(
            sender_secret, recipient_secret,
            "ECDH symmetry broken: sender and recipient derived different shared secrets"
        );
    }

    #[test]
    fn test_ecdh_different_seeds_different_secrets() {
        let wallet = StealthWallet::generate(&[55u8; 32]);
        let s1 = StealthWallet::derive_shared_secret_sender(&[10u8; 32], &wallet.view_pubkey);
        let s2 = StealthWallet::derive_shared_secret_sender(&[11u8; 32], &wallet.view_pubkey);
        assert_ne!(s1, s2, "Different ephemeral seeds must produce different shared secrets");
    }

    #[test]
    fn test_stealth_address_derive_and_scan() {
        let wallet = StealthWallet::generate(&[42u8; 32]);
        let (ota, eph) = wallet.derive_one_time_address(&[99u8; 32]);
        assert!(wallet.scan_output(&eph, &ota).is_some());
    }

    #[test]
    fn test_stealth_address_wrong_wallet_misses() {
        let w1 = StealthWallet::generate(&[1u8; 32]);
        let w2 = StealthWallet::generate(&[2u8; 32]);
        let (ota, eph) = w1.derive_one_time_address(&[99u8; 32]);
        assert!(w2.scan_output(&eph, &ota).is_none());
    }

    #[test]
    fn test_stealth_different_ephemerals_give_different_otas() {
        let w = StealthWallet::generate(&[3u8; 32]);
        let (ota1, _) = w.derive_one_time_address(&[10u8; 32]);
        let (ota2, _) = w.derive_one_time_address(&[11u8; 32]);
        assert_ne!(ota1.0, ota2.0);
    }

    #[test]
    fn test_pedersen_deterministic() {
        let a = VusdAmount::from_usd_8dec(1_000_00000000);
        let b = [7u8; 32];
        assert_eq!(PedersenCommitment::commit(&a, &b), PedersenCommitment::commit(&a, &b));
    }

    #[test]
    fn test_pedersen_different_amounts_differ() {
        let b = [7u8; 32];
        let c1 = PedersenCommitment::commit(&VusdAmount::from_usd_8dec(1_000_00000000), &b);
        let c2 = PedersenCommitment::commit(&VusdAmount::from_usd_8dec(2_000_00000000), &b);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_pedersen_balance_proof() {
        let x = Scalar::from_bytes_mod_order([10u8; 32]);
        let y = Scalar::from_bytes_mod_order([6u8; 32]);
        let f = (x - y).to_bytes();
        assert!(PedersenCommitment::verify_balance(&[[10u8; 32]], &[[6u8; 32]], &f));
    }

    #[test]
    fn test_key_image_deterministic() {
        let ki1 = KeyImage::derive(&[5u8; 32], &[6u8; 32]);
        let ki2 = KeyImage::derive(&[5u8; 32], &[6u8; 32]);
        assert_eq!(ki1, ki2);
    }

    #[test]
    fn test_key_image_unique() {
        assert_ne!(KeyImage::derive(&[1u8; 32], &[2u8; 32]),
                   KeyImage::derive(&[3u8; 32], &[4u8; 32]));
    }

    #[test]
    fn test_double_spend_detection() {
        let os = VusdOutputSet::new();
        let ki = KeyImage::derive(&[1u8; 32], &[2u8; 32]);
        os.mark_spent(ki.clone()).unwrap();
        assert!(matches!(os.mark_spent(ki), Err(PrivacyError::DoubleSpend)));
    }

    #[test]
    fn test_ring_signature_sign_and_verify() {
        let priv_scalar = hash_to_scalar(&[10u8; 32], b"TEST_PRIV");
        let real_priv   = priv_scalar.to_bytes();
        let real_pub    = (priv_scalar * G).compress().to_bytes();
        let decoys: Vec<[u8; 32]> = (1..RING_SIZE)
            .map(|i| (Scalar::from(i as u64) * G).compress().to_bytes())
            .collect();
        let sig = RingSignature::sign(b"test_msg", &real_priv, &real_pub, decoys, 3).unwrap();
        assert!(sig.verify(b"test_msg"));
        assert_eq!(sig.ring.len(), RING_SIZE);
        assert_eq!(sig.sig_data.len(), (RING_SIZE + 1) * 32);
    }

    #[test]
    fn test_ring_signature_wrong_message_fails() {
        let priv_scalar = hash_to_scalar(&[20u8; 32], b"TEST_PRIV");
        let real_priv   = priv_scalar.to_bytes();
        let real_pub    = (priv_scalar * G).compress().to_bytes();
        let decoys: Vec<[u8; 32]> = (1..RING_SIZE)
            .map(|i| (Scalar::from(i as u64) * G).compress().to_bytes())
            .collect();
        let sig = RingSignature::sign(b"correct", &real_priv, &real_pub, decoys, 0).unwrap();
        assert!(!sig.verify(b"wrong"));
    }

    #[test]
    fn test_bulletproof_prove_and_verify() {
        let amount  = VusdAmount::from_usd_8dec(50_000_00000000);
        let blinding = [3u8; 32];
        assert!(BulletproofRangeProof::prove(&amount, &blinding).verify());
    }

    #[test]
    fn test_bulletproof_zero_amount() {
        assert!(BulletproofRangeProof::prove(&VusdAmount::ZERO, &[1u8; 32]).verify());
    }

    #[test]
    fn test_privacy_layer_mint_and_scan() {
        let layer  = PrivacyLayer::new();
        let wallet = StealthWallet::generate(&[1u8; 32]);
        let amount = VusdAmount::from_usd_8dec(10_000_00000000);

        for i in 0..15u8 {
            let dw = StealthWallet::generate(&[i + 100u8; 32]);
            layer.create_mint_output(VusdAmount::from_usd_8dec(1_000_00000000), &dw).unwrap();
        }

        let output = layer.create_mint_output(amount, &wallet).unwrap();
        assert_eq!(layer.output_set.output_count(), 16);
        assert!(wallet.scan_output(&output.ephemeral_pubkey, &output.stealth_address).is_some());
        assert!(output.range_proof.verify());
    }

    #[test]
    fn test_full_transfer() {
        let layer     = PrivacyLayer::new();
        let sender    = StealthWallet::generate(&[1u8; 32]);
        let recipient = StealthWallet::generate(&[2u8; 32]);
        let amount    = VusdAmount::from_usd_8dec(5_000_00000000);
        let fee       = VusdAmount::from_usd_8dec(10_00000000);

        // Populate output set with decoys so ring can be built
        for i in 0..15u8 {
            let dw = StealthWallet::generate(&[i + 50u8; 32]);
            layer.create_mint_output(amount, &dw).unwrap();
        }

        // Mint input to sender
        let input   = layer.create_mint_output(amount, &sender).unwrap();
        // Derive the blinding that create_mint_output used internally.
        // We do this by re-deriving from the ephemeral pubkey, since the
        // blinding = hash_to_scalar(ephemeral_seed, "VUSD_OUTPUT_BLIND").
        // But the ephemeral_seed is opaque to us now — what we CAN do is use
        // the privkey derived by scan_output and a dummy blinding for the test,
        // since create_transfer also generates its own fresh seed internally.
        let privkey  = sender.scan_output(&input.ephemeral_pubkey, &input.stealth_address).unwrap();
        let blinding = [0u8; 32]; // test only — blinding for commitment doesn't affect ring sig path

        let tx = layer.create_transfer(
            &input, &privkey, &blinding, &recipient, amount, fee,
        ).unwrap();

        assert_eq!(tx.inputs.len(), 1);
        assert!(tx.inputs[0].verify(&compute_tx_message(&amount, &fee)));
        assert!(tx.outputs[0].range_proof.verify());
    }
}
