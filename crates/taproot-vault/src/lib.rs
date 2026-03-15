// crates/taproot-vault/src/lib.rs
//
// Phase III — Taproot Vault Layer
//
// This crate handles all Bitcoin L1 interaction for VSCx vaults.
// Each vault is anchored to a single P2TR (Pay-to-Taproot) output with
// a 3-leaf MAST (Merkelized Abstract Syntax Tree):
//
//   TapRoot Output (P2TR)
//   │
//   ├── KeyPath: owner_internal_key (cooperative close — cheapest path)
//   │
//   └── ScriptPath: MAST Root
//         ├── Leaf A: Repay Branch
//         │     owner_sig + VUSD burn proof
//         ├── Leaf B: Liquidation Branch
//         │     keeper_sig + oracle_proof + auction_winner
//         └── Leaf C: Emergency Timelock
//               owner_sig after 26,280 blocks (~6 months)
//
// Phase I/II: This crate uses mock Bitcoin operations (no real node required).
// Phase III (testnet): Replace MockBitcoinClient with real bitcoin-rpc calls
//                      using rust-bitcoin + BDK.

pub mod btc_tx;
pub mod signet_btc;
pub use btc_tx::{TaprootVault, VaultScripts, TxBuildError, to_bitcoin_xonly};
pub use signet_btc::SignetBtcLayer;

use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};
use thiserror::Error;
use vscx_core::{
    BitcoinAddress, OutPoint, Satoshis, VaultId, XOnlyPubkey,
    VusdAmount, MockBtcLayer, current_time_secs,
    EMERGENCY_TIMELOCK_BLOCKS,
};

// ─────────────────────────────────────────────────────────────────────────────
// ERRORS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum TaprootError {
    #[error("UTXO not found or already spent: {0}")]
    UtxoNotFound(String),

    #[error("Script verification failed for leaf {leaf}")]
    ScriptVerificationFailed { leaf: String },

    #[error("Timelock not yet satisfied: need block {need}, current {current}")]
    TimelockNotSatisfied { need: u64, current: u64 },

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),

    #[error("Bitcoin node error: {0}")]
    NodeError(String),

    #[error("Signature invalid")]
    InvalidSignature,
}

// ─────────────────────────────────────────────────────────────────────────────
// TAPROOT SCRIPT TYPES
// ─────────────────────────────────────────────────────────────────────────────

/// The version byte for Taproot leaf scripts (BIP-341).
pub const TAPROOT_LEAF_VERSION: u8 = 0xC0;

/// A single leaf in the MAST tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapLeaf {
    pub version: u8,
    pub script: TapScript,
    /// SHA256(version || script_bytes) — used in MAST construction.
    pub leaf_hash: [u8; 32],
}

impl TapLeaf {
    pub fn new(script: TapScript) -> Self {
        let script_bytes = script.serialize();
        let leaf_hash = tagged_hash("TapLeaf", &{
            let mut data = vec![TAPROOT_LEAF_VERSION];
            data.extend_from_slice(&(script_bytes.len() as u64).to_le_bytes());
            data.extend_from_slice(&script_bytes);
            data
        });
        TapLeaf { version: TAPROOT_LEAF_VERSION, script, leaf_hash }
    }
}

/// Script types for vault spending conditions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TapScript {
    /// Leaf A: owner can spend by providing sig + burn proof
    RepayBranch {
        owner_pubkey: XOnlyPubkey,
    },
    /// Leaf B: keeper can spend with oracle proof + auction winner
    LiquidationBranch {
        keeper_pubkey: XOnlyPubkey,
        min_oracle_sigs: u8,
    },
    /// Leaf C: owner can spend after timelock (26,280 blocks ≈ 6 months)
    EmergencyTimelock {
        owner_pubkey: XOnlyPubkey,
        block_height_lock: u32,
    },
}

impl TapScript {
    /// Serialize to Bitcoin script bytes.
    /// Phase I: Simplified encoding. Phase III: Real Bitcoin Script opcodes.
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            TapScript::RepayBranch { owner_pubkey } => {
                let mut s = vec![0x01]; // OP_REPAY marker
                s.extend_from_slice(&owner_pubkey.0);
                s.push(0xAC); // OP_CHECKSIG
                s
            }
            TapScript::LiquidationBranch { keeper_pubkey, min_oracle_sigs } => {
                let mut s = vec![0x02]; // OP_LIQUIDATION marker
                s.push(*min_oracle_sigs);
                s.extend_from_slice(&keeper_pubkey.0);
                s.push(0xAE); // OP_CHECKMULTISIG
                s
            }
            TapScript::EmergencyTimelock { owner_pubkey, block_height_lock } => {
                let mut s = vec![0x03]; // OP_EMERGENCY marker
                s.extend_from_slice(&block_height_lock.to_le_bytes());
                s.push(0xB1); // OP_CHECKLOCKTIMEVERIFY
                s.push(0x75); // OP_DROP
                s.extend_from_slice(&owner_pubkey.0);
                s.push(0xAC); // OP_CHECKSIG
                s
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MAST CONSTRUCTION
// ─────────────────────────────────────────────────────────────────────────────

/// The complete Taproot MAST for a vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMast {
    /// The vault owner's internal key (used for KeyPath spending).
    pub internal_key: XOnlyPubkey,
    /// Leaf A: repay branch
    pub leaf_repay: TapLeaf,
    /// Leaf B: liquidation branch
    pub leaf_liquidation: TapLeaf,
    /// Leaf C: emergency timelock
    pub leaf_emergency: TapLeaf,
    /// MAST root hash (Merkle root of all leaves).
    pub merkle_root: [u8; 32],
    /// The tweaked output key (what appears on-chain as the P2TR address).
    pub output_key: XOnlyPubkey,
    /// Block height at which this vault was created (for timelock calculation).
    pub open_block_height: u32,
}

impl VaultMast {
    /// Construct a VaultMast for a new vault.
    ///
    /// `protocol_keeper_pubkey` is the protocol-wide keeper key embedded in
    /// Leaf B. It must never be the owner's pubkey — using the owner's key
    /// would reveal their identity on-chain whenever a liquidation occurs.
    /// Pass `PROTOCOL_KEEPER_PUBKEY` from vscx_core::types for all normal use.
    pub fn new(
        owner_pubkey:           XOnlyPubkey,
        protocol_keeper_pubkey: XOnlyPubkey,
        open_block_height:      u32,
    ) -> Self {
        let leaf_repay = TapLeaf::new(TapScript::RepayBranch {
            owner_pubkey,
        });

        // Leaf B embeds the protocol keeper key, NOT the owner's key.
        // Spending this leaf reveals only the protocol pubkey — identical
        // across all vaults — not anything specific to this owner.
        let leaf_liquidation = TapLeaf::new(TapScript::LiquidationBranch {
            keeper_pubkey: protocol_keeper_pubkey,
            min_oracle_sigs: 5,
        });

        let emergency_lock_height = open_block_height + EMERGENCY_TIMELOCK_BLOCKS;
        let leaf_emergency = TapLeaf::new(TapScript::EmergencyTimelock {
            owner_pubkey,
            block_height_lock: emergency_lock_height,
        });

        // Compute Merkle root: TapBranch(TapBranch(leaf_A, leaf_B), leaf_C)
        let branch_ab = tap_branch(&leaf_repay.leaf_hash, &leaf_liquidation.leaf_hash);
        let merkle_root = tap_branch(&branch_ab, &leaf_emergency.leaf_hash);

        // Compute output key: internal_key tweaked by H_taptweak(internal_key || merkle_root)
        let output_key = compute_taproot_output_key(&owner_pubkey, &merkle_root);

        VaultMast {
            internal_key: owner_pubkey,
            leaf_repay,
            leaf_liquidation,
            leaf_emergency,
            merkle_root,
            output_key,
            open_block_height,
        }
    }

    /// Returns the P2TR address string for this vault.
    /// Phase I: hex encoding of output key.
    /// Phase III: real bech32m address using rust-bitcoin.
    pub fn p2tr_address(&self) -> String {
        format!("tb1p{}", hex_encode(&self.output_key.0))
    }

    /// Returns the Merkle proof (sibling hashes) for spending Leaf A (repay).
    pub fn repay_merkle_proof(&self) -> Vec<[u8; 32]> {
        let branch_ab_complement = tap_branch(&self.leaf_repay.leaf_hash, &self.leaf_liquidation.leaf_hash);
        vec![
            self.leaf_liquidation.leaf_hash, // sibling of leaf_A in branch_AB
            self.leaf_emergency.leaf_hash,   // sibling of branch_AB in root
        ]
    }

    /// Returns the Merkle proof for spending Leaf B (liquidation).
    pub fn liquidation_merkle_proof(&self) -> Vec<[u8; 32]> {
        vec![
            self.leaf_repay.leaf_hash,       // sibling of leaf_B in branch_AB
            self.leaf_emergency.leaf_hash,   // sibling of branch_AB in root
        ]
    }

    /// Returns the Merkle proof for spending Leaf C (emergency).
    pub fn emergency_merkle_proof(&self) -> Vec<[u8; 32]> {
        let branch_ab = tap_branch(&self.leaf_repay.leaf_hash, &self.leaf_liquidation.leaf_hash);
        vec![
            branch_ab, // sibling of leaf_C in root
        ]
    }
}

fn tap_branch(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // BIP-341: TapBranch = H_tapbranch(sort(left, right))
    let (a, b) = if left <= right { (left, right) } else { (right, left) };
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(a);
    data.extend_from_slice(b);
    tagged_hash("TapBranch", &data)
}

fn compute_taproot_output_key(internal_key: &XOnlyPubkey, merkle_root: &[u8; 32]) -> XOnlyPubkey {
    // BIP-341: output_key = internal_key + H_taptweak(internal_key || merkle_root) * G
    // Phase I: Simplified — output_key = SHA256("taptweak" || internal_key || merkle_root)
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&internal_key.0);
    data.extend_from_slice(merkle_root);
    let tweaked = tagged_hash("TapTweak", &data);
    // XOR internal_key with tweak (phase I approximation)
    let mut output = [0u8; 32];
    for i in 0..32 {
        output[i] = internal_key.0[i] ^ tweaked[i];
    }
    XOnlyPubkey(output)
}

fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(tag.as_bytes());
        let r = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&r);
        out
    };
    let mut h = Sha256::new();
    h.update(&tag_hash);
    h.update(&tag_hash);
    h.update(data);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// SPEND PATH CONSTRUCTION
// ─────────────────────────────────────────────────────────────────────────────

/// Represents a constructed witness for a specific Taproot spending path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaprootWitness {
    pub spend_path: SpendPath,
    pub witness_stack: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpendPath {
    /// KeyPath: cheapest, most private. No script revealed.
    KeyPath,
    /// ScriptPath via Leaf A (repay).
    RepayLeaf,
    /// ScriptPath via Leaf B (liquidation).
    LiquidationLeaf,
    /// ScriptPath via Leaf C (emergency timelock).
    EmergencyTimelock,
}

impl TaprootWitness {
    /// Construct a KeyPath witness (cooperative close).
    /// Requires owner's Schnorr signature over the spending transaction.
    pub fn keypath(owner_sig: Vec<u8>) -> Self {
        TaprootWitness {
            spend_path: SpendPath::KeyPath,
            witness_stack: vec![owner_sig],
        }
    }

    /// Construct a Leaf A (repay) witness.
    pub fn repay_leaf(
        owner_sig: Vec<u8>,
        burn_proof_hash: [u8; 32],
        leaf_script: Vec<u8>,
        merkle_proof: Vec<[u8; 32]>,
        internal_key: XOnlyPubkey,
    ) -> Self {
        let mut stack = vec![
            owner_sig,
            burn_proof_hash.to_vec(),
            leaf_script,
        ];
        // Control block = leaf_version || internal_key || merkle_proof_hashes
        let mut control_block = vec![TAPROOT_LEAF_VERSION];
        control_block.extend_from_slice(&internal_key.0);
        for proof_hash in merkle_proof {
            control_block.extend_from_slice(&proof_hash);
        }
        stack.push(control_block);
        TaprootWitness {
            spend_path: SpendPath::RepayLeaf,
            witness_stack: stack,
        }
    }

    /// Construct a Leaf B (liquidation) witness.
    pub fn liquidation_leaf(
        keeper_sig: Vec<u8>,
        oracle_sigs: Vec<Vec<u8>>,
        auction_winner_proof: [u8; 32],
        leaf_script: Vec<u8>,
        merkle_proof: Vec<[u8; 32]>,
        internal_key: XOnlyPubkey,
    ) -> Self {
        let mut stack = vec![
            keeper_sig,
            auction_winner_proof.to_vec(),
        ];
        for sig in oracle_sigs {
            stack.push(sig);
        }
        stack.push(leaf_script);
        let mut control_block = vec![TAPROOT_LEAF_VERSION];
        control_block.extend_from_slice(&internal_key.0);
        for proof_hash in merkle_proof {
            control_block.extend_from_slice(&proof_hash);
        }
        stack.push(control_block);
        TaprootWitness {
            spend_path: SpendPath::LiquidationLeaf,
            witness_stack: stack,
        }
    }

    /// Construct a Leaf C (emergency timelock) witness.
    pub fn emergency_timelock(
        owner_sig: Vec<u8>,
        leaf_script: Vec<u8>,
        merkle_proof: Vec<[u8; 32]>,
        internal_key: XOnlyPubkey,
    ) -> Self {
        let mut stack = vec![
            owner_sig,
            leaf_script,
        ];
        let mut control_block = vec![TAPROOT_LEAF_VERSION];
        control_block.extend_from_slice(&internal_key.0);
        for proof_hash in merkle_proof {
            control_block.extend_from_slice(&proof_hash);
        }
        stack.push(control_block);
        TaprootWitness {
            spend_path: SpendPath::EmergencyTimelock,
            witness_stack: stack,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VAULT TAPROOT CLIENT
// ─────────────────────────────────────────────────────────────────────────────

/// Manages all Taproot operations for vault open/close/liquidate.
///
/// T4: Now generic over BtcLayer. Accepts either MockBtcLayer (tests) or
/// SignetBtcLayer (testnet) via Arc<dyn BtcLayer>.
pub struct VaultTaprootClient {
    pub btc: std::sync::Arc<dyn vscx_core::BtcLayer>,
}

impl VaultTaprootClient {
    /// Construct with any BtcLayer implementation.
    pub fn new(btc: impl vscx_core::BtcLayer + 'static) -> Self {
        VaultTaprootClient { btc: std::sync::Arc::new(btc) }
    }

    /// Construct with a pre-boxed Arc<dyn BtcLayer> (useful when sharing the layer).
    pub fn with_arc_btc(btc: std::sync::Arc<dyn vscx_core::BtcLayer>) -> Self {
        VaultTaprootClient { btc }
    }

    /// Open a vault: construct MAST via TaprootVault, lock BTC in P2TR output.
    ///
    /// T4: VaultScripts are built from the owner pubkey and stored in the MAST so
    ///     close/liquidation paths have the correct script for witness assembly.
    /// T5/T6: btc.lock_btc() on SignetBtcLayer will broadcast the real funding tx.
    ///
    /// Returns (OutPoint of the locked UTXO, VaultMast)
    pub fn open_vault(
        &self,
        owner_pubkey: XOnlyPubkey,
        collateral_sats: Satoshis,
        current_block_height: u32,
        repay_hash: [u8; 32],
    ) -> Result<(OutPoint, VaultMast), TaprootError> {
        let mast = VaultMast::new(
            owner_pubkey,
            vscx_core::PROTOCOL_KEEPER_PUBKEY,
            current_block_height,
        );

        // T4: Build TaprootVault MAST to derive the canonical P2TR address.
        // This verifies the MAST can be constructed from the owner pubkey before
        // committing funds. The address is logged for on-chain verification.
        let btc_owner = btc_tx::to_bitcoin_xonly(&owner_pubkey)
            .map_err(|e| TaprootError::InvalidWitness(e.to_string()))?;
        let btc_keeper = btc_tx::to_bitcoin_xonly(&vscx_core::PROTOCOL_KEEPER_PUBKEY)
            .map_err(|e| TaprootError::InvalidWitness(e.to_string()))?;

        // A6: repay_hash is passed in from the engine — it was committed at vault open
        // via open_vault(). The MAST Leaf A is: OP_SHA256 <repay_hash> OP_EQUALVERIFY <owner_key> OP_CHECKSIG.
        // When the owner repays their debt, the engine reveals the preimage.
        // The owner presents (preimage, owner_sig) in the witness to spend Leaf A.

        let scripts = VaultScripts::build(
            &btc_owner,
            &btc_keeper,
            &repay_hash,
            EMERGENCY_TIMELOCK_BLOCKS as u16,
        ).map_err(|e| TaprootError::InvalidWitness(e.to_string()))?;

        let taproot_vault = TaprootVault::build(scripts, bitcoin::Network::Signet)
            .map_err(|e| TaprootError::InvalidWitness(e.to_string()))?;

        tracing::info!(
            p2tr_address = %taproot_vault.address,
            legacy_address = %mast.p2tr_address(),
            collateral = %collateral_sats,
            merkle_root = %hex_encode(&mast.merkle_root),
            "Vault P2TR output constructed (T4: real MAST address computed)"
        );

        // T5/T6: on SignetBtcLayer, lock_btc broadcasts the real funding tx.
        // On MockBtcLayer, this returns a synthetic OutPoint instantly.
        let utxo = self.btc.lock_btc(collateral_sats, owner_pubkey);

        Ok((utxo, mast))
    }

    /// Close a vault via KeyPath (cooperative close — most private).
    pub fn close_vault_keypath(
        &self,
        utxo: &OutPoint,
        owner_sig: Vec<u8>,
        return_address: &BitcoinAddress,
    ) -> Result<OutPoint, TaprootError> {
        // Phase I: mock spend. Phase III: construct spending tx with KeyPath witness.
        let spend_tx = self.btc.unlock_btc(utxo, return_address)
            .map_err(|e| TaprootError::UtxoNotFound(e))?;

        tracing::info!(
            utxo = %utxo,
            return_address = %return_address,
            "Vault closed via KeyPath"
        );

        Ok(spend_tx)
    }

    /// Close a vault via Leaf A (repay branch — script path).
    pub fn close_vault_repay_leaf(
        &self,
        utxo: &OutPoint,
        mast: &VaultMast,
        owner_sig: Vec<u8>,
        burn_proof_hash: [u8; 32],
        return_address: &BitcoinAddress,
    ) -> Result<OutPoint, TaprootError> {
        let proof = mast.repay_merkle_proof();
        let witness = TaprootWitness::repay_leaf(
            owner_sig,
            burn_proof_hash,
            mast.leaf_repay.script.serialize(),
            proof,
            mast.internal_key,
        );

        // Phase I: mock spend. Phase III: broadcast spending tx with script path witness.
        let spend_tx = self.btc.unlock_btc(utxo, return_address)
            .map_err(|e| TaprootError::UtxoNotFound(e))?;

        tracing::info!(
            utxo = %utxo,
            spend_path = "RepayLeaf",
            "Vault closed via Leaf A"
        );

        Ok(spend_tx)
    }

    /// Liquidate a vault via Leaf B.
    pub fn liquidate_vault(
        &self,
        utxo: &OutPoint,
        mast: &VaultMast,
        keeper_sig: Vec<u8>,
        oracle_sigs: Vec<Vec<u8>>,
        auction_winner_proof: [u8; 32],
        winner_address: &BitcoinAddress,
        keeper_address: &BitcoinAddress,
        keeper_bonus_sats: Satoshis,
    ) -> Result<OutPoint, TaprootError> {
        if oracle_sigs.len() < 5 {
            return Err(TaprootError::InvalidWitness(
                format!("Need 5 oracle sigs, got {}", oracle_sigs.len())
            ));
        }

        let proof = mast.liquidation_merkle_proof();
        let witness = TaprootWitness::liquidation_leaf(
            keeper_sig,
            oracle_sigs,
            auction_winner_proof,
            mast.leaf_liquidation.script.serialize(),
            proof,
            mast.internal_key,
        );

        // Phase I: send full amount to winner (simplified).
        // Phase III: build tx with 2 outputs: winner + keeper.
        let spend_tx = self.btc.unlock_btc(utxo, winner_address)
            .map_err(|e| TaprootError::UtxoNotFound(e))?;

        tracing::info!(
            utxo = %utxo,
            spend_path = "LiquidationLeaf",
            winner = %winner_address,
            keeper_bonus = %keeper_bonus_sats,
            "Vault liquidated via Leaf B"
        );

        Ok(spend_tx)
    }

    /// Recover vault via Leaf C (emergency timelock) after 26,280 blocks.
    pub fn recover_vault_emergency(
        &self,
        utxo: &OutPoint,
        mast: &VaultMast,
        owner_sig: Vec<u8>,
        current_block_height: u32,
        return_address: &BitcoinAddress,
    ) -> Result<OutPoint, TaprootError> {
        let unlock_height = mast.open_block_height + EMERGENCY_TIMELOCK_BLOCKS;
        if current_block_height < unlock_height {
            return Err(TaprootError::TimelockNotSatisfied {
                need: unlock_height as u64,
                current: current_block_height as u64,
            });
        }

        let proof = mast.emergency_merkle_proof();
        let witness = TaprootWitness::emergency_timelock(
            owner_sig,
            mast.leaf_emergency.script.serialize(),
            proof,
            mast.internal_key,
        );

        let spend_tx = self.btc.unlock_btc(utxo, return_address)
            .map_err(|e| TaprootError::UtxoNotFound(e))?;

        tracing::info!(
            utxo = %utxo,
            spend_path = "EmergencyTimelock",
            "Vault recovered via emergency timelock"
        );

        Ok(spend_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vscx_core::MockBtcLayer;

    fn owner_pk() -> XOnlyPubkey { XOnlyPubkey([0xABu8; 32]) }

    #[test]
    fn test_mast_construction() {
        let owner = owner_pk();
        let mast = VaultMast::new(owner, vscx_core::PROTOCOL_KEEPER_PUBKEY, 800_000);

        // All leaf hashes should be distinct
        assert_ne!(mast.leaf_repay.leaf_hash, mast.leaf_liquidation.leaf_hash);
        assert_ne!(mast.leaf_repay.leaf_hash, mast.leaf_emergency.leaf_hash);
        assert_ne!(mast.leaf_liquidation.leaf_hash, mast.leaf_emergency.leaf_hash);

        // Merkle root should be deterministic
        let mast2 = VaultMast::new(owner, vscx_core::PROTOCOL_KEEPER_PUBKEY, 800_000);
        assert_eq!(mast.merkle_root, mast2.merkle_root);

        // Output key should differ from internal key (it was tweaked)
        assert_ne!(mast.output_key.0, mast.internal_key.0);
    }

    #[test]
    fn test_different_owners_different_mast() {
        let owner1 = XOnlyPubkey([0x01u8; 32]);
        let owner2 = XOnlyPubkey([0x02u8; 32]);
        let mast1 = VaultMast::new(owner1, vscx_core::PROTOCOL_KEEPER_PUBKEY, 800_000);
        let mast2 = VaultMast::new(owner2, vscx_core::PROTOCOL_KEEPER_PUBKEY, 800_000);
        assert_ne!(mast1.merkle_root, mast2.merkle_root);
        assert_ne!(mast1.output_key.0, mast2.output_key.0);
    }

    #[test]
    fn test_open_vault_keypath_close() {
        let btc = MockBtcLayer::new();
        let client = VaultTaprootClient::new(btc);
        let owner = owner_pk();

        let (utxo, mast) = client.open_vault(owner, Satoshis::ONE_BTC, 800_000, [0xABu8; 32]).unwrap();
        assert!(client.btc.is_utxo_unspent(&utxo));

        let dummy_sig = vec![0u8; 64];
        let return_addr = BitcoinAddress::new("tb1p_owner_return");
        client.close_vault_keypath(&utxo, dummy_sig, &return_addr).unwrap();

        assert!(!client.btc.is_utxo_unspent(&utxo));
    }

    #[test]
    fn test_liquidation_leaf_spend() {
        let btc = MockBtcLayer::new();
        let client = VaultTaprootClient::new(btc);
        let owner = owner_pk();

        let (utxo, mast) = client.open_vault(owner, Satoshis::ONE_BTC, 800_000, [0xABu8; 32]).unwrap();

        let keeper_sig = vec![0xCCu8; 64];
        let oracle_sigs = vec![
            vec![1u8; 32], vec![2u8; 32], vec![3u8; 32], vec![4u8; 32], vec![5u8; 32]
        ];
        let auction_winner_proof = [0xFFu8; 32];
        let winner_addr = BitcoinAddress::new("tb1p_winner");
        let keeper_addr = BitcoinAddress::new("tb1p_keeper");

        client.liquidate_vault(
            &utxo, &mast, keeper_sig, oracle_sigs, auction_winner_proof,
            &winner_addr, &keeper_addr, Satoshis(2_000_000),
        ).unwrap();

        assert!(!client.btc.is_utxo_unspent(&utxo));
    }

    #[test]
    fn test_emergency_timelock_before_expiry_rejected() {
        let btc = MockBtcLayer::new();
        let client = VaultTaprootClient::new(btc);
        let owner = owner_pk();

        let open_height = 800_000u32;
        let (utxo, mast) = client.open_vault(owner, Satoshis::ONE_BTC, open_height, [0xABu8; 32]).unwrap();

        let current_height = 800_000 + 100; // way before 26,280 block timelock
        let result = client.recover_vault_emergency(
            &utxo, &mast, vec![0u8; 64], current_height,
            &BitcoinAddress::new("tb1p_owner"),
        );

        assert!(matches!(result, Err(TaprootError::TimelockNotSatisfied { .. })));
    }

    #[test]
    fn test_emergency_timelock_after_expiry_succeeds() {
        let btc = MockBtcLayer::new();
        let client = VaultTaprootClient::new(btc);
        let owner = owner_pk();

        let open_height = 800_000u32;
        let (utxo, mast) = client.open_vault(owner, Satoshis::ONE_BTC, open_height, [0xABu8; 32]).unwrap();

        let current_height = open_height + EMERGENCY_TIMELOCK_BLOCKS + 1;
        let result = client.recover_vault_emergency(
            &utxo, &mast, vec![0u8; 64], current_height,
            &BitcoinAddress::new("tb1p_owner"),
        );

        assert!(result.is_ok());
        assert!(!client.btc.is_utxo_unspent(&utxo));
    }

    #[test]
    fn test_merkle_proofs_are_distinct() {
        let owner = owner_pk();
        let mast = VaultMast::new(owner, vscx_core::PROTOCOL_KEEPER_PUBKEY, 800_000);

        let repay_proof = mast.repay_merkle_proof();
        let liq_proof   = mast.liquidation_merkle_proof();
        let emerg_proof = mast.emergency_merkle_proof();

        // Proofs should be different (they cover different leaves)
        assert_ne!(repay_proof[0], liq_proof[0]);
        // Emergency proof has only 1 element (branch_AB is its only sibling)
        assert_eq!(emerg_proof.len(), 1);
    }
}
