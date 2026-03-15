// crates/taproot-vault/src/btc_tx.rs
//
// Bitcoin signet/mainnet transaction building for VSCx vault operations.
//
// Uses rust-bitcoin 0.31 to construct real Taproot transactions for:
//   - open_vault:  P2TR output locking BTC into a 3-leaf MAST
//   - close_vault: spending via Leaf A (repay script), returning BTC to owner
//   - liquidate:   spending via Leaf B (liquidation script), sending to bidder
//   - emergency:   spending via Leaf C (CSV timelock), owner-only recovery
//
// The tapscripts are built to match the 3-leaf MAST defined in VaultMast.
// Key path spending (MuSig2 aggregate key) is a future upgrade — all paths
// currently use script path spending.
//
// SIGNET vs MAINNET: controlled by the Network parameter.
// Never use mainnet private keys on signet. Always test on signet first.

use bitcoin::{
    absolute::LockTime,
    address::NetworkChecked,
    key::UntweakedPublicKey,
    opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP, OP_EQUALVERIFY, OP_SHA256},
    script::{Builder as ScriptBuilder, PushBytesBuf},
    secp256k1::{All, Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
    taproot::{
        LeafVersion, TaprootBuilder, TaprootSpendInfo,
    },
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use sha2::{Digest, Sha256};
use std::str::FromStr;
use thiserror::Error;
use vscx_core::{Satoshis, XOnlyPubkey as VusdXOnly};
use serde_json;

#[derive(Debug, Error)]
pub enum TxBuildError {
    #[error("Invalid public key: {0}")]
    InvalidPubkey(String),
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Taproot build error: {0}")]
    TaprootError(String),
    #[error("Insufficient funds: have {have_sats} sats, need {need_sats} sats")]
    InsufficientFunds { have_sats: u64, need_sats: u64 },
    #[error("Script error: {0}")]
    ScriptError(String),
}

/// Fee rate in sat/vbyte for vault transactions.
/// Conservative default — keeper/close operations can use lower rates.
pub const DEFAULT_FEE_RATE_SAT_VB: u64 = 10;

/// Approximate vbyte size for a 1-input 1-output P2TR script-path spend.
/// Exact size depends on the tapscript and witness stack. This is a safe upper bound.
pub const TAPROOT_SPEND_VBYTES: u64 = 200;

/// The three script leaves of the VUSD vault MAST.
/// Must match the scripts in VaultMast (crates/taproot-vault/src/lib.rs).
#[derive(Debug, Clone)]
pub struct VaultScripts {
    /// Leaf A: repay script — owner key + SHA256 preimage of repay hash.
    pub repay:      ScriptBuf,
    /// Leaf B: liquidation script — keeper key after oracle confirms undercollat.
    pub liquidation: ScriptBuf,
    /// Leaf C: emergency timelock — owner key only, after EMERGENCY_TIMELOCK_BLOCKS.
    pub emergency:  ScriptBuf,
}

impl VaultScripts {
    /// Build the three tapscripts for a vault.
    ///
    /// repay_hash:    SHA256 of the "repay preimage" that the engine issues when debt is cleared.
    /// owner_xonly:   vault owner's x-only pubkey (secp256k1).
    /// keeper_xonly:  any keeper pubkey OR the aggregated keeper set pubkey.
    /// timelock_blocks: emergency CSV (default: 26,280 = ~6 months).
    pub fn build(
        owner_xonly:     &XOnlyPublicKey,
        keeper_xonly:    &XOnlyPublicKey,
        repay_hash:      &[u8; 32],
        timelock_blocks: u16,
    ) -> Result<Self, TxBuildError> {
        // ── Leaf A: Repay ────────────────────────────────────────────────────
        // OP_SHA256 <repay_hash> OP_EQUALVERIFY <owner_key> OP_CHECKSIG
        let mut repay_hash_push = PushBytesBuf::new();
        repay_hash_push.extend_from_slice(repay_hash)
            .map_err(|e| TxBuildError::ScriptError(e.to_string()))?;

        let mut owner_key_push = PushBytesBuf::new();
        owner_key_push.extend_from_slice(&owner_xonly.serialize())
            .map_err(|e| TxBuildError::ScriptError(e.to_string()))?;

        let repay = ScriptBuilder::new()
            .push_opcode(OP_SHA256)
            .push_slice(repay_hash_push.as_push_bytes())
            .push_opcode(OP_EQUALVERIFY)
            .push_slice(owner_key_push.as_push_bytes())
            .push_opcode(OP_CHECKSIG)
            .into_script();

        // ── Leaf B: Liquidation ──────────────────────────────────────────────
        // <keeper_key> OP_CHECKSIG
        let mut keeper_key_push = PushBytesBuf::new();
        keeper_key_push.extend_from_slice(&keeper_xonly.serialize())
            .map_err(|e| TxBuildError::ScriptError(e.to_string()))?;

        let liquidation = ScriptBuilder::new()
            .push_slice(keeper_key_push.as_push_bytes())
            .push_opcode(OP_CHECKSIG)
            .into_script();

        // ── Leaf C: Emergency Timelock ────────────────────────────────────────
        // <timelock_blocks> OP_CSV OP_DROP <owner_key> OP_CHECKSIG
        let mut owner_key_push2 = PushBytesBuf::new();
        owner_key_push2.extend_from_slice(&owner_xonly.serialize())
            .map_err(|e| TxBuildError::ScriptError(e.to_string()))?;

        let emergency = ScriptBuilder::new()
            .push_int(timelock_blocks as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_slice(owner_key_push2.as_push_bytes())
            .push_opcode(OP_CHECKSIG)
            .into_script();

        Ok(VaultScripts { repay, liquidation, emergency })
    }
}

/// A built Taproot vault — the P2TR address and full spend info.
#[derive(Debug)]
pub struct TaprootVault {
    pub scripts:    VaultScripts,
    pub spend_info: TaprootSpendInfo,
    pub address:    Address<NetworkChecked>,
    pub network:    Network,
}

impl TaprootVault {
    /// Build the Taproot MAST and derive the P2TR vault address.
    ///
    /// Tree structure (BIP-341 MAST):
    ///   - internal key: unspendable (NUMS point — no key path)
    ///   - leaf A (depth 2): repay script      weight 1
    ///   - leaf B (depth 2): liquidation script weight 1
    ///   - leaf C (depth 1): emergency script   weight 2  (higher in tree = more likely path)
    pub fn build(
        scripts:  VaultScripts,
        network:  Network,
    ) -> Result<Self, TxBuildError> {
        let secp = Secp256k1::new();

        // NUMS (Nothing-Up-My-Sleeve) internal key — no key path spending.
        // H = hash_to_curve("VUSD_NUMS_KEY") — unknown discrete log.
        let nums_bytes = nums_internal_key();
        let internal_key = UntweakedPublicKey::from_slice(&nums_bytes)
            .map_err(|e| TxBuildError::TaprootError(e.to_string()))?;

        // Build MAST: A and B at depth 2, C at depth 1
        let builder = TaprootBuilder::new()
            .add_leaf(2, scripts.repay.clone())
            .map_err(|e| TxBuildError::TaprootError(format!("{:?}", e)))?
            .add_leaf(2, scripts.liquidation.clone())
            .map_err(|e| TxBuildError::TaprootError(format!("{:?}", e)))?
            .add_leaf(1, scripts.emergency.clone())
            .map_err(|e| TxBuildError::TaprootError(format!("{:?}", e)))?;

        let spend_info = builder
            .finalize(&secp, internal_key)
            .map_err(|e| TxBuildError::TaprootError(format!("{:?}", e)))?;

        let address = Address::p2tr_tweaked(spend_info.output_key(), network);

        Ok(TaprootVault { scripts, spend_info, address, network })
    }

    /// Build the unsigned funding transaction (open vault).
    ///
    /// caller_utxo: the UTXO the vault owner will spend to fund the vault
    /// caller_input_sats: amount in that UTXO
    /// vault_sats: amount to lock in the vault (must be <= caller_input_sats - fee)
    /// change_address: where to send the change
    pub fn build_open_tx(
        &self,
        caller_utxo:       OutPoint,
        caller_input_sats: u64,
        vault_sats:        u64,
        change_address:    &str,
    ) -> Result<Transaction, TxBuildError> {
        let fee_sats = DEFAULT_FEE_RATE_SAT_VB * TAPROOT_SPEND_VBYTES;
        let total_needed = vault_sats + fee_sats;

        if caller_input_sats < total_needed {
            return Err(TxBuildError::InsufficientFunds {
                have_sats: caller_input_sats,
                need_sats: total_needed,
            });
        }

        let change_sats = caller_input_sats - total_needed;
        let change_addr = Address::from_str(change_address)
            .map_err(|e| TxBuildError::InvalidAddress(e.to_string()))?
            .require_network(self.network)
            .map_err(|e| TxBuildError::InvalidAddress(e.to_string()))?;

        let tx = Transaction {
            version:   Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: caller_utxo,
                script_sig: ScriptBuf::new(), // P2TR inputs have empty scriptSig
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),      // filled in by the signer
            }],
            output: {
                let mut outs = vec![TxOut {
                    value:        Amount::from_sat(vault_sats),
                    script_pubkey: self.address.script_pubkey(),
                }];
                if change_sats > 546 { // dust threshold
                    outs.push(TxOut {
                        value:        Amount::from_sat(change_sats),
                        script_pubkey: change_addr.script_pubkey(),
                    });
                }
                outs
            },
        };

        Ok(tx)
    }

    /// Build the unsigned repay/close transaction (Leaf A spend).
    ///
    /// vault_utxo:   the outpoint of the vault funding output
    /// vault_sats:   the amount locked in the vault
    /// owner_address: where to return the BTC after vault closure
    /// repay_preimage: the 32-byte preimage that satisfies SHA256(preimage) == repay_hash
    pub fn build_close_tx(
        &self,
        vault_utxo:     OutPoint,
        vault_sats:     u64,
        owner_address:  &str,
        repay_preimage: &[u8; 32],
    ) -> Result<(Transaction, Vec<u8>), TxBuildError> {
        let fee_sats = DEFAULT_FEE_RATE_SAT_VB * TAPROOT_SPEND_VBYTES;
        if vault_sats < fee_sats + 546 {
            return Err(TxBuildError::InsufficientFunds {
                have_sats: vault_sats,
                need_sats: fee_sats + 546,
            });
        }

        let out_sats = vault_sats - fee_sats;
        let owner_addr = Address::from_str(owner_address)
            .map_err(|e| TxBuildError::InvalidAddress(e.to_string()))?
            .require_network(self.network)
            .map_err(|e| TxBuildError::InvalidAddress(e.to_string()))?;

        let tx = Transaction {
            version:   Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: vault_utxo,
                script_sig:  ScriptBuf::new(),
                sequence:    Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness:     Witness::new(), // signer fills in: <sig> <preimage> <repay_script> <control_block>
            }],
            output: vec![TxOut {
                value:         Amount::from_sat(out_sats),
                script_pubkey: owner_addr.script_pubkey(),
            }],
        };

        // Return the repay_preimage as witness element 1 (element 0 is the signature)
        Ok((tx, repay_preimage.to_vec()))
    }

    /// Build the unsigned liquidation transaction (Leaf B spend).
    ///
    /// vault_utxo:    the outpoint of the vault funding output
    /// vault_sats:    the amount locked in the vault
    /// bidder_address: winning keeper's Bitcoin address
    pub fn build_liquidation_tx(
        &self,
        vault_utxo:     OutPoint,
        vault_sats:     u64,
        bidder_address: &str,
    ) -> Result<Transaction, TxBuildError> {
        let fee_sats = DEFAULT_FEE_RATE_SAT_VB * TAPROOT_SPEND_VBYTES;
        let out_sats = vault_sats.saturating_sub(fee_sats);

        let bidder_addr = Address::from_str(bidder_address)
            .map_err(|e| TxBuildError::InvalidAddress(e.to_string()))?
            .require_network(self.network)
            .map_err(|e| TxBuildError::InvalidAddress(e.to_string()))?;

        Ok(Transaction {
            version:   Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: vault_utxo,
                script_sig:  ScriptBuf::new(),
                sequence:    Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness:     Witness::new(), // signer fills in: <keeper_sig> <liquidation_script> <control_block>
            }],
            output: vec![TxOut {
                value:         Amount::from_sat(out_sats),
                script_pubkey: bidder_addr.script_pubkey(),
            }],
        })
    }

    /// Build the unsigned emergency recovery transaction (Leaf C spend).
    ///
    /// vault_utxo:     the outpoint of the vault funding output
    /// vault_sats:     the amount locked
    /// owner_address:  the vault owner's receive address
    /// timelock_blocks: must match the CSV value in the script
    pub fn build_emergency_tx(
        &self,
        vault_utxo:      OutPoint,
        vault_sats:      u64,
        owner_address:   &str,
        timelock_blocks: u16,
    ) -> Result<Transaction, TxBuildError> {
        let fee_sats = DEFAULT_FEE_RATE_SAT_VB * TAPROOT_SPEND_VBYTES;
        let out_sats = vault_sats.saturating_sub(fee_sats);

        let owner_addr = Address::from_str(owner_address)
            .map_err(|e| TxBuildError::InvalidAddress(e.to_string()))?
            .require_network(self.network)
            .map_err(|e| TxBuildError::InvalidAddress(e.to_string()))?;

        Ok(Transaction {
            version:   Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: vault_utxo,
                script_sig:  ScriptBuf::new(),
                // CSV: nSequence must be >= timelock_blocks
                sequence:    Sequence(timelock_blocks as u32),
                witness:     Witness::new(), // signer fills in: <owner_sig> <emergency_script> <control_block>
            }],
            output: vec![TxOut {
                value:         Amount::from_sat(out_sats),
                script_pubkey: owner_addr.script_pubkey(),
            }],
        })
    }

    /// Compute the control block bytes for spending a given leaf.
    /// These go into the witness stack as the last element for script path spends.
    pub fn control_block_for_leaf(&self, script: &ScriptBuf) -> Option<Vec<u8>> {
        self.spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .map(|cb| cb.serialize())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

/// NUMS (Nothing-Up-My-Sleeve) internal key for the Taproot output.
/// Computed as SHA256("VUSD_VAULT_NUMS_INTERNAL_KEY") interpreted as an x-only pubkey.
/// This disables key-path spending — all spends must use one of the three script leaves.
///
/// Note: the resulting 32 bytes must land on the secp256k1 curve.
/// If it doesn't (probability ~50%), we increment a counter until it does.
/// This is the standard "provably unspendable" Taproot construction.
fn nums_internal_key() -> [u8; 32] {
    let mut counter: u8 = 0;
    loop {
        let mut h = Sha256::new();
        h.update(b"VUSD_VAULT_NUMS_INTERNAL_KEY");
        h.update([counter]);
        let candidate: [u8; 32] = h.finalize().into();
        // Try to parse as x-only pubkey — succeeds when the point is on the curve
        if XOnlyPublicKey::from_slice(&candidate).is_ok() {
            return candidate;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Convert a VUSD XOnlyPubkey to a bitcoin::secp256k1::XOnlyPublicKey.
pub fn to_bitcoin_xonly(pk: &VusdXOnly) -> Result<XOnlyPublicKey, TxBuildError> {
    XOnlyPublicKey::from_slice(&pk.0)
        .map_err(|e| TxBuildError::InvalidPubkey(e.to_string()))
}


// ─────────────────────────────────────────────────────────────────────────────
// TAPROOT SIGNER  (T5 + T6)
// ─────────────────────────────────────────────────────────────────────────────

use bitcoin::{
    sighash::{Prevouts, SighashCache, TapSighashType},
    TapLeafHash, TxOut as BtcTxOut,
};
#[allow(unused_imports)]
use bitcoin::secp256k1::Signing as _Signing;

/// Taproot transaction signer.
///
/// T5: Computes BIP-341 sighash for KeyPath and ScriptPath spends.
/// T6: Broadcasts signed transactions via bitcoind RPC (sendrawtransaction).
///
/// Key management: the signing keypair must be derived from the vault owner's
/// seed and provided by the CLI/wallet layer. This struct does not store keys.
pub struct TaprootSigner {
    secp: Secp256k1<All>,
}

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("Sighash computation failed: {0}")]
    SighashError(String),
    #[error("Signing failed: {0}")]
    SignError(String),
    #[error("Witness assembly failed: {0}")]
    WitnessError(String),
    #[error("Broadcast failed: {0}")]
    BroadcastError(String),
}

impl TaprootSigner {
    pub fn new() -> Self {
        TaprootSigner { secp: Secp256k1::new() }
    }

    /// Sign and complete a KeyPath (cooperative close) spend.
    ///
    /// For KeyPath, the sighash covers the full output set via Prevouts::All.
    /// The signature goes into input[0].witness as the only element.
    ///
    /// keypair: the owner's tweaked internal key (tweaked = internal_key + tap_tweak)
    /// prevout: the vault P2TR TxOut being spent (amount + scriptPubKey)
    pub fn sign_keypath(
        &self,
        tx:      &mut Transaction,
        prevout: BtcTxOut,
        keypair: &Keypair,
    ) -> Result<(), SignerError> {
        let prevouts = Prevouts::All(&[prevout]);
        let mut cache = SighashCache::new(&*tx);

        let sighash = cache
            .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
            .map_err(|e| SignerError::SighashError(e.to_string()))?;

        let msg = { let mut b = [0u8;32]; b.copy_from_slice(sighash.as_ref()); bitcoin::secp256k1::Message::from_digest(b) };

        // BIP-340 Schnorr sign with the tweaked keypair
        let sig = self.secp.sign_schnorr(&msg, keypair);
        let sig_bytes = sig.serialize();

        tx.input[0].witness.clear();
        tx.input[0].witness.push(sig_bytes);

        Ok(())
    }

    /// Sign and complete a ScriptPath (Leaf A/B/C) spend.
    ///
    /// For script path, sighash includes the leaf hash (tap_leaf_hash).
    /// Witness stack (BIP-341 order): <items...> <script> <control_block>
    ///
    /// keypair:       the signing key (owner for A/C, keeper for B)
    /// prevout:       the vault TxOut being spent
    /// leaf_script:   the tapscript for this leaf
    /// control_block: serialized control block from TaprootVault::control_block_for_leaf()
    /// extra_witness: additional witness items pushed BEFORE the signature
    ///                (e.g., for Leaf A: the repay preimage)
    pub fn sign_scriptpath(
        &self,
        tx:            &mut Transaction,
        prevout:       BtcTxOut,
        keypair:       &Keypair,
        leaf_script:   &ScriptBuf,
        control_block: Vec<u8>,
        extra_witness: Vec<Vec<u8>>,
    ) -> Result<(), SignerError> {
        let prevouts = Prevouts::All(&[prevout]);
        let mut cache = SighashCache::new(&*tx);

        let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::TapScript);

        let sighash = cache
            .taproot_script_spend_signature_hash(
                0,
                &prevouts,
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|e| SignerError::SighashError(e.to_string()))?;

        let msg = { let mut b = [0u8;32]; b.copy_from_slice(sighash.as_ref()); bitcoin::secp256k1::Message::from_digest(b) };
        let sig = self.secp.sign_schnorr(&msg, keypair);
        let sig_bytes = sig.serialize();

        // BIP-341 witness stack for script path:
        //   [sig] [extra_witness items...] [script] [control_block]
        tx.input[0].witness.clear();
        tx.input[0].witness.push(sig_bytes);
        for item in extra_witness {
            tx.input[0].witness.push(item);
        }
        tx.input[0].witness.push(leaf_script.to_bytes());
        tx.input[0].witness.push(control_block);

        Ok(())
    }

    /// T6: Serialize the transaction and broadcast via bitcoind sendrawtransaction.
    ///
    /// Returns the txid as a hex string on success.
    ///
    /// This is called by SignetBtcLayer::unlock_btc() after signing is complete.
    /// The rpc_url / credentials are obtained from ThunderNodeConfig or CLI config.
    pub fn broadcast(
        &self,
        tx:      &Transaction,
        rpc_url: &str,
        rpc_user: &str,
        rpc_pass: &str,
    ) -> Result<String, SignerError> {
        use bitcoin::consensus::encode::serialize_hex;

        let tx_hex = serialize_hex(tx);
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id":      1,
            "method":  "sendrawtransaction",
            "params":  [tx_hex],
        });

        let client = reqwest::blocking::Client::new();
        let resp = client
            .post(rpc_url)
            .basic_auth(rpc_user, Some(rpc_pass))
            .json(&body)
            .send()
            .map_err(|e| SignerError::BroadcastError(format!("HTTP error: {}", e)))?;

        #[derive(serde::Deserialize)]
        struct RpcResp { result: Option<String>, error: Option<serde_json::Value> }
        let rpc: RpcResp = resp.json()
            .map_err(|e| SignerError::BroadcastError(format!("Parse error: {}", e)))?;

        if let Some(err) = rpc.error {
            return Err(SignerError::BroadcastError(format!("RPC error: {}", err)));
        }

        rpc.result.ok_or_else(|| SignerError::BroadcastError("null txid".to_string()))
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    fn test_xonly(seed: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        kp.x_only_public_key().0
    }

    fn test_scripts() -> VaultScripts {
        let owner  = test_xonly(1);
        let keeper = test_xonly(2);
        let repay_hash = [0xAB; 32];
        VaultScripts::build(&owner, &keeper, &repay_hash, 26_280).unwrap()
    }

    #[test]
    fn test_vault_scripts_build() {
        let scripts = test_scripts();
        // Repay script should be non-empty and contain SHA256 opcode
        assert!(!scripts.repay.is_empty());
        assert!(!scripts.liquidation.is_empty());
        assert!(!scripts.emergency.is_empty());
    }

    #[test]
    fn test_taproot_vault_build_signet() {
        let scripts = test_scripts();
        let vault = TaprootVault::build(scripts, Network::Signet).unwrap();
        // Address should be a valid signet bech32m address
        let addr_str = vault.address.to_string();
        assert!(addr_str.starts_with("tb1p"), "signet P2TR must start with tb1p, got: {}", addr_str);
    }

    #[test]
    fn test_nums_key_is_valid_xonly() {
        let key_bytes = nums_internal_key();
        assert!(XOnlyPublicKey::from_slice(&key_bytes).is_ok());
    }

    #[test]
    fn test_control_block_available_for_each_leaf() {
        let scripts = test_scripts();
        let vault   = TaprootVault::build(scripts.clone(), Network::Signet).unwrap();
        assert!(vault.control_block_for_leaf(&scripts.repay).is_some());
        assert!(vault.control_block_for_leaf(&scripts.liquidation).is_some());
        assert!(vault.control_block_for_leaf(&scripts.emergency).is_some());
    }

    #[test]
    fn test_open_tx_builds() {
        let scripts = test_scripts();
        let vault   = TaprootVault::build(scripts, Network::Signet).unwrap();

        let fake_utxo = OutPoint::new(Txid::all_zeros(), 0);
        let tx = vault.build_open_tx(
            fake_utxo,
            1_000_000,    // 0.01 BTC input
            900_000,      // 0.009 BTC to vault
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", // signet P2WPKH
        ).unwrap();

        assert_eq!(tx.input.len(), 1);
        assert!(tx.output.len() >= 1);
        assert_eq!(tx.output[0].value.to_sat(), 900_000);
    }

    #[test]
    fn test_insufficient_funds_error() {
        let scripts = test_scripts();
        let vault   = TaprootVault::build(scripts, Network::Signet).unwrap();
        let fake_utxo = OutPoint::new(Txid::all_zeros(), 0);

        let result = vault.build_open_tx(
            fake_utxo,
            500,   // way too little
            1_000, // want more than we have
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        );
        assert!(matches!(result, Err(TxBuildError::InsufficientFunds { .. })));
    }
}
