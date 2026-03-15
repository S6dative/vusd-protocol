// crates/vscx-core/src/lib.rs
//
// VSCx Core — the vault engine at the heart of the VUSD protocol.
//
// Public API surface. External crates import from here.

pub mod types;
pub mod vault;
pub mod events;
pub mod mock;
pub mod engine;
pub mod oracle_feed;

// Re-export the most commonly used types at the crate root
pub use types::{
    Satoshis, VusdAmount, VaultId, AuctionId, OutPoint, BitcoinAddress,
    XOnlyPubkey, CollateralRatioBps, OraclePrice, TapLeaf, StealthAddress,
    FEE_INDEX_SCALE, ORACLE_MAX_AGE_SECS,
    MIN_COLLATERAL_RATIO_BPS, LIQUIDATION_THRESHOLD_BPS, AT_RISK_THRESHOLD_BPS,
    LIQUIDATION_PENALTY_BPS, KEEPER_BONUS_BPS, DEFAULT_STABILITY_FEE_APR_BPS,
    VAULT_OPEN_FEE_USD_CENTS, VAULT_CLOSE_FEE_USD_CENTS,
    AUCTION_DURATION_SECS, EMERGENCY_TIMELOCK_BLOCKS,
    KeeperKeyRegistry, KeeperKeyRotation,
};
pub use vault::{VaultRecord, VaultState, VaultHealth, VaultError, AuctionRecord, AuctionBid};
pub use events::{VscxEvent, EventBus};
pub use engine::{VaultEngine, EngineConfig, AuctionSettlement, PriceUpdateResult};
pub use mock::{MockOracle, MockBtcLayer, MockVusdLedger, RingCtLedger, BulletproofVerifier, BtcLayer, current_time_secs};
pub use oracle_feed::OracleFeed;
pub use types::PROTOCOL_KEEPER_PUBKEY;
