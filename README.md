# VUSD Protocol

**A non-custodial Bitcoin-collateral stablecoin with Monero-style privacy.**

VUSD is a dollar-pegged stablecoin backed by BTC locked in Taproot vaults. Transfers are private by default — ring signatures, stealth addresses, and Pedersen commitments make VUSD outputs cryptographically unlinkable, on-chain and over Lightning.

---

## Architecture

```
Bitcoin L1 (signet/mainnet)
  └── Taproot Vault (P2TR, 3-leaf MAST)
        ├── Leaf A: repay + burn proof → cooperative close
        ├── Leaf B: keeper liquidation
        └── Leaf C: emergency timelock (~6 months)

VUSD Engine (vscx-core)
  ├── Vault lifecycle: open → mint → repay → close
  ├── Collateral ratio enforcement (150% min, 110% liquidation)
  ├── Stability fee accumulation (MakerDAO-style lazy index)
  └── Oracle price feed (5-of-7 Schnorr quorum)

Privacy Layer
  ├── Ring signatures (Ristretto255, ring size 11)
  ├── Stealth addresses (Monero dual-key scheme)
  ├── Pedersen commitments (hidden amounts)
  └── Bulletproof range proofs

Lightning Transport
  ├── VUSD transfers over keysend (TLV type 5482373486)
  ├── AnonTransport: Tor + private channels + relay mesh + jitter
  └── Thunder Node: privacy relay with stealth operator fees
```

## Crates

| Crate | Description |
|-------|-------------|
| `vscx-core` | Vault engine, types, oracle interface |
| `oracle` | Price feeds, 5-of-7 Schnorr aggregator |
| `taproot-vault` | BIP-341 MAST construction, SignetBtcLayer |
| `privacy` | Ring sigs, stealth addresses, bulletproofs |
| `lightning` | LND transport, AnonTransport stack |
| `keeper` | Liquidation bots, auction coordinator |
| `thunder-node` | Privacy relay daemon — [github.com/S6dative/thunder-node](https://github.com/S6dative/thunder-node) |
| `cli` | vusd command-line interface |
| `testnet` | Integration harness, scenarios, checklist |

## Protocol Parameters

| Parameter | Value |
|-----------|-------|
| Min collateral ratio | 150% |
| Liquidation threshold | 110% |
| Emergency timelock | 26,280 blocks (~6 months) |
| Oracle quorum | 5-of-7 Schnorr |
| Ring size | 11 |
| Thunder relay fee | 0.02% |
| Operator cut | 0.01% |

## Status

**Testnet-ready (signet).** All T1–T9 testnet blockers resolved:

- Oracle aggregation with real Schnorr verification (T1/T2)
- `SignetBtcLayer` — real P2TR funding + KeyPath spending via bitcoind RPC (T3–T6)
- Lightning mock path blocked outside test builds (T7)
- Runtime Tor + private channel verification via LND (T8/T9)
- Repay preimage bridge — `repay_hash` committed in Leaf A tapscript (A6)

**Mainnet work remaining:** MuSig2 oracle aggregate (A1), RingCT ledger (A3), keeper key rotation (A4).

## Quick Start

```bash
git clone https://github.com/S6dative/vusd-protocol
cd vusd-protocol
cargo build --release

# Run the testnet checklist
cargo run --bin vusd-testnet

# Open a vault (signet)
cargo run --bin vusd -- open-vault --collateral 1.0
```

Requires: bitcoind + lnd running on signet with Tor.

## Thunder Node

The privacy relay for VUSD Lightning transfers is maintained as a standalone repo:
**https://github.com/S6dative/thunder-node**

## License

MIT. This software is experimental. Signet only until audited.
