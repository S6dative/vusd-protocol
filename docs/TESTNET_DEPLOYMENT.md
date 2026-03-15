# VUSD Testnet Deployment Guide

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Ubuntu | 22.04+ | Other Linux distros work with minor changes |
| Rust | 1.75+ | `rustup update stable` |
| Bitcoin Core | 26.0+ | For signet |
| LND | 0.18+ | With Tor enabled |
| Tor | Any | `sudo apt install tor` |

---

## Quick Setup (automated)

```bash
git clone https://github.com/S6dative/vusd-protocol
cd vusd-protocol
chmod +x deploy/signet_setup.sh
./deploy/signet_setup.sh
```

This script installs Bitcoin Core, LND, Tor, and builds the VUSD CLI.

---

## Manual Setup

### Step 1: Install Tor

```bash
sudo apt install tor
sudo systemctl start tor
# Verify Tor is running
curl --socks5-hostname localhost:9050 https://check.torproject.org/api/ip
```

### Step 2: Start bitcoind on signet

```bash
# Install config
mkdir -p ~/.bitcoin
cp deploy/bitcoin.conf ~/.bitcoin/

# Start
bitcoind -signet -daemon

# Wait for sync (~5 minutes on signet)
watch bitcoin-cli -signet getblockchaininfo
```

### Step 3: Configure and start LND

```bash
mkdir -p ~/.lnd
cp deploy/lnd.conf ~/.lnd/

# Add bitcoind credentials to lnd.conf:
# bitcoind.rpcuser=vusd
# bitcoind.rpcpass=vusd_rpc_password
# bitcoind.zmqpubrawblock=tcp://127.0.0.1:28332
# bitcoind.zmqpubrawtx=tcp://127.0.0.1:28333

lnd --configfile=~/.lnd/lnd.conf
```

In a new terminal:

```bash
# Create wallet (save the seed!)
lncli --network=signet create

# Get your .onion address
cat /var/lib/tor/hidden_service/hostname

# Add to lnd.conf:
# externalip=<your-onion>.onion
```

### Step 4: Get signet BTC

```bash
# Generate a receive address
lncli --network=signet newaddress p2tr

# Fund from faucet
# https://signetfaucet.com
# https://signet.bc-2.jp
```

### Step 5: Build VUSD

```bash
cd vusd-protocol
cargo build --release
```

### Step 6: Run the testnet checklist

```bash
./target/release/vusd-testnet checklist
```

All 24 items must show ✅ before opening vaults.

### Step 7: Open your first vault

```bash
# Open a vault with 0.1 BTC collateral
./target/release/vusd open-vault --collateral 0.1

# Check vault status
./target/release/vusd vault-status

# Mint VUSD (up to 66% of collateral value)
./target/release/vusd mint --amount 5000

# Check balance
./target/release/vusd balance
```

---

## Keeper Node Setup

Keepers monitor vaults and trigger liquidations. Run at least one keeper:

```bash
./target/release/vusd-testnet keeper --key <your-keeper-pubkey-hex>
```

---

## Thunder Node Setup

See [thunder-node README](https://github.com/S6dative/thunder-node) for full setup.

Quick start:

```bash
thunder setup --gen-wallet
# Edit ~/.config/thunder-node/config.toml
thunder status
thunder start
```

---

## Architecture on Signet

```
bitcoind (signet)
    │  zmq blocks/txs
    ▼
lnd (Tor-only)
    │  REST :8080
    ▼
VaultEngine ── SignetBtcLayer ── P2TR vaults on-chain
    │
    ├── OracleAggregator (MuSig2, 5-of-7)
    ├── KeeperCoordinator
    ├── RingCtLedger
    └── LightningTransport ── AnonTransport
                                    │
                                    └── Thunder Node (optional)
```

---

## Troubleshooting

**bitcoind won't start**: check `~/.bitcoin/debug.log`

**LND can't connect to bitcoind**: verify zmq ports in lnd.conf match bitcoin.conf

**Tor not working**: `sudo systemctl status tor` — check logs

**Faucet request failing**: signet faucets have rate limits — try a different one

**Vault open fails**: make sure bitcoind is fully synced and LND has confirmed channels
