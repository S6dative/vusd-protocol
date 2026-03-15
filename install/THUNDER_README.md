# ⚡ Thunder Node

> *"You can't see thunder."*

A privacy-maximized Lightning relay node for the [VULTD](https://v0-vultd-stablecoin-platform.vercel.app/) protocol. Thunder Node wraps your VUSD stablecoin transfers in five layers of cryptographic privacy and routes the operator's fee income to a stealth address — so neither the sender, recipient, amount, nor operator can be identified from the network.

---

## Install

### Windows

**Option 1 — Installer (recommended)**
Download `thunder-*-windows-x86_64.msi` from the [latest release](https://github.com/S6dative/vusd-protocol/releases/latest), double-click, follow the wizard.
- Installs to `%ProgramFiles%\ThunderNode\`
- Adds `thunder` to your PATH automatically
- Creates a Start Menu entry

**Option 2 — Portable binary**
Download `thunder-*-windows-x86_64.exe`, rename it `thunder.exe`, place it anywhere in your PATH.

---

### macOS

**Option 1 — Package installer (recommended)**
Download `thunder-*-macos-universal.pkg` from the [latest release](https://github.com/S6dative/vusd-protocol/releases/latest) and double-click.
- Universal binary: runs natively on **Intel and Apple Silicon** (M1/M2/M3/M4)
- Installs `thunder` to `/usr/local/bin/`
- Requires macOS 11.0 (Big Sur) or later

> If macOS says the package is from an "unidentified developer":
> Go to **System Settings → Privacy & Security → Open Anyway**

**Option 2 — One-line install**
```bash
curl -fsSL https://raw.githubusercontent.com/S6dative/vusd-protocol/main/install/install.sh | bash
```

**Option 3 — Homebrew** *(coming soon)*
```bash
brew install vultd/tap/thunder-node
```

---

### Linux

**One-line install (recommended)**
```bash
curl -fsSL https://raw.githubusercontent.com/S6dative/vusd-protocol/main/install/install.sh | bash
```
Detects your architecture (x86\_64 or ARM64) automatically. Verifies the SHA256 checksum. Installs to `/usr/local/bin/thunder`.

**Manual install — x86\_64**
```bash
VERSION=$(curl -fsSL https://api.github.com/repos/S6dative/vusd-protocol/releases/latest | grep tag_name | cut -d'"' -f4)
curl -fsSL "https://github.com/S6dative/vusd-protocol/releases/download/${VERSION}/thunder-${VERSION}-linux-x86_64" -o thunder
sha256sum -c <(curl -fsSL "https://github.com/S6dative/vusd-protocol/releases/download/${VERSION}/thunder-${VERSION}-linux-x86_64.sha256")
chmod +x thunder && sudo mv thunder /usr/local/bin/
```

**Manual install — ARM64 (Raspberry Pi 4/5, AWS Graviton)**
```bash
# Same as above but replace linux-x86_64 with linux-aarch64
```

**Static binary** — the Linux builds link against musl libc, meaning zero system dependencies. The binary runs on any Linux distribution from Ubuntu 18.04 to Alpine.

---

### Verify your download

Every release asset ships with a `.sha256` checksum file.

```bash
# Linux / macOS
sha256sum -c thunder-*-linux-x86_64.sha256

# macOS (alternative)
shasum -a 256 -c thunder-*-macos-universal.pkg.sha256

# Windows (PowerShell)
(Get-FileHash .\thunder-*-windows-x86_64.msi -Algorithm SHA256).Hash
# Compare to the .sha256 file contents
```

---

## Quick Start

After installing, open a terminal:

```bash
# 1. Generate Tor + LND configuration files for your machine
thunder setup

# 2. Review all 25 threat mitigations (recommended reading)
thunder threats

# 3. Preview the fee breakdown for a 1000 VUSD transfer
thunder fees 1000

# 4. After configuring Tor and LND (see Prerequisites below):
thunder start
```

---

## What Thunder Node does

Thunder Node is a privacy relay for VUSD (a Bitcoin-backed stablecoin). When someone sends VUSD through a Thunder Node:

1. **Ring signatures** hide which of 11 possible senders actually signed the transaction
2. **Stealth addresses** give the recipient a one-time address — never reusable, never linkable
3. **Bulletproof commitments** hide the transfer amount with a zero-knowledge range proof
4. **Tor hidden service** hides the relay operator's IP address
5. **Private Lightning channels** hide the relay operator's node from the public graph
6. **Multi-hop relay path** means no single relay knows both sender and recipient
7. **Traffic padding + jitter** makes all transfers look identical on the wire

### Fee structure

| Component | Amount | Who receives it |
|---|---|---|
| Thunder fee | 2× standard LN fee (~0.02%) | Network routing costs |
| Operator cut | 1% of transfer amount | Your stealth wallet |
| Net to recipient | ~98.98% of transfer | Recipient |

**Example:** 1,000 VUSD sent through Thunder Node
- Thunder fee: 0.20 VUSD
- Operator earnings: 10.00 VUSD → your stealth wallet
- Recipient receives: 989.80 VUSD

The operator fee routes to a **VUSD stealth address** — a cryptographic one-time address that cannot be linked to your identity without your private view key. You collect earnings by scanning with your view key on an offline device.

---

## Prerequisites

Thunder Node requires two external services:

### 1. Tor

```bash
# macOS
brew install tor && brew services start tor

# Ubuntu / Debian
sudo apt install tor && sudo systemctl enable --now tor

# Windows
# Download Tor Expert Bundle from https://www.torproject.org/download/tor/
# Extract and run tor.exe — or use the Tor Browser which bundles Tor
```

### 2. LND (Lightning Network Daemon)

Download the latest LND release for your platform from:
https://github.com/lightningnetwork/lnd/releases

```bash
# After downloading and extracting:
lnd --configfile=$(thunder setup --print-lnd-path)
```

Run `thunder setup` to generate a complete, ready-to-use `lnd.conf` with Tor enabled.

---

## Security model

Thunder Node implements 25 catalogued threat mitigations across six adversary classes:

```
thunder threats
```

```
🔴 CRITICAL  — T01 Tor hidden service (ISP cannot see your IP)
               T04 Private channels (node absent from public graph)
               T19 Ristretto255 ring signatures (128-bit security)
               T20 OsRng ephemeral stealth addresses (no key reuse)
               T21 Pedersen commitments + bulletproofs (hidden amounts)

🟠 HIGH      — T06 Multi-hop relay path (min 2 hops)
               T09 100–2000ms timing jitter (defeats correlation)
               T11 Zero logs stored (cannot produce what never existed)
               T13 Operator fees → stealth address (operator anonymous)
               T17 Watch-only key in relay RAM (spend key never in memory)
               ... and 4 more

🟡 MEDIUM    — Traffic padding, decoy pool depth, jurisdiction, ...
🟢 LOW       — Supply chain, open-source attribution, ...
```

**7 threats are code-verified** — the node refuses to start if they are not satisfied:
- Tor must be reachable on the SOCKS5 port
- Private-only channels must be configured
- Minimum 2 relay nodes must be available
- Operator spend private key must not be in relay process memory

**The remaining threats are operational** — things you configure once when setting up the machine (disk encryption, hosting provider, funding source). `thunder setup` prints the full checklist.

---

## Building from source

```bash
# Install Rust (nightly required for curve25519-dalek v3)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install nightly
rustup default nightly

# Clone
git clone https://github.com/S6dative/vusd-protocol
cd vusd-protocol

# Build
cargo build --release -p thunder-node

# Binary is at:
./target/release/thunder
```

---

## Architecture

```
Thunder Node
├── crates/thunder-node/     ← this binary
│   ├── Fee engine           (2× LN fee + 1% operator cut)
│   ├── Threat matrix        (25 catalogued mitigations)
│   └── Operator wallet      (watch-only stealth address in relay)
│
├── crates/lightning/
│   ├── AnonTransport        (5-layer anonymization stack)
│   │   ├── Layer 1: Tor hidden service
│   │   ├── Layer 2: Private channels only
│   │   ├── Layer 3: Ephemeral key rotation (30-day default)
│   │   ├── Layer 4: Multi-hop relay path
│   │   └── Layer 5: Traffic padding + timing jitter
│   └── LndTransport         (LND gRPC client)
│
└── crates/privacy/
    ├── Ring signatures      (Borromean Schnorr on Ristretto255)
    ├── Stealth addresses    (OTA = H_s(r·V)·G + S)
    ├── Pedersen commitments (hide amounts)
    └── Bulletproofs         (range proofs, no trusted setup)
```

---

## Releases

Releases are built automatically by GitHub Actions on every version tag. Each release includes:

| Asset | Description |
|---|---|
| `thunder-*-windows-x86_64.msi` | Windows installer |
| `thunder-*-windows-x86_64.exe` | Windows portable binary |
| `thunder-*-macos-universal.pkg` | macOS installer (Intel + Apple Silicon) |
| `thunder-*-linux-x86_64` | Linux static binary |
| `thunder-*-linux-aarch64` | Linux ARM64 static binary |
| `*.sha256` | SHA256 checksum for each asset |

---

## License

MIT — see [LICENSE](LICENSE)

This software is provided as-is. Running a Lightning relay node may have legal implications in your jurisdiction. You are responsible for understanding and complying with applicable laws.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions are welcome.
Run `cargo fmt --all` before opening a PR — CI will reject unformatted code.
