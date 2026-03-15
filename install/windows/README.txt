⚡ THUNDER NODE — Quick Start
"You can't see thunder."
══════════════════════════════════════════════════════

Thunder Node is installed to:
  %ProgramFiles%\ThunderNode\thunder.exe

It has been added to your PATH. Open a new terminal and run:

  thunder setup         → generate Tor + LND configuration files
  thunder threats       → review all 25 threat mitigations
  thunder fees 1000     → preview fee breakdown for 1000 VUSD
  thunder start         → start the relay node (requires Tor + LND)

PREREQUISITES
─────────────────────────────────────────────────────────
Before running Thunder Node you need:

  1. Tor for Windows
     https://www.torproject.org/download/
     Install and ensure Tor is running (check system tray icon)

  2. LND (Lightning Network Daemon)
     https://github.com/lightningnetwork/lnd/releases
     Download lnd-windows-amd64-*.zip and extract to a folder in PATH

  3. Bitcoin Core (optional — needed to validate BTC collateral)
     https://bitcoincore.org/en/download/

CONFIGURATION
─────────────────────────────────────────────────────────
Run "thunder setup" to generate:
  • torrc         → copy to C:\Users\<you>\AppData\Roaming\tor\torrc
  • lnd.conf      → copy to C:\Users\<you>\AppData\Local\Lnd\lnd.conf

After copying configuration files:
  1. Restart Tor
  2. Start LND: lnd --configfile=path\to\lnd.conf
  3. Run: thunder start

OPERATOR SECURITY CHECKLIST
─────────────────────────────────────────────────────────
  □ Tor must be running before starting Thunder Node
  □ LND must be configured with tor.active=true
  □ Open channels only with other private relay nodes
  □ Store your operator seed phrase OFFLINE — never on this machine
  □ Pay for any services with Monero, not credit cards
  □ Use a dedicated machine or VM for running Thunder Node

SUPPORT
─────────────────────────────────────────────────────────
Documentation: https://github.com/S6dative/vusd-protocol
Issues:        https://github.com/S6dative/vusd-protocol/issues
