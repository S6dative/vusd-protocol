# Security Policy

## Scope

This policy covers the VUSD Protocol codebase: vault engine, oracle network,
privacy layer (ring signatures, bulletproofs, stealth addresses), Lightning
transport, and all supporting infrastructure.

**In scope:**
- Cryptographic vulnerabilities (ring signature forgery, commitment imbalance, ECDH key leakage)
- Vault state machine exploits (unauthorized liquidation, collateral theft, double-spend)
- Oracle manipulation (price spoofing, quorum bypass)
- Key material exposure (oracle seeds, keeper keys)
- Denial-of-service attacks on the keeper or oracle network

**Out of scope:**
- Bitcoin Core or LND vulnerabilities (report to those projects directly)
- Theoretical attacks with no practical exploit path
- Issues in test/mock infrastructure not reachable in production

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: `security@vusd-protocol.org` (PGP key available on request)

Include:
1. Description of the vulnerability and affected component
2. Steps to reproduce or proof-of-concept code
3. Potential impact assessment
4. Your suggested fix (optional but appreciated)

---

## Response Timeline

| Event | Target |
|-------|--------|
| Acknowledgement | 48 hours |
| Initial assessment | 5 business days |
| Fix or mitigation | Depends on severity (see below) |
| Public disclosure | After fix is deployed |

**Severity → fix timeline:**
- Critical (funds at risk): 7 days
- High (protocol integrity): 14 days
- Medium (privacy degradation): 30 days
- Low / informational: next release cycle

---

## Bug Bounty

VUSD Protocol will be launching a bug bounty program prior to mainnet.
Rewards will be proportional to severity. Details to be announced.

Critical findings affecting real user funds will be rewarded retroactively
at mainnet launch even before the formal program is live.

---

## Cryptographic Scope

The following are the highest-priority areas for security research:

- **Ring signature closure** — can a forged signature pass `verify()`?
- **ECDH symmetry** — can the sender-side `r·V` diverge from recipient-side `v·R`?
- **Commitment balance** — can `verify_commitment_sum()` pass with inflation?
- **Key image collision** — can two distinct outputs produce the same key image?
- **Oracle quorum bypass** — can a price be accepted with fewer than 5 valid signatures?
- **Staleness gate bypass** — can a stale price trigger a liquidation?

---

*VUSD Protocol — anonymous. trustless. private.*
