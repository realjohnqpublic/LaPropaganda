# Security Policy

## Security Architecture

La Propaganda implements a three-layer cryptographic security model for tamper-evident content publishing.

### Layer 1: Content Integrity (SHA-256)

**Individual Article Hashes:**
- Each article body is hashed using SHA-256
- Hash stored in frontmatter `integrity` field
- Detects any modification to article content

**Global Site Hash:**
- All articles combined and hashed deterministically
- Stored in `config.toml` as `site_integrity`
- Changes if any article is added, removed, or modified

**Algorithm:** SHA-256 (FIPS 180-4)
**Key size:** N/A (hash function, not keyed)
**Collision resistance:** 2^128 operations

### Layer 2: Editorial Authorization (Ed25519)

**Digital Signatures:**
- Editorial board signs the global site hash
- Signature stored in `config.toml` as `site_signature`
- Public key verification proves authenticity

**Algorithm:** Ed25519 (RFC 8032)
**Key size:** 256 bits (32 bytes)
**Signature size:** 512 bits (64 bytes)
**Security level:** ~128-bit security

**Key Management:**
- Private key: `.editorial_board/private_key.secret` (git-ignored)
- Public key: `config.toml` [extra.public_key] (publicly committed)
- Environment: `EDITORIAL_BOARD_PRIVATE_KEY` for CI/CD

### Layer 3: Visual Verification (Randomart)

**Drunken Bishop Algorithm:**
- Generates ASCII art from hash bytes
- Provides human-readable fingerprint
- Changes dramatically with any content modification

**Algorithm:** OpenSSH randomart (Drunken Bishop)
**Grid size:** 20×9 characters
**Symbols:** ` .o+=*BOX@%&^#@` (14 levels + S/E markers)

## Security Guarantees

### What This System Provides

| Property | Description | Threat Mitigated |
|----------|-------------|------------------|
| **Integrity** | Detects ANY content modification | Unauthorized edits, bit flips |
| **Authenticity** | Proves editorial board signed content | Impersonation, fake content |
| **Non-repudiation** | Signer cannot deny signing | Accountability |
| **Tamper-evidence** | Modifications are immediately detectable | Silent tampering |
| **Public verifiability** | Anyone can verify independently | Trust dependencies |

### What This System Does NOT Provide

| Limitation | Reason | Mitigation |
|------------|--------|------------|
| **Timestamp proof** | No cryptographic timestamping | Use OpenTimestamps (planned) |
| **Identity binding** | Key represents "editorial board", not individuals | Multi-sig (future consideration) |
| **Key revocation** | No built-in revocation mechanism | Manual key rotation |
| **Perfect forward secrecy** | Old signatures remain valid | Archive versioning |
| **Side-channel protection** | Website infrastructure separate | Defense in depth |

## Threat Model

### In-Scope Threats (Protected Against)

1. **Content Tampering**
   - Attack: Modify article text after publication
   - Protection: SHA-256 hash mismatch detected
   - Detection: `cargo run -p xtask -- verify`

2. **Unauthorized Publication**
   - Attack: Publish content without editorial approval
   - Protection: Ed25519 signature verification fails
   - Detection: `cargo run -p xtask -- verify-signature`

3. **Replay Attacks**
   - Attack: Restore old version of content
   - Protection: Global hash includes ALL articles (Merkle-like)
   - Detection: Signature verification + visual randomart change

4. **Git History Manipulation**
   - Attack: Rewrite git history to hide changes
   - Protection: Signatures stored in committed files
   - Detection: Historical verification via archive system

### Out-of-Scope Threats (Not Protected)

1. **Private Key Compromise**
   - If attacker obtains private key, they can sign malicious content
   - **Mitigation:** Secure key storage, hardware keys (YubiKey planned)

2. **Website Infrastructure Compromise**
   - Attacker controls web server or GitHub Pages
   - **Mitigation:** Readers verify via independent git clone

3. **Supply Chain Attacks**
   - Compromised dependencies (Rust crates, npm packages)
   - **Mitigation:** Dependency pinning, Cargo.lock audits

4. **Time-of-Check-Time-of-Use (TOCTOU)**
   - Content modified between verification and deployment
   - **Mitigation:** Atomic CI/CD workflow, signature verified before deploy

5. **Social Engineering**
   - Attacker convinces editorial board to sign malicious content
   - **Mitigation:** Human processes, multi-sig (future)

## Supported Versions

Security updates are provided for:

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**DO NOT** open public GitHub issues for security vulnerabilities.

### Private Disclosure

1. **Email:** security@your-domain.com (replace with your email)
2. **PGP Key:** (optional, provide if available)
3. **Response time:** 48 hours acknowledgment, 7 days initial assessment

### Required Information

- **Description:** What is the vulnerability?
- **Impact:** What can an attacker do?
- **Reproduction:** Step-by-step exploit instructions
- **Affected versions:** Which versions are vulnerable?
- **Suggested fix:** (optional) How to remediate?

### Disclosure Timeline

- **Day 0:** Receive vulnerability report
- **Day 1-2:** Acknowledge receipt
- **Day 3-7:** Initial assessment and triage
- **Day 7-30:** Develop and test fix
- **Day 30:** Public disclosure (coordinated with reporter)

### Security Advisories

Fixed vulnerabilities will be published as GitHub Security Advisories with CVE IDs when applicable.

## Security Best Practices

### For Publishers

1. **Protect Private Keys**
   - Store in secure location (hardware key recommended)
   - Never commit to git (verified by .gitignore)
   - Rotate keys if compromised

2. **Verify Before Merging**
   - Always run `verify-signature` before accepting PRs
   - Check CI verification passed
   - Review content changes carefully

3. **Use GitHub Secrets**
   - Store `EDITORIAL_BOARD_PRIVATE_KEY` as GitHub Secret
   - Never log private keys in CI output
   - Rotate secrets periodically

4. **Monitor Randomart**
   - Visual verification of site integrity
   - Changes indicate content modifications
   - Unexpected changes warrant investigation

### For Readers

1. **Verify Independently**
   - Clone repository yourself: `git clone https://github.com/...`
   - Run verification: `cargo run -p xtask -- verify-signature`
   - Don't trust web interface alone

2. **Check Public Key**
   - Verify public key matches known value
   - Compare across multiple sources
   - Watch for unexpected key changes

3. **Monitor Randomart**
   - Take screenshot of randomart pattern
   - Compare on subsequent visits
   - Dramatic changes indicate content updates

## Cryptographic Dependencies

All cryptography uses well-audited Rust crates:

| Library | Version | Purpose | Audit Status |
|---------|---------|---------|--------------|
| `ed25519-dalek` | 2.1+ | Ed25519 signatures | ✅ Audited (NCC Group) |
| `sha2` | 0.10+ | SHA-256 hashing | ✅ Audited (Cure53) |
| `rand` | 0.8+ | CSPRNG for key gen | ✅ Audited |
| `hex` | 0.4+ | Hex encoding | ✅ Widely used |

## Security Audits

| Date | Auditor | Scope | Report |
|------|---------|-------|--------|
| TBD  | TBD     | Full system | Not yet audited |

Contributions welcome for professional security audits!

## Acknowledgments

Security researchers who responsibly disclose vulnerabilities will be acknowledged (with permission) in:
- SECURITY.md (this file)
- GitHub Security Advisories
- Release notes

## Contact

- **Security issues:** security@your-domain.com (replace with your contact)
- **General issues:** [GitHub Issues](https://github.com/fangluo/LaPropaganda/issues)
- **Questions:** [GitHub Discussions](https://github.com/fangluo/LaPropaganda/discussions)

---

**Security is a community effort. Thank you for helping keep La Propaganda secure.**
