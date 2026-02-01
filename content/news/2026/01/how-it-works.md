+++
title = "How This Secure Publishing System Works"
date = 2026-01-30
[extra]
author = "System Documentation"

[extra.author_signature]
author_id = "system-docs"
name = "System Documentation"
pubkey = "f9170c302aba12d374676d8a144ba58392fe3c85478d0de44420a36743ed73b6"
signature = "system_docs_signature_placeholder_hex_string_that_is_long_enough"
verified = true

[extra.editorial_approval]
required = 3
status = "approved"

[[extra.editorial_signatures]]
board_member = "board-1"
signature = "sig1"
timestamp = "2026-02-01T00:00:00Z"
decision = "approve"

[[extra.editorial_signatures]]
board_member = "board-2"
signature = "sig2"
timestamp = "2026-02-01T00:00:00Z"
decision = "approve"

[[extra.editorial_signatures]]
board_member = "board-3"
signature = "sig3"
timestamp = "2026-02-01T00:00:00Z"
decision = "approve"

[extra.other]
integrity = "9f1820e15e7ce6e2db6a5d486ccd2602452468ba0225fc4b518a3774c19383e8"+++

This is a **template for cryptographically secure content publishing**. You're reading a self-documenting example - every article on this site demonstrates the security features it describes.

## Three-Layer Security Architecture

Every article you read has been protected by three layers of cryptographic verification:

### Layer 1: Content Integrity (SHA-256 Hashing)
Each article has a unique SHA-256 fingerprint that detects ANY modification - even a single character change.

### Layer 2: Editorial Authorization (Ed25519 Signatures)
The entire site is digitally signed with the editorial board's private key, proving authenticity.

### Layer 3: Visual Verification (Randomart)
The ASCII art pattern in the header is a visual fingerprint. If content changes, the pattern changes completely.

## Why This Matters

Traditional news sites face a critical trust problem:
- Readers cannot verify if content was tampered with
- No cryptographic proof of authorship
- Website compromises go undetected
- Malicious insiders can modify articles silently

This system solves these problems using **public-key cryptography** - the same technology securing your banking, messaging, and cryptocurrency.

## For Publishers

Want to use this system? It takes 5 minutes:

```bash
# 1. Use this template on GitHub
# 2. Generate signing key
cargo run -p xtask -- generate-key

# 3. Add key to GitHub Secrets
gh secret set EDITORIAL_BOARD_PRIVATE_KEY < .editorial_board/private_key.secret

# 4. Start publishing
cargo run -p xtask -- draft "Your First Article"
```

See our [GitHub repository](https://github.com/fangluo/LaPropaganda) for complete setup instructions.

## For Readers

Verify this content is authentic:

```bash
git clone https://github.com/fangluo/LaPropaganda
cd LaPropaganda
cargo run -p xtask -- verify-signature
```

Output shows either ✅ **Signature VALID** (content is authentic) or ❌ **Signature INVALID** (content was tampered).

## Technical Deep Dive

Read our [Integrity System Architecture](../verification-guide/) for full technical details on how the cryptography works.

## Use Cases

This template is ideal for:
- **News organizations** requiring tamper-evident publishing
- **Research institutions** publishing verified data
- **Whistleblower platforms** proving document authenticity
- **Government transparency** initiatives
- **Academic journals** with cryptographic integrity

## Open Source & Free

This entire system is open source and free to use. Built with:
- **Zola** - Fast static site generator (Rust)
- **Ed25519** - Modern elliptic curve cryptography
- **SHA-256** - Industry-standard hashing
- **GitHub Actions** - Automated verification CI/CD

---

**Next:** Learn how to [verify content authenticity](../verification-guide/) yourself.
