+++
title = "How to Verify Content Authenticity"
date = 2026-01-30
[extra]
author = "Transparency Team"

[extra.author_signature]
author_id = "transparency-team"
name = "Transparency Team"
pubkey = "f9170c302aba12d374676d8a144ba58392fe3c85478d0de44420a36743ed73b6"
signature = "transparency_team_placeholder_hex_string_that_is_long_enough"
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
integrity = "32277551c7e978607812dc910a48ad9233e19dcc38a39d2ef233eca6f016ddb2"+++

Every article on this site is cryptographically signed by the editorial board. **You can verify authenticity yourself** - no trust required.

## Quick Visual Check (10 seconds)

Look at the **randomart** displayed in the site header (top-left on desktop):

```
+-----[ Magic ]------+
|+oo.. oB=.    ..o . |
|o.o  ..o+ .  .  .E. |
... (pattern continues)
+-----[ SHA256 ]-----+
```

This ASCII art is a visual fingerprint of **all site content**. Think of it like a QR code for integrity.

**How to use it:**
1. Take a screenshot of the randomart today
2. Come back tomorrow
3. Compare patterns
   - **Same pattern** = No content changes
   - **Different pattern** = Content was updated (or tampered)

This works because the randomart is generated from a SHA-256 hash of all articles. Changing even one character anywhere creates a completely different pattern.

## Full Cryptographic Verification (5 minutes)

For complete security, verify the digital signature:

### Prerequisites
- git (install: https://git-scm.com)
- Rust toolchain (install: https://rustup.rs)

### Verification Steps

```bash
# 1. Clone this repository
git clone https://github.com/fangluo/LaPropaganda
cd LaPropaganda

# 2. Run verification
cargo run -p xtask -- verify-signature
```

### Expected Output (Valid Content)

```
🔐 Verifying cryptographic signature...
Hashing 3 articles for global integrity...
✅ Signature VALID - Content signed by editorial board

🔑 Public key:
   ba02dcac96a4254e96c7c47601502cc3...

📋 Site hash:
   dfc3932a7cd395c699d254dc26c03267...

✅ Content authenticity verified!
```

### If Content Was Tampered

```
❌ Signature verification failed
⚠️  Content has been modified and is NOT signed by editorial board
```

## What This Proves

✅ **Authenticity** - Content was signed by someone with the editorial board's private key
✅ **Integrity** - Content has NOT been modified since signing
✅ **Visual Match** - The randomart matches the current content

❌ **Timestamp** - Does NOT prove when content was signed
❌ **Identity** - Does NOT prove which specific person signed (only "editorial board")

## How It Works (Technical Details)

### Step 1: Recalculate Content Hash
The verification tool:
1. Reads each article's body content
2. Calculates SHA-256 hash of each article
3. Combines all hashes into a global site hash

### Step 2: Extract Signature
From `config.toml`:
```toml
[extra]
public_key = "ba02dcac96a4254e96c7c47601502cc3..."  # Ed25519 public key
site_signature = "a75918e6d032ff9bb12b30d68388f0c1..."  # Ed25519 signature
```

### Step 3: Verify Signature
Uses Ed25519 public-key cryptography:
```
Ed25519.verify(public_key, site_hash, signature)
```

If this returns `true`, content is authentic. If `false`, content was tampered or signed with a different key.

## Security Guarantees

This system provides:

| Property | Description |
|----------|-------------|
| **Integrity** | Detects ANY modification (even 1 character) |
| **Authenticity** | Proves editorial board authorized the content |
| **Non-repudiation** | Editorial board cannot deny signing |
| **Transparency** | Anyone can verify independently (no special access needed) |
| **Tamper-evident** | Changes are immediately detectable |

## Limitations

What this system does NOT protect against:

- **Timestamp manipulation** - No proof of when content was signed
- **Authorized changes** - Editorial board can modify content and re-sign
- **Key compromise** - If private key is stolen, attacker can sign content
- **Side-channel attacks** - Website infrastructure could be compromised separately

For these threats, see our [Archive Strategy](../archive-strategy/) for additional protections.

## For Developers

### Verify Programmatically

Use the xtask commands in scripts:

```bash
# Verify signature (exit code 0 = valid, non-zero = invalid)
cargo run -p xtask -- verify-signature

# Verify content hashes
cargo run -p xtask -- verify

# Both checks
if cargo run -p xtask -- verify-signature 2>/dev/null; then
    echo "Content is authentic ✓"
else
    echo "Content verification FAILED ✗"
    exit 1
fi
```

### Integration with CI/CD

Our GitHub Actions workflow automatically verifies signatures before deployment:

```yaml
- name: Verify Signature
  run: cargo run -p xtask -- verify-signature
```

If verification fails, deployment is blocked.

## Questions?

- **How is this different from HTTPS?** HTTPS protects data in transit. This protects data at rest (stored content).
- **Can the website owner fake this?** No - they would need the private key, which is stored securely (not on web server).
- **What if I don't trust GitHub?** Clone the repo to your own server and verify there.
- **Is this overkill?** For casual blogs, yes. For journalism, whistleblowing, or research data, no.

---

**Next:** Learn about our [long-term archive strategy](../archive-strategy/) for preserving verified content.
