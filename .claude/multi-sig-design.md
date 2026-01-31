# Multi-Signature System Design

## Overview

Two-level cryptographic signing system:
1. **Author Level**: Individual authors sign their own articles
2. **Editorial Board Level**: k-of-n threshold signatures for approval/rejection

## Article Frontmatter Structure

```toml
+++
title = "Article Title"
date = 2026-01-30

[author]
name = "Dr. Alice Smith"
email = "alice@example.com"  # Optional
pubkey = "a1b2c3d4e5f6789..."  # Author's Ed25519 public key (hex)
signature = "9f8e7d6c5b4a321..."  # Author signs SHA-256(article body)

[editorial_approval]
required = 3  # k-of-n threshold: needs 3 board signatures
status = "approved"  # Values: "pending", "approved", "rejected"

# Array of editorial board signatures
[[editorial_signatures]]
board_member = "bob-editor"  # ID from config.toml board registry
signature = "8e7d6c5b4a3210..."  # Signs SHA-256(article_hash + author_signature)
timestamp = 2026-01-30T12:00:00Z
decision = "approve"  # Values: "approve", "reject"

[[editorial_signatures]]
board_member = "carol-reviewer"
signature = "7d6c5b4a321098..."
timestamp = 2026-01-30T13:00:00Z
decision = "approve"

[[editorial_signatures]]
board_member = "dan-chief"
signature = "6c5b4a32109876..."
timestamp = 2026-01-30T14:00:00Z
decision = "approve"

[extra]
# Backward compatibility: keep existing integrity hash
integrity = "ab8912e4a56ec7d03e5a41c2c65ae037f5c09e88b74fff90b71e030fe5ce3fad"
+++

Article content here...
```

## Editorial Board Configuration (config.toml)

```toml
[extra]
# Existing site-level fields
public_key = "ba02dcac96a4254e96c7c47601502cc3630aa0d1ec4d6c9ad55452eeebea4884"
site_signature = "..."
site_integrity = "..."
site_randomart = """..."""

# Editorial board threshold configuration
editorial_board_threshold = 3  # k-of-n: requires 3 signatures minimum

# Editorial board member registry
[[editorial_board.members]]
id = "bob-editor"
name = "Bob Editor"
role = "Senior Editor"
pubkey = "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"
active = true
joined = 2025-01-15

[[editorial_board.members]]
id = "carol-reviewer"
name = "Carol Reviewer"
role = "Fact Checker"
pubkey = "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4"
active = true
joined = 2025-03-20

[[editorial_board.members]]
id = "dan-chief"
name = "Dan Chief"
role = "Editor in Chief"
pubkey = "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"
active = true
joined = 2024-12-01

[[editorial_board.members]]
id = "eve-deputy"
name = "Eve Deputy"
role = "Deputy Editor"
pubkey = "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"
active = true
joined = 2025-06-10

[[editorial_board.members]]
id = "frank-emeritus"
name = "Frank Emeritus"
role = "Editor Emeritus"
pubkey = "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
active = false  # Inactive members cannot sign new articles
joined = 2023-01-01
retired = 2025-12-31
```

## Cryptographic Signing Chain

### Step 1: Author Signs Article

**Command**: `cargo run -p xtask -- author-sign article.md`

**Process**:
1. Author has private key in `.authors/<author-id>/private_key.secret`
2. Calculate article hash: `SHA-256(article body)`
3. Sign: `Ed25519.sign(author_private_key, article_hash)`
4. Update frontmatter with author.pubkey and author.signature
5. Set editorial_approval.status = "pending"

**What's signed**: SHA-256 hash of the article body (same as integrity hash)

### Step 2: Editorial Board Member Reviews

**Command**: `cargo run -p xtask -- editorial-review article.md --approve`

**Process**:
1. Board member has private key in `.editorial_board/<member-id>/private_key.secret`
2. Verify author signature is valid
3. Calculate review hash: `SHA-256(article_hash + author_signature)`
4. Sign: `Ed25519.sign(board_member_private_key, review_hash)`
5. Add editorial_signatures entry with signature, timestamp, decision
6. Check if threshold reached (k signatures)
7. If threshold reached, update editorial_approval.status = "approved"

**What's signed**: SHA-256(article_hash + author_signature) - creates a signature chain

### Step 3: CI Verification

**CI verifies before publication**:
1. Verify author signature is valid
2. Verify each editorial signature is valid
3. Check threshold is met (k-of-n)
4. Check all signers are active board members
5. If any verification fails, block deployment

## New xtask Commands

### Author Commands

```bash
# Generate author keypair
cargo run -p xtask -- author-keygen --name "Alice Smith" --id alice-smith

# Sign article as author
cargo run -p xtask -- author-sign content/news/2026/01/article.md

# Verify author signature
cargo run -p xtask -- verify-author content/news/2026/01/article.md
```

### Editorial Board Commands

```bash
# Generate board member keypair
cargo run -p xtask -- board-keygen --name "Bob Editor" --id bob-editor --role "Senior Editor"

# Add board member to config.toml
cargo run -p xtask -- board-add --id bob-editor --pubkey <hex>

# Review article (approve/reject)
cargo run -p xtask -- editorial-review content/news/2026/01/article.md --approve
cargo run -p xtask -- editorial-review content/news/2026/01/article.md --reject

# List board members
cargo run -p xtask -- board-list

# Deactivate board member
cargo run -p xtask -- board-deactivate --id frank-emeritus
```

### Verification Commands

```bash
# Verify all signatures on an article
cargo run -p xtask -- verify-article content/news/2026/01/article.md

# Verify all articles have required signatures
cargo run -p xtask -- verify-all-articles

# Check if article meets publication threshold
cargo run -p xtask -- check-threshold content/news/2026/01/article.md
```

## Key Management

### Directory Structure

```
.editorial_board/
├── README.md                      # Key management docs
├── private_key.secret             # Site-level signing key (existing)
└── board/
    ├── bob-editor/
    │   └── private_key.secret     # Bob's private key
    ├── carol-reviewer/
    │   └── private_key.secret     # Carol's private key
    └── dan-chief/
        └── private_key.secret     # Dan's private key

.authors/
├── README.md                      # Author key management
└── alice-smith/
    └── private_key.secret         # Alice's private key
```

### .gitignore Protection

```gitignore
# All private keys
.editorial_board/**/*.secret
.editorial_board/**/private_key.*
.authors/**/*.secret
.authors/**/private_key.*
```

## Verification Logic

### Article-Level Verification

```rust
fn verify_article(article_path: &Path) -> Result<()> {
    // 1. Parse frontmatter
    let frontmatter = parse_frontmatter(article_path)?;

    // 2. Verify author signature
    let article_hash = calculate_hash(&article.body);
    verify_ed25519(
        &frontmatter.author.pubkey,
        &article_hash,
        &frontmatter.author.signature
    )?;

    // 3. Verify editorial signatures
    let review_hash = sha256(&format!("{}{}", article_hash, frontmatter.author.signature));
    let valid_sigs = 0;

    for sig in frontmatter.editorial_signatures {
        // Check board member is active
        let member = get_board_member(&sig.board_member)?;
        if !member.active {
            continue; // Skip inactive members
        }

        // Verify signature
        if verify_ed25519(&member.pubkey, &review_hash, &sig.signature).is_ok() {
            valid_sigs += 1;
        }
    }

    // 4. Check threshold
    let threshold = frontmatter.editorial_approval.required;
    if valid_sigs < threshold {
        bail!("Article has {} signatures, needs {}", valid_sigs, threshold);
    }

    println!("✅ Article verified: {}/{} signatures", valid_sigs, threshold);
    Ok(())
}
```

## Future: LLM Fact-Checking Integration

### Proposed Architecture

```toml
[editorial_approval]
required = 3
status = "approved"
llm_fact_check = true  # Enable AI fact-checking

[[editorial_signatures]]
board_member = "claude-fact-checker"  # Special AI board member
signature = "..."
timestamp = 2026-01-30T11:00:00Z
decision = "approve"
confidence = 0.92  # AI confidence score
reasoning = "Verified claims against reputable sources. Found 3 citations, all valid."
```

**Implementation considerations**:
- AI acts as additional board member (doesn't reduce human threshold)
- AI signature has lower weight (e.g., counts as 0.5 signatures)
- AI provides confidence score + reasoning for transparency
- Human editors can override AI decisions
- Future feature: not implemented in Phase 1

## Migration Path

### Phase 1: Add Multi-Sig Infrastructure
- Implement author signing
- Implement editorial k-of-n signatures
- Update CI verification

### Phase 2: Migrate Existing Articles
- Existing articles keep single-signature model
- New articles use multi-sig model
- Verification supports both models

### Phase 3: Deprecate Single-Signature
- Convert all articles to multi-sig
- Remove old single-signature code
- Update documentation

## Security Properties

### Guarantees

1. **Author Authenticity**: Proves article was written (or approved) by author with private key
2. **Editorial Authorization**: Proves k board members approved publication
3. **Non-Repudiation**: Neither author nor board members can deny signing
4. **Tamper Evidence**: Any content modification invalidates all signatures
5. **Threshold Security**: Requires k compromised keys to forge approval

### Threat Model

**Protected Against**:
- Unauthorized article publication
- Content tampering after signing
- Single rogue board member approving malicious content
- Impersonation of authors or board members

**NOT Protected Against**:
- k malicious board members colluding
- Social engineering of authors/board members
- Private key compromise (requires key rotation)
- Time-of-check-time-of-use attacks (requires atomic deployment)

## Implementation Priority

1. ✅ Design frontmatter structure (this document)
2. 🔄 Add author key generation and signing commands
3. ⏳ Add editorial board signing commands
4. ⏳ Update verification logic
5. ⏳ Add board member management
6. ⏳ Update documentation articles
7. ⏳ Test complete workflow
