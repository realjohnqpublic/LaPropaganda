+++
title = "Multi-Signature Editorial Workflow"
date = 2026-01-31
[extra]
author = "Security Team"

[extra.author_signature]
author_id = "security-team"
name = "Security Team"
pubkey = "f9170c302aba12d374676d8a144ba58392fe3c85478d0de44420a36743ed73b6"
signature = "security_team_placeholder_hex_string_that_is_long_enough"
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
integrity = "63f3d69b14260beda78b87d0ad6c7ce861dd7de69c0df83a090b58db4db770ef"
+++

La Propaganda now implements a **two-level cryptographic signing system** that separates author accountability from editorial approval. This prevents unauthorized publication while preserving individual authorship attribution.

## Why Multi-Signature?

The original single-signature system had a critical limitation: **anyone with the editorial board private key could publish content**. This created several problems:

### Single-Signature Problems
- No individual author accountability
- Editorial board key must be shared among members
- Compromised key = total system failure
- No separation of duties (author vs. editor)
- Cannot track who approved what

### Multi-Signature Solution
```
Author signs article
    ↓
Editorial board members review
    ↓
k-of-n threshold signatures (e.g., 3 of 5)
    ↓
Publish when threshold reached
```

## Two-Level Security Architecture

### Level 1: Author Signatures

**Purpose:** Prove article authorship

**Process:**
1. Author writes article
2. Author signs with their Ed25519 private key
3. Signature proves: "I, [Author Name], wrote this content"
4. Article hash: `SHA-256(article body)`
5. Author signature: `Ed25519.sign(author_private_key, article_hash)`

**Guarantees:**
- Tamper detection: Any edit invalidates author signature
- Attribution: Proves specific person authored content
- Non-repudiation: Author cannot deny writing article

### Level 2: Editorial k-of-n Signatures

**Purpose:** Prove editorial board approval

**Process:**
1. Board member reviews author-signed article
2. Board member verifies author signature is valid
3. Board member signs review hash: `SHA-256(article_hash + author_signature)`
4. Repeat until k signatures collected
5. When threshold reached, article approved for publication

**Guarantees:**
- Requires k compromised keys to forge approval (not just 1)
- Individual board member accountability (who approved what)
- Flexible threshold (can require unanimous, majority, or quorum)
- Prevents rogue board member from publishing alone

## Workflow Example

### For Authors

**Step 1: Generate Your Signing Key (Once)**

```bash
cargo run -p xtask -- author-keygen \
  --name "Alice Smith" \
  --id alice-smith \
  --email alice@example.com
```

Output:
```
✅ Author keypair generated successfully!

📁 Private key saved to:
   .authors/alice-smith/private_key.secret
   ⚠️  KEEP THIS SECRET! Never commit to git.

🔑 Public key:
   a1b2c3d4e5f6789...

Next steps:
1. Use this public key when signing articles
2. Sign articles with:
   cargo run -p xtask -- author-sign <article.md>
```

**Step 2: Write Article**

```bash
cargo run -p xtask -- draft "Breaking: Wizarding Stocks Plummet"
```

Edit the article in `content/news/2026/01/breaking-wizarding-stocks-plummet.md`.

**Step 3: Sign Article**

```bash
cargo run -p xtask -- author-sign content/news/2026/01/breaking-wizarding-stocks-plummet.md
```

The command will prompt:
```
Enter author ID (from .authors/ directory):
> alice-smith

✅ Signed as: Alice Smith

✅ Article signed successfully!

📋 Article hash:
   d4937380754bd91c10ed92c7...
✍️  Author signature:
   9f8e7d6c5b4a32109876...

Next steps:
1. Submit article for editorial review
2. Editorial board members review with:
   cargo run -p xtask -- editorial-review <article.md> --approve
```

**Step 4: Submit for Review**

```bash
git add content/news/2026/01/breaking-wizarding-stocks-plummet.md
git commit -m "feat: Add article on wizarding stock crash (pending review)"
git push
```

Article frontmatter now includes:

```toml
[extra.author_signature]
author_id = "alice-smith"
name = "Alice Smith"
email = "alice@example.com"
pubkey = "a1b2c3d4e5f6789..."
signature = "9f8e7d6c5b4a321..."

[extra.editorial_approval]
required = 3  # Needs 3 board signatures
status = "pending"
```

### For Editorial Board Members

**Step 1: Generate Board Member Key (Once)**

```bash
cargo run -p xtask -- board-keygen \
  --name "Bob Editor" \
  --id bob-editor \
  --role "Senior Editor"
```

Output provides the public key to add to `config.toml`:

```toml
[[editorial_board.members]]
id = "bob-editor"
name = "Bob Editor"
role = "Senior Editor"
pubkey = "b2c3d4e5f6a7b8c9..."
active = true
joined = "2026-01-31"
```

**Step 2: Review Submitted Article**

Pull the article from git:

```bash
git pull origin main
```

Read and fact-check the article, then approve:

```bash
cargo run -p xtask -- editorial-review \
  content/news/2026/01/breaking-wizarding-stocks-plummet.md \
  --approve
```

The command will:
1. Verify author signature (ensures article wasn't tampered)
2. Prompt for your board member ID
3. Sign your approval
4. Check if threshold is reached

Output:
```
Step 1: Verifying author signature...
✅ Author signature VALID

Enter board member ID (from .editorial_board/board/ directory):
> bob-editor

Step 2: Signing approve decision as: Bob Editor

Step 3: Checking threshold (1/3 signatures)
⏳ 2 more signature(s) needed

✅ Editorial approve recorded successfully!
```

**Step 3: Threshold Reached**

After 3 board members approve, the article status changes:

```toml
[extra.editorial_approval]
required = 3
status = "approved"  # Changed from "pending"

[[extra.editorial_signatures]]
board_member = "bob-editor"
signature = "8e7d6c5b4a3210..."
timestamp = "2026-01-31T12:00:00Z"
decision = "approve"

[[extra.editorial_signatures]]
board_member = "carol-reviewer"
signature = "7d6c5b4a321098..."
timestamp = "2026-01-31T13:00:00Z"
decision = "approve"

[[extra.editorial_signatures]]
board_member = "dan-chief"
signature = "6c5b4a32109876..."
timestamp = "2026-01-31T14:00:00Z"
decision = "approve"
```

**Step 4: CI Publishes**

GitHub Actions verifies all signatures and publishes:

```yaml
- name: Verify Multi-Sig Articles
  run: |
    # Verify all articles have required signatures
    cargo run -p xtask -- verify-all-articles

- name: Build and Deploy
  if: success()
  run: cargo run -p xtask -- print
```

## Verification Commands

### Verify Specific Article

```bash
cargo run -p xtask -- verify-article content/news/2026/01/article.md
```

Output:
```
🔐 Verifying all signatures: content/news/2026/01/article.md

Step 1: Verifying author signature...
✅ Author signature VALID

Step 2: Verifying editorial signatures...
   ✅ Signature 1: bob-editor (approve)
   ✅ Signature 2: carol-reviewer (approve)
   ✅ Signature 3: dan-chief (approve)

📊 Summary: 3/3 valid approval signatures
✅ Article meets publication threshold!
```

### List Board Members

```bash
cargo run -p xtask -- board-list
```

Output:
```
📋 Editorial Board Members

| ID | Name | Role | Status |
|---|---|---|---|
| bob-editor | Bob Editor | Senior Editor | ✅ Active |
| carol-reviewer | Carol Reviewer | Fact Checker | ✅ Active |
| dan-chief | Dan Chief | Editor in Chief | ✅ Active |
| eve-deputy | Eve Deputy | Deputy Editor | ✅ Active |
| frank-emeritus | Frank Emeritus | Editor Emeritus | ❌ Inactive |
```

## Security Properties

### What This System Prevents

| Attack | Prevention |
|--------|-----------|
| **Unauthorized publication** | Requires k board signatures |
| **Content tampering** | Invalidates author + editorial signatures |
| **Impersonation** | Author signature proves identity |
| **Single rogue board member** | k-of-n threshold requires multiple approvals |
| **Key compromise** | Compromised key rotation doesn't affect old signatures |

### Cryptographic Signature Chain

```
Article body (plaintext)
    ↓
    SHA-256 hash
    ↓
Author signs: Ed25519(author_private_key, article_hash)
    ↓
Review hash: SHA-256(article_hash + author_signature)
    ↓
Board member signs: Ed25519(board_private_key, review_hash)
```

This creates a **chain-of-custody**:
1. Article hash proves content integrity
2. Author signature proves authorship
3. Editorial signatures prove k board members approved the (article + author_signature) combination
4. Tampering with article invalidates author signature
5. Tampering with author signature invalidates editorial signatures

### Threshold Security

**k-of-n threshold** means:
- **n** total board members (e.g., 5)
- **k** required signatures (e.g., 3)
- Attacker must compromise **k keys** to forge approval

**Examples:**
- 3-of-5: Requires compromising 3 keys (60% of board)
- 5-of-7: Requires compromising 5 keys (71% of board)
- 1-of-3: Requires compromising 1 key (33% - not recommended)

**Tradeoffs:**
- Higher k = more secure, but harder to reach threshold
- Lower k = faster approvals, but less secure
- **Recommended:** k = ⌈n/2⌉ + 1 (simple majority + 1)

## Key Management

### Author Keys

**Location:** `.authors/<author-id>/private_key.secret`

**Protection:**
- Git-ignored (never committed)
- Author controls their own key
- No shared secrets

**Rotation:** Generate new keypair with new ID, re-sign articles

### Board Member Keys

**Location:** `.editorial_board/board/<member-id>/private_key.secret`

**Protection:**
- Git-ignored (never committed)
- Individual member controls their key
- CI/CD does NOT have access (only site-level key)

**Rotation:** Generate new keypair, deactivate old member in config.toml

### Site-Level Key (Backward Compatibility)

**Location:** `.editorial_board/private_key.secret`

**Purpose:**
- Backward compatibility with single-signature articles
- Optional: CI/CD automated signing (not recommended for sensitive content)

**Future:** This key may be deprecated in favor of pure multi-sig workflow.

## Future Enhancements

### LLM Fact-Checking Integration

**Proposed architecture:**
- Claude API integration for automated fact-checking
- AI acts as special "board member" with weighted signature
- AI provides confidence score + reasoning
- Human editors can override AI decisions

**Example:**
```toml
[[editorial_signatures]]
board_member = "claude-fact-checker"  # Special AI member
signature = "..."
timestamp = "2026-01-31T11:00:00Z"
decision = "approve"
confidence = 0.92  # AI confidence: 92%
reasoning = "Verified claims against reputable sources. Found 3 citations, all valid."
```

### Hardware Security Keys (YubiKey)

**Proposed:**
- Store private keys on YubiKey hardware device
- Requires physical key presence for signing
- Maximum security for high-stakes publications

See [YubiKey Setup Guide](../yubikey-setup/) (coming soon).

## Migration from Single-Signature

### Backward Compatibility

The system supports **both** single-signature and multi-signature articles:

**Single-signature articles** (legacy):
- Have `integrity` field in frontmatter
- Signed by site-level key
- Verified by `verify-signature` command

**Multi-signature articles** (new):
- Have `[author]` and `[[editorial_signatures]]` sections
- Signed by author + k board members
- Verified by `verify-article` command

### Migration Steps

1. **Add board members** to config.toml
2. **Generate board member keys** for each member
3. **New articles** use multi-sig workflow automatically
4. **Old articles** remain valid (no re-signing needed)
5. **Gradually migrate** old articles if needed

## Use This System

This entire publishing platform is **open source and free**:

```bash
# Use as template
gh repo create my-publication --template fangluo/LaPropaganda

# Setup multi-sig workflow
cd my-publication

# Generate author keys
cargo run -p xtask -- author-keygen --name "Your Name" --id your-id

# Generate board member keys
cargo run -p xtask -- board-keygen \
  --name "Board Member" \
  --id member-id \
  --role "Editor"

# Start publishing
cargo run -p xtask -- draft "Your Article"
cargo run -p xtask -- author-sign content/news/YYYY/MM/your-article.md
```

---

**Questions?** See:
- [How It Works](../how-it-works/) - System architecture
- [Verification Guide](../verification-guide/) - Reader instructions
- [Archive Strategy](../archive-strategy/) - Long-term preservation
- `.authors/README.md` - Author key management
- `.editorial_board/board/README.md` - Board member key management
