# Editorial Board Member Keys

This directory stores Ed25519 cryptographic signing keys for editorial board members in the multi-signature publication system.

## Overview

In the multi-signature workflow, **editorial board members review and sign articles** after authors submit them. The system requires **k-of-n threshold signatures** (e.g., 3 out of 5 board members) before an article can be published.

## Directory Structure

```
.editorial_board/
├── private_key.secret    # Site-level signing key (backward compatibility)
├── README.md             # Site-level key management docs
└── board/
    ├── README.md         # This file
    └── <member-id>/
        ├── private_key.secret  # Board member's Ed25519 private key
        └── member.info         # Board member metadata (name, role, pubkey)
```

## Generating Board Member Keys

Generate a new board member keypair:

```bash
cargo run -p xtask -- board-keygen \
  --name "Bob Editor" \
  --id bob-editor \
  --role "Senior Editor"
```

This creates:
- `.editorial_board/board/bob-editor/private_key.secret` - **NEVER commit to git!**
- `.editorial_board/board/bob-editor/member.info` - Metadata including public key

After generation, manually add the member to `config.toml`:

```toml
[[editorial_board.members]]
id = "bob-editor"
name = "Bob Editor"
role = "Senior Editor"
pubkey = "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"
active = true
joined = "2026-01-30"
```

## Editorial Review Workflow

### Step 1: Author Submits Article

Author signs article and pushes to git:
```bash
cargo run -p xtask -- author-sign content/news/2026/01/article.md
git add .
git commit -m "feat: Add new article (pending review)"
git push
```

### Step 2: Board Member Reviews

Board member reviews the article and approves/rejects:

```bash
# Approve the article
cargo run -p xtask -- editorial-review content/news/2026/01/article.md --approve

# OR reject the article
cargo run -p xtask -- editorial-review content/news/2026/01/article.md --reject
```

The command will:
1. Verify the author's signature is valid
2. Prompt for your board member ID
3. Calculate review hash: `SHA-256(article_hash + author_signature)`
4. Sign the review hash with your private key
5. Add your signature to the article's frontmatter
6. Check if threshold is met (e.g., 3 signatures)
7. If threshold met, update status to "approved"

### Step 3: Publication

Once the threshold is met (e.g., 3 approvals), the article status changes to "approved" and CI can deploy it.

## Listing Board Members

View all board members:

```bash
cargo run -p xtask -- board-list
```

Output:
```
| ID | Name | Role | Status |
|---|---|---|---|
| bob-editor | Bob Editor | Senior Editor | ✅ Active |
| carol-reviewer | Carol Reviewer | Fact Checker | ✅ Active |
| dan-chief | Dan Chief | Editor in Chief | ✅ Active |
```

## Threshold Configuration

The approval threshold is set in each article's frontmatter:

```toml
[editorial_approval]
required = 3  # k-of-n: needs 3 signatures
status = "pending"  # or "approved" or "rejected"
```

You can also set a default threshold in `config.toml`:

```toml
[extra]
editorial_board_threshold = 3  # Default: requires 3 signatures
```

## Verifying Article Signatures

Verify all signatures on an article (author + editorial):

```bash
cargo run -p xtask -- verify-article content/news/2026/01/article.md
```

Output shows:
```
Step 1: Verifying author signature...
✅ Author signature VALID

Step 2: Verifying editorial signatures...
   ✅ Signature 1: bob-editor (approve)
   ✅ Signature 2: carol-reviewer (approve)
   ✅ Signature 3: dan-chief (approve)

📊 Summary: 3/3 valid approval signatures
✅ Article meets publication threshold!
```

## Security

### Private Key Protection

**CRITICAL:** Board member private keys must NEVER be committed to git!

Protection layers:
1. `.gitignore` blocks all `.editorial_board/board/**/*.secret` files
2. Git hooks verify no secrets are committed
3. CI/CD should only have site-level key (for backward compatibility)

### Signing Chain Verification

Editorial signatures create a cryptographic chain:

```
Article body
  ↓ SHA-256
Article hash
  ↓ Author signs
Author signature
  ↓ Combine: SHA-256(article_hash + author_signature)
Review hash
  ↓ Board member signs
Editorial signature
```

This ensures:
- Board members sign both the article content AND the author's approval
- Tampering with article invalidates author signature
- Tampering with author signature invalidates editorial signatures
- Complete chain-of-custody cryptographic proof

## Board Member Management

### Adding a New Member

1. Generate keypair:
   ```bash
   cargo run -p xtask -- board-keygen --name "Eve Deputy" --id eve-deputy --role "Deputy Editor"
   ```

2. Add to `config.toml`:
   ```toml
   [[editorial_board.members]]
   id = "eve-deputy"
   name = "Eve Deputy"
   role = "Deputy Editor"
   pubkey = "<hex from keygen output>"
   active = true
   joined = "2026-01-31"
   ```

3. Commit public key (safe):
   ```bash
   git add config.toml
   git commit -m "feat: Add Eve Deputy to editorial board"
   ```

4. Share private key securely:
   - **Option A**: Encrypt and send: `gpg -r eve@example.com -e .editorial_board/board/eve-deputy/private_key.secret`
   - **Option B**: In-person transfer via USB
   - **Option C**: Hardware security key (YubiKey)

### Deactivating a Member

When a board member leaves:

1. Update `config.toml`:
   ```toml
   [[editorial_board.members]]
   id = "frank-emeritus"
   active = false  # Changed from true
   retired = "2026-01-31"
   ```

2. Commit change:
   ```bash
   git add config.toml
   git commit -m "chore: Retire Frank from editorial board"
   ```

3. Their old signatures remain valid, but they cannot sign new articles.

### Key Rotation

If a board member's private key is compromised:

```bash
# 1. Immediately deactivate old key in config.toml
# 2. Generate new keypair with new ID
cargo run -p xtask -- board-keygen --name "Bob Editor" --id bob-editor-v2 --role "Senior Editor"

# 3. Update config.toml
[[editorial_board.members]]
id = "bob-editor"
active = false
compromised = "2026-01-31"

[[editorial_board.members]]
id = "bob-editor-v2"
active = true
joined = "2026-01-31"
pubkey = "<new public key>"

# 4. Old signatures remain valid
# 5. New articles signed with new key
```

## Frequently Asked Questions

### Q: What happens if we can't reach threshold?

If you can't get k signatures:
- Article remains in "pending" status
- CI blocks deployment of pending articles
- Options:
  1. Lower threshold in article frontmatter (requires existing signatures)
  2. Recruit more board members
  3. Reject the article

### Q: Can a board member approve their own article?

**Not recommended** - this defeats the purpose of multi-sig review. Best practices:
- Authors should not be on the editorial board for their own articles
- Use conflict-of-interest policies
- Require signatures from members who didn't write the article

### Q: What if a board member disagrees with others?

Board members can `--reject` instead of `--approve`:

```bash
cargo run -p xtask -- editorial-review article.md --reject
```

Rejection signatures are recorded but don't count toward the approval threshold. The article shows:

```
[[editorial_signatures]]
board_member = "carol-reviewer"
decision = "reject"  # This doesn't count toward approval
```

### Q: How do we change the threshold?

The threshold is per-article. To change it:

```toml
[editorial_approval]
required = 5  # Change from 3 to 5
status = "pending"
```

**Note:** Changing the threshold after signatures are collected may invalidate the article's approval status.

### Q: Can we have different thresholds for different types of articles?

Yes! Each article can have its own threshold:

```toml
# Investigative journalism: high threshold
[editorial_approval]
required = 5

# Op-eds: lower threshold
[editorial_approval]
required = 2

# Breaking news: emergency threshold
[editorial_approval]
required = 1
```

### Q: What if GitHub Actions needs to sign articles?

For automated deployment:

**Option A**: Use site-level key (backward compatibility)
```yaml
env:
  EDITORIAL_BOARD_PRIVATE_KEY: ${{ secrets.EDITORIAL_BOARD_PRIVATE_KEY }}
```

**Option B**: Create a bot board member
```toml
[[editorial_board.members]]
id = "ci-bot"
name = "CI/CD Bot"
role = "Automated Publisher"
active = true
```

Store bot's private key in GitHub Secrets and use it for automated approvals.

## Contact

For questions about editorial board signing:
- **Documentation**: See `content/news/` articles about multi-sig workflow
- **Issues**: [GitHub Issues](https://github.com/fangluo/LaPropaganda/issues)
- **Security**: See `SECURITY.md` for vulnerability disclosure
