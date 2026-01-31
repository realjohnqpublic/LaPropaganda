# Author Keys Directory

This directory stores Ed25519 cryptographic signing keys for individual authors in the multi-signature publication system.

## Overview

In the multi-signature workflow, **authors sign their own articles** before submitting them for editorial review. Each author has their own Ed25519 keypair stored in `.authors/<author-id>/`.

## Directory Structure

```
.authors/
├── README.md           # This file
└── <author-id>/
    ├── private_key.secret    # Ed25519 private key (32 bytes hex)
    └── author.info           # Author metadata (name, email, pubkey)
```

## Generating Author Keys

Generate a new author keypair:

```bash
cargo run -p xtask -- author-keygen --name "Alice Smith" --id alice-smith --email alice@example.com
```

This creates:
- `.authors/alice-smith/private_key.secret` - **NEVER commit to git!**
- `.authors/alice-smith/author.info` - Metadata including public key

## Signing Articles

After writing an article, sign it with your author key:

```bash
cargo run -p xtask -- author-sign content/news/2026/01/my-article.md
```

The command will:
1. Prompt for your author ID
2. Calculate SHA-256 hash of article body
3. Sign hash with your private key
4. Update article frontmatter with signature
5. Set editorial approval status to "pending"

## Security

### Private Key Protection

**CRITICAL:** Private keys must NEVER be committed to git!

Protection layers:
1. `.gitignore` blocks all `.authors/**/*.secret` files
2. Git hooks should verify no secrets are committed
3. CI/CD should not have access to author private keys (only board keys)

### Verifying Your Signature

Verify your signature is valid:

```bash
cargo run -p xtask -- verify-author content/news/2026/01/my-article.md
```

## Multi-Signature Workflow

### For Authors

1. **Write article**: Create article with `cargo run -p xtask -- draft "Title"`
2. **Sign article**: `cargo run -p xtask -- author-sign <article.md>`
3. **Submit for review**: Commit and push to git
4. **Wait for editorial approval**: Board members review and sign

### For Editorial Board

See `.editorial_board/board/README.md` for editorial review workflow.

## Key Rotation

If an author's private key is compromised:

```bash
# 1. Generate new keypair
cargo run -p xtask -- author-keygen --name "Alice Smith" --id alice-smith-new

# 2. Re-sign all articles by that author
find content/news -name "*.md" -exec grep -l "alice-smith" {} \; | while read article; do
    # Remove old signature section
    # Re-sign with new key
    cargo run -p xtask -- author-sign "$article"
done

# 3. Update documentation
echo "Author key rotated on $(date)" >> .authors/alice-smith/ROTATED

# 4. Remove old key (optional)
mv .authors/alice-smith .authors/alice-smith.old
```

## Frequently Asked Questions

### Q: Can multiple authors collaborate on one article?

Currently, the system supports one author signature per article. For multi-author articles:
- Primary author signs the article
- Credit additional authors in article metadata
- Future enhancement: support multiple `[[author]]` sections

### Q: What if I lose my private key?

If you lose your private key:
1. Generate a new keypair with a new ID
2. Re-sign any articles that need your signature
3. Update your author ID in the publication system

**Note:** Lost private keys cannot be recovered. Old signatures remain valid, but you cannot create new signatures with the lost key.

### Q: Can I use the same key across multiple publications?

Technically yes, but **not recommended**:
- Each publication should have isolated keys
- Compromised key affects all publications
- Better practice: one keypair per publication

### Q: How do I back up my private key?

**Secure backup options**:
1. **Hardware security key** (YubiKey): Store key on device
2. **Encrypted backup**: `gpg -c .authors/<id>/private_key.secret`
3. **Password manager**: 1Password, Bitwarden vault
4. **Offline storage**: Print QR code, store in safe

**NEVER**:
- Email private keys
- Store in Dropbox/Google Drive unencrypted
- Commit to git (even private repos)
- Share via Slack/Discord/messaging

## Contact

For questions about author signing:
- **Documentation**: See `content/news/` articles about multi-sig workflow
- **Issues**: [GitHub Issues](https://github.com/fangluo/LaPropaganda/issues)
- **Security**: See `SECURITY.md` for vulnerability disclosure
