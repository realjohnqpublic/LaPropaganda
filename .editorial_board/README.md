# Editorial Board Key Management

This directory contains cryptographic keys used for signing content.

## ⚠️ Security Warning

**NEVER commit `private_key.secret` to git!**

The private key is listed in `.gitignore` to prevent accidental commits.

## Key Files

### `private_key.secret` (Git-ignored, SECRET)
- Ed25519 private signing key (32 bytes, hex-encoded)
- Used to sign content and prove editorial authorization
- **Must be kept secret**
- Backed up securely outside of git
- Used locally for development

### Public Key (in `config.toml`)
- Ed25519 public verification key (32 bytes, hex-encoded)
- Stored in `config.toml` under `[extra]` section
- **Safe to commit** - this is how readers verify signatures
- Mathematically linked to private key

## Key Generation

Generate a new keypair:

```bash
cargo run -p xtask -- generate-key
```

This will:
1. Create `.editorial_board/private_key.secret`
2. Add public key to `config.toml`
3. Display instructions for GitHub Secrets setup

## GitHub CI/CD Setup

For automated signing in CI:

```bash
# Add private key to GitHub Secrets
gh secret set EDITORIAL_BOARD_PRIVATE_KEY < .editorial_board/private_key.secret
```

Or manually:
1. Go to Repository Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Name: `EDITORIAL_BOARD_PRIVATE_KEY`
4. Value: (paste content of `private_key.secret`)

## Signing Workflow

### Local Development (Software Keys)

```bash
# 1. Generate keypair (once)
cargo run -p xtask -- generate-key

# 2. Write content
cargo run -p xtask -- draft "Article Title"
# Edit the article...

# 3. Sign content
cargo run -p xtask -- hash
# This hashes articles AND signs with private key

# 4. Verify signature
cargo run -p xtask -- verify-signature

# 5. Commit and push
git add .
git commit -m "feat: Add signed article"
git push
```

### CI Workflow

When you push to main:
1. CI loads private key from `EDITORIAL_BOARD_PRIVATE_KEY` secret
2. Runs `hash` command to sign content
3. Runs `verify-signature` to confirm
4. Builds and deploys site

## Key Rotation

If the private key is compromised:

```bash
# 1. Generate new keypair
cargo run -p xtask -- generate-key

# 2. Update GitHub Secret
gh secret set EDITORIAL_BOARD_PRIVATE_KEY < .editorial_board/private_key.secret

# 3. Re-sign all content
cargo run -p xtask -- hash

# 4. Commit new public key and signatures
git add config.toml
git commit -m "security: Rotate editorial board signing key"
git push
```

## YubiKey Support (Optional, Advanced)

For hardware-backed signing with YubiKey:

```bash
# Generate key on YubiKey PIV slot
cargo run -p xtask -- generate-key --yubikey

# Sign content (requires YubiKey inserted)
cargo run -p xtask -- hash
```

See main README for full YubiKey setup instructions.

## Security Properties

The Ed25519 signature system provides:

- **Integrity**: Detects any modification to content
- **Authenticity**: Proves content was signed by holder of private key
- **Non-repudiation**: Signer cannot deny signing
- **Public verification**: Anyone can verify with public key

## Troubleshooting

### Error: "No signing key found"

Run `cargo run -p xtask -- generate-key` first.

### Error: "Signature verification failed"

Content has been modified after signing. Run `cargo run -p xtask -- hash` to re-sign.

### CI failing with "No signing key found"

Add `EDITORIAL_BOARD_PRIVATE_KEY` to GitHub Secrets.
