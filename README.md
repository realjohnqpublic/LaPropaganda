# La Propaganda - Secure Publishing Template

[![Security: Signed](https://img.shields.io/badge/security-signed-green.svg)](https://github.com/fangluo/LaPropaganda)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Use This Template](https://img.shields.io/badge/use-this_template-purple.svg)](https://github.com/fangluo/LaPropaganda/generate)

**A cryptographically secure static publishing platform with tamper-evident content integrity.**

This is a GitHub template for building publications with built-in cryptographic verification. Every article is digitally signed, hash-verified, and includes visual randomart fingerprinting for reader verification.

## ⚡ Quick Start (5 Minutes)

```bash
# 1. Use this template (GitHub UI: "Use this template" button)

# 2. Clone your new repository
git clone https://github.com/YOUR-USERNAME/YOUR-PUBLICATION
cd YOUR-PUBLICATION

# 3. Generate editorial board signing key
cargo run -p xtask -- generate-key

# 4. Add private key to GitHub Secrets
gh secret set EDITORIAL_BOARD_PRIVATE_KEY < .editorial_board/private_key.secret

# 5. Customize your publication
# Edit config.toml:
#   base_url = "https://YOUR-USERNAME.github.io/YOUR-PUBLICATION"
#   title = "Your Publication Name"
#   description = "Your tagline"

# 6. Push and publish
git add config.toml .gitignore
git commit -m "feat: Initialize secure publication"
git push origin main

# Done! CI will build, sign, and deploy automatically.
```

## 🔒 Security Features

### Three-Layer Protection

```
┌─────────────────────────────────────────┐
│ Layer 1: Content Integrity (SHA-256)   │
│ - Individual article hashes             │
│ - Global site hash                      │
│ - Randomart visualization               │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│ Layer 2: Authorization (Ed25519)       │
│ - Editorial board signatures           │
│ - Public key verification               │
│ - Tamper-evident publishing             │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│ Layer 3: Visual Verification           │
│ - Randomart fingerprint                 │
│ - Quick visual integrity check          │
│ - Reader-friendly verification          │
└─────────────────────────────────────────┘
```

### What This Prevents

- ✅ **Content tampering** - SHA-256 detects ANY modification
- ✅ **Unauthorized changes** - Ed25519 signatures prove editorial authorization
- ✅ **Silent modifications** - Randomart provides visual change detection
- ✅ **Website compromise** - Readers can verify content independently

## 📖 Use Cases

This template is ideal for:

- **Journalism** - Tamper-evident news publishing
- **Research** - Verified academic papers and datasets
- **Whistleblowing** - Authenticated document publication
- **Government** - Transparent public records
- **Organizations** - Trusted official communications

## 🛠️ Available Commands

```bash
# Content Management
cargo run -p xtask -- draft "Article Title"    # Create new article
cargo run -p xtask -- proofread                 # Preview locally (zola serve)
cargo run -p xtask -- hash                      # Sign all content
cargo run -p xtask -- print                     # Build static site

# Security & Verification
cargo run -p xtask -- generate-key              # Generate Ed25519 keypair
cargo run -p xtask -- verify                    # Verify content hashes
cargo run -p xtask -- verify-signature          # Verify cryptographic signature
cargo run -p xtask -- ci                        # Run CI checks (verify + build)
```

## 🔐 Key Management

### Local Development (Software Keys)

**Private key location:** `.editorial_board/private_key.secret` (git-ignored)
**Public key location:** `config.toml` (committed safely)

⚠️ **NEVER commit the private key to git!** It's protected by `.gitignore`.

### CI/CD (GitHub Actions)

Add your private key as a GitHub Secret:

```bash
# Option 1: GitHub CLI
gh secret set EDITORIAL_BOARD_PRIVATE_KEY < .editorial_board/private_key.secret

# Option 2: GitHub UI
# Go to: Repo Settings → Secrets and variables → Actions → New secret
# Name: EDITORIAL_BOARD_PRIVATE_KEY
# Value: (paste content of .editorial_board/private_key.secret)
```

### Key Rotation

If your private key is compromised:

```bash
# 1. Generate new keypair
cargo run -p xtask -- generate-key

# 2. Update GitHub Secret
gh secret set EDITORIAL_BOARD_PRIVATE_KEY < .editorial_board/private_key.secret

# 3. Re-sign all content
cargo run -p xtask -- hash

# 4. Commit new public key
git add config.toml
git commit -m "security: Rotate editorial board signing key"
git push
```

See [.editorial_board/README.md](.editorial_board/README.md) for detailed key management instructions.

## 📚 Reader Verification

Readers can verify content authenticity in two ways:

### Visual Check (Quick)

Look at the randomart pattern in the site header. If content changes, the pattern changes completely.

### Cryptographic Verification (Complete)

```bash
git clone https://github.com/YOUR-USERNAME/YOUR-PUBLICATION
cd YOUR-PUBLICATION
cargo run -p xtask -- verify-signature
```

Output shows ✅ **Signature VALID** or ❌ **Signature INVALID**.

## 🏗️ Architecture

### Built With

- **[Zola](https://www.getzola.org/)** - Fast static site generator (Rust)
- **[Ed25519](https://ed25519.cr.yp.to/)** - Modern elliptic curve cryptography
- **[SHA-256](https://en.wikipedia.org/wiki/SHA-2)** - Industry-standard hashing
- **[GitHub Actions](https://github.com/features/actions)** - Automated CI/CD

### Project Structure

```
your-publication/
├── .editorial_board/          # Cryptographic keys
│   ├── README.md              # Key management guide
│   ├── .gitkeep               # Track directory
│   └── private_key.secret     # Private signing key (git-ignored)
├── .github/workflows/         # CI/CD automation
│   └── newsroom.yml           # Build, sign, verify, deploy
├── content/news/              # Articles (Markdown)
│   └── 2026/01/
│       ├── how-it-works.md
│       ├── verification-guide.md
│       └── archive-strategy.md
├── templates/                 # Zola templates
│   ├── base.html              # Base template
│   └── index.html             # Homepage layout
├── static/                    # Static assets
│   └── js/main.js             # JavaScript
├── sass/                      # Styles
│   └── style.scss             # SCSS stylesheets
├── xtask/                     # Build tooling (Rust)
│   ├── Cargo.toml             # Dependencies
│   └── src/main.rs            # Newsroom CLI
├── config.toml                # Site configuration
├── Cargo.toml                 # Rust workspace
└── README.md                  # This file
```

## 🚀 Deployment

### GitHub Pages (Recommended)

Automatic deployment via GitHub Actions:

1. **Enable Pages:** Repo Settings → Pages → Source: "gh-pages" branch
2. **Push to main:** CI automatically builds, signs, verifies, and deploys
3. **Site URL:** `https://YOUR-USERNAME.github.io/YOUR-PUBLICATION`

### Custom Domain

Add `CNAME` file to static/:

```bash
echo "your-domain.com" > static/CNAME
git add static/CNAME
git commit -m "Add custom domain"
git push
```

Then configure DNS:
- Add `CNAME` record: `your-domain.com` → `YOUR-USERNAME.github.io`

## 🎨 Customization

### Update Site Metadata

Edit `config.toml`:

```toml
base_url = "https://your-domain.com"
title = "Your Publication"
description = "Your tagline"

[extra]
author = "Your Name"
public_key = "..." # Auto-generated, don't edit manually
```

### Styling

Edit `sass/style.scss` for visual customization. The default theme is a newspaper-inspired design.

### Templates

Modify templates in `templates/`:
- `base.html` - Site layout, header, footer
- `index.html` - Homepage structure

## 🔬 Advanced Features

### YubiKey Support (Coming Soon)

For hardware-backed signing with YubiKey:

```bash
# Generate key on YubiKey PIV slot
cargo run -p xtask -- generate-key --yubikey

# Sign locally (requires YubiKey inserted)
cargo run -p xtask -- hash
```

See [plan documentation](.claude/plans/) for YubiKey implementation roadmap.

### Archive System (Planned)

For long-term content preservation:

```bash
# Create monthly archive
cargo run -p xtask -- archive 2026-01

# Verify archive
cargo run -p xtask -- verify-archive 2026-01
```

Signed manifests ensure archived content remains verifiable forever.

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 🐛 Issues & Support

- **Bug reports:** [GitHub Issues](https://github.com/fangluo/LaPropaganda/issues)
- **Feature requests:** [GitHub Discussions](https://github.com/fangluo/LaPropaganda/discussions)
- **Security issues:** See [SECURITY.md](SECURITY.md)

## 🌟 Star This Repo

If you find this template useful, please star the repository to help others discover it!

## 📖 Learn More

- [How It Works](http://lapropaganda.org/news/2026/01/how-it-works/) - Architecture explanation
- [Verification Guide](http://lapropaganda.org/news/2026/01/verification-guide/) - Reader instructions
- [Archive Strategy](http://lapropaganda.org/news/2026/01/archive-strategy/) - Long-term preservation

---

**Built with security by default. No trust required - verify everything.**

[![Use This Template](https://img.shields.io/badge/use-this_template-purple.svg)](https://github.com/fangluo/LaPropaganda/generate)
