+++
title = "Long-Term Content Archiving Strategy"
date = 2026-01-30
[extra]
author = "Infrastructure Team"

[extra.author_signature]
author_id = "infra-team"
name = "Infrastructure Team"
pubkey = "f9170c302aba12d374676d8a144ba58392fe3c85478d0de44420a36743ed73b6"
signature = "infra_team_signature_placeholder_hex_string_that_is_long_enough"
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
integrity = "ab2d6645a9751ad13e8611153949699cdd0eb669449455e4f6c8189499a131ee"+++

As publications grow, git repositories become bloated. This system includes a **scalable archiving strategy** for long-term content preservation with cryptographic integrity.

## The Git Problem

Git is excellent for version control but problematic for large-scale publishing:

### Growth Projections
- **100 articles/month** × 12 months = **1,200 articles/year**
- Each with full version history
- Plus images, animations, binary assets
- **Result:** Repository size grows unbounded

### Real-World Constraints
- **GitHub limit:** 100GB repository size
- **Clone time:** Increases linearly with history size
- **CI/CD costs:** More data = longer builds = higher costs
- **Old content:** Rarely needs version history after publication

## The Archive Solution

Our system uses **signed manifests** for monthly/yearly content snapshots.

### Archive Structure

```
archives/
├── index.html              # Archive landing page
├── 2026/
│   ├── 01/
│   │   ├── manifest.toml   # Signed manifest
│   │   ├── index.html      # Month archive page
│   │   └── articles/       # Frozen HTML
│   │       ├── how-it-works.html
│   │       └── verification-guide.html
│   └── 02/
│       └── ...
└── 2025/
    └── 12/
        └── ...
```

### Signed Manifest Format

**`archives/2026/01/manifest.toml`:**
```toml
[archive]
period = "2026-01"
created_at = "2026-02-01T00:00:00Z"
article_count = 3
archived_by = "Editorial Board"

[signature]
algorithm = "Ed25519"
public_key = "ba02dcac96a4254e96c7c47601502cc3..."
signature = "signed_hash_of_this_manifest..."

[[articles]]
slug = "how-it-works"
title = "How This Secure Publishing System Works"
date = "2026-01-30"
author = "System Documentation"
integrity = "sha256_hash_of_html..."
html_path = "articles/how-it-works.html"

[[articles]]
slug = "verification-guide"
title = "How to Verify Content Authenticity"
date = "2026-01-30"
author = "Transparency Team"
integrity = "sha256_hash_of_html..."
html_path = "articles/verification-guide.html"
```

## Archive Workflow

### Step 1: Freeze Content (End of Month)

```bash
# Create archive for January 2026
cargo run -p xtask -- archive 2026-01
```

**What happens:**
1. Identifies all articles from 2026-01
2. Builds static HTML for each article (via Zola)
3. Calculates SHA-256 hash of each HTML file
4. Generates manifest with article metadata + hashes
5. Signs manifest with editorial board private key
6. Exports to `archives/2026/01/` directory

### Step 2: Store Archive

Archives are stored in a **separate orphan branch** `gh-pages-archive`:

```bash
git checkout --orphan gh-pages-archive
git add archives/2026/01/
git commit -m "Archive: January 2026"
git push origin gh-pages-archive
```

### Step 3: Prune Main Branch (Optional)

After archiving, optionally remove old articles from main branch:

```bash
rm -rf content/news/2026/01/
git commit -m "Pruned archived content (2026-01)"
```

**Result:** Main repository stays small, archived content preserved separately.

## Verification

### Verify Archive Integrity

```bash
cargo run -p xtask -- verify-archive 2026-01
```

**What it checks:**
1. Manifest signature is valid (signed by editorial board)
2. Each article HTML matches its integrity hash
3. All articles listed in manifest are present

**Output:**
```
✅ Archive 2026-01 verified successfully
   - Manifest signature: VALID
   - 3 articles checked: ALL MATCH
   - No tampering detected
```

### Verify Old Archives Years Later

Archives remain verifiable indefinitely:

```bash
# Checkout archive branch
git checkout gh-pages-archive

# Verify archive from 5 years ago
cargo run -p xtask -- verify-archive 2021-01

# Result: ✅ Still valid!
```

## Storage Strategies

### Option A: Orphan Branches (Default)
- **Pros:** Simple, uses existing GitHub infrastructure
- **Cons:** Still counts toward repo size limit
- **Best for:** Small to medium publications (<10,000 articles)

### Option B: Separate Archive Repository
- **Pros:** Main repo stays tiny, unlimited archive growth
- **Cons:** Requires managing two repos
- **Best for:** Large publications or multi-year archives

### Option C: Content-Addressed Storage (IPFS)
- **Pros:** Permanent, decentralized, content-addressable
- **Cons:** Requires IPFS infrastructure, more complex
- **Best for:** Critical historical records

## Archive Commands (Coming Soon)

```bash
# Create monthly archive
cargo run -p xtask -- archive 2026-01

# Create yearly archive
cargo run -p xtask -- archive 2026

# Verify specific archive
cargo run -p xtask -- verify-archive 2026-01

# List all archives
cargo run -p xtask -- archives

# Restore archive to staging
cargo run -p xtask -- restore-archive 2026-01
```

## Benefits

✅ **Main repo stays small** - Active content only
✅ **Archives cryptographically signed** - Tamper-evident
✅ **Historical content preserved** - Never lost
✅ **Faster clone times** - Less history to download
✅ **Lower CI/CD costs** - Smaller builds
✅ **Verifiable forever** - Signatures never expire

## Advanced: Timestamping

For absolute proof of publication time, combine with **OpenTimestamps**:

```bash
# Archive + timestamp to Bitcoin blockchain
cargo run -p xtask -- archive 2026-01 --timestamp

# Verify timestamp
ots verify archives/2026/01/manifest.toml.ots
```

This anchors the archive to Bitcoin's immutable blockchain, proving the content existed at a specific time.

## Implementation Status

⚠️ **Archive system is planned but not yet fully implemented.**

**Current status:**
- ✅ Cryptographic signing system complete
- ✅ Content integrity verification complete
- 🔄 Archive command in development
- 🔄 Manifest generation in development
- 🔄 Archive verification in development

**Roadmap:**
- **Phase 1 (Complete):** Ed25519 signing
- **Phase 2 (In Progress):** Template transformation
- **Phase 3 (Planned):** Archive system
- **Phase 4 (Future):** YubiKey support, OpenTimestamps

Track progress in our [GitHub Issues](https://github.com/fangluo/LaPropaganda/issues).

## Use This System

This entire publishing platform is **open source and free**:

```bash
# Use as template
gh repo create my-publication --template fangluo/LaPropaganda

# Or clone directly
git clone https://github.com/fangluo/LaPropaganda
cd LaPropaganda
cargo run -p xtask -- generate-key
```

---

**Questions?** See [How It Works](../how-it-works/) for architecture overview.
