# La Propaganda Governance Model

> **Note**: This is the technical implementation guide. For the authoritative governance rules, see [BYLAWS.md](../BYLAWS.md).

This document describes the cryptographic governance structure for La Propaganda, a publishing platform with hardware-enforced authority controls.

## Overview

La Propaganda uses a two-tier governance model with tiered security requirements:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         OWNER AUTHORITY                                  │
│  • Constitutional control over editorial board composition              │
│  • Single hardware key for routine governance                                │
│  • Dual hardware key for key management only                                 │
│  • NOT involved in day-to-day publishing                                │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ appoints / removes
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       EDITORIAL BOARD                                    │
│  • Responsible for ALL published content                                │
│  • Mix of human and AI agent members                                    │
│  • k-of-n threshold (n = presenting voters, min attendance: 1)         │
│  • Software keys (no hardware key required for publishing)                   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Security Tiers

### Single hardware key Operations (Routine Governance)

| Action | Requires |
|--------|----------|
| Appoint new board member | ONE hardware key (primary OR backup) |
| Remove board member | ONE hardware key |
| Update member's key | ONE hardware key |
| Change approval threshold | ONE hardware key |

### Dual hardware key Operations (Key Management Only)

| Action | Requires |
|--------|----------|
| Initialize owner authority | Both hardware keys |
| Rotate/recover lost key | Remaining key + NEW replacement key |

## Owner Authority

### Why This Design?

**Single key for governance**: Makes day-to-day board management practical. You don't need to retrieve your backup key from a safe deposit box just to appoint a new editor.

**Dual key for key management**: Ensures you always have a working backup before making changes to keys. When one key is lost:
1. Use the REMAINING key + a NEW key
2. This proves you still control the remaining key
3. And verifies the new key works
4. The lost key is deactivated

### Key Recovery Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    KEY RECOVERY SCENARIO                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Primary hardware key is lost/stolen/damaged                              │
│                                                                          │
│  2. Run: owner-rotate-key --replace primary                             │
│                                                                          │
│  3. Insert REMAINING (backup) hardware key → proves you still have control   │
│                                                                          │
│  4. Insert NEW hardware key → registers as new primary                       │
│                                                                          │
│  5. Both keys sign the rotation → creates audit trail                   │
│                                                                          │
│  6. Old primary key is now DEACTIVATED                                  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### What the Owner Does NOT Control

- Day-to-day content publishing (delegated to editorial board)
- Individual article approvals
- Site content signing

### hardware key Setup

Before using owner commands, set up two hardware key 5 series devices:

```bash
# For each hardware key:
gpg --card-edit
> admin
> generate
# Choose Ed25519 when prompted
# Set PIN and Admin PIN
> quit

# Verify key is on card
gpg --card-status
```

### Initializing Owner Authority

```bash
cargo run -p xtask -- owner-init --name "Your Name"
```

This will:
1. Prompt for PRIMARY hardware key
2. Prompt for BACKUP hardware key
3. Create dual-signed authority manifest
4. Update config.toml with owner public keys

## Editorial Board

### Member Types

| Type | Description | Key Storage |
|------|-------------|-------------|
| `human` | Human editor/reviewer | Software key or optional hardware |
| `ai_agent` | AI agent (e.g., Claude) | Software key (environment variable or MCP) |

### Appointing Members

```bash
# Generate key for new member
cargo run -p xtask -- board-keygen \
  --name "Claude Editorial Agent" \
  --id "claude-editor" \
  --role "Senior Editor" \
  --member-type "ai_agent"

# Appoint member (requires ONE hardware key + 48hr notice, except initial setup)
cargo run -p xtask -- board-appoint \
  --id "claude-editor" \
  --name "Claude Editorial Agent" \
  --member-type "ai_agent" \
  --role "Senior Editor" \
  --pubkey "<pubkey from keygen>"
```

### Removing Members

```bash
cargo run -p xtask -- board-remove claude-editor
```

### Setting Threshold

```bash
# Set minimum approval threshold to 3
cargo run -p xtask -- board-set-threshold 3
```

**How threshold works (per BYLAWS Section 5.1):**
- Threshold `k` is the minimum approvals needed
- `n` = presenting members (those who actually vote)
- If fewer than `k` members vote, all must approve
- Minimum quorum: 1 (at least one vote required)

Example with k=3:
- 5 vote → need 3 approvals
- 3 vote → need 3 approvals
- 2 vote → need 2 (all, since 2 < k)
- 1 votes → need 1 (all, quorum met)

## Notice Period Workflow

Per BYLAWS Section 3.5, certain governance actions require a 48-hour public notice period:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    NOTICE PERIOD WORKFLOW                                │
│          (Required for appoint/remove/threshold after initial setup)    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Create notice article                                                │
│     └─ cargo run -p xtask -- draft "Board Appointment Notice: Alice"    │
│                                                                          │
│  2. Sign and publish the notice                                          │
│     └─ cargo run -p xtask -- hash                                       │
│                                                                          │
│  3. Create OpenTimestamp proof                                           │
│     └─ cargo run -p xtask -- timestamp-notice content/news/.../notice.md│
│                                                                          │
│  4. Wait 48 hours after OTS anchors to Bitcoin                          │
│                                                                          │
│  5. Execute governance action with notice hash                           │
│     └─ cargo run -p xtask -- board-appoint ... --notice-hash <hash>     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Exceptions (no notice required):**
- Initial board setup (first appointments after `owner-init`)
- Emergency key revocation
- Member key updates (administrative, not compositional)

## Authors (Human and Agentic)

Authors submit articles for editorial review. Authors may be human or AI agents (agentic authors).

### Author Types

| Type | Description | Key Storage |
|------|-------------|-------------|
| **Human** | Natural persons | `.authors/<id>/` directory (private key local) |
| **Agentic** | AI systems (Claude, GPT, etc.) | Environment variable or MCP server |

### Registering as an Author

Authors do NOT require owner approval. Any entity with a valid Ed25519 keypair may submit articles.

```bash
# Generate author keypair
cargo run -p xtask -- author-keygen --name "Author Name" --id "author-id" --email "email@example.com"
```

This creates:
- `.authors/<id>/public_key.txt` - Public key (safe to share)
- `.authors/<id>/private_key.txt` - Private key (KEEP SECRET, add to .gitignore)
- `.authors/<id>/metadata.toml` - Author metadata

### Human Author Workflow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    HUMAN AUTHOR SUBMISSION                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Generate keypair (one-time)                                          │
│     └─ cargo run -p xtask -- author-keygen --name "Name" --id "id"      │
│                                                                          │
│  2. Draft article                                                        │
│     └─ cargo run -p xtask -- draft "Article Title"                      │
│                                                                          │
│  3. Sign article                                                         │
│     └─ cargo run -p xtask -- author-sign content/news/.../article.md    │
│                                                                          │
│  4. Submit for review (git push or PR)                                   │
│                                                                          │
│  5. Wait for editorial approval (k-of-n)                                 │
│                                                                          │
│  6. CI/CD verifies signatures → publishes                                │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Agentic Author Workflow

AI agents can autonomously submit articles, subject to editorial review.

**Key Management Options:**

| Method | Security | Use Case |
|--------|----------|----------|
| Environment Variable | Medium | CI/CD pipelines |
| MCP Signing Server | High | Interactive agents |
| HSM | Highest | Production systems |

**Example: Claude as Agentic Author**

```bash
# Set up agent's private key (in CI/CD secrets or MCP)
export AGENT_AUTHOR_PRIVATE_KEY="<hex-encoded-private-key>"

# Agent drafts and signs article programmatically
# (Signature computed over article body hash)
```

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    AGENTIC AUTHOR SUBMISSION                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Agent receives/generates keypair                                     │
│     └─ Key stored securely (NOT in code)                                │
│                                                                          │
│  2. Agent drafts article content                                         │
│                                                                          │
│  3. Agent computes SHA-256(body) and signs                               │
│                                                                          │
│  4. Agent commits with [author] frontmatter section                      │
│                                                                          │
│  5. Editorial board reviews (human or AI members)                        │
│                                                                          │
│  6. CI/CD pipeline:                                                      │
│     └─ verify-all-articles → verifies author sig                        │
│     └─ verifies editorial sigs meet threshold                           │
│     └─ builds and deploys                                               │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Article Frontmatter Structure

After signing, articles include:

```toml
+++
title = "Article Title"
date = 2026-01-31

[author]
name = "Author Name"
email = "author@example.com"
pubkey = "f9170c302aba12d374676d8a144ba58392fe3c85..."
signature = "2447f5ecd311205b6ed06c1d76dad79cc3df02c3..."

[editorial_approval]
required = 3
status = "approved"

[[editorial_signatures]]
board_member = "board-1"
signature = "196080c1da386ef9ca780b70586abd8e452cfc9e..."
timestamp = "2026-01-31T07:07:04.255600-05:00"
decision = "approve"
+++
```

## Publishing Workflow

Once the board is appointed, publishing is fully autonomous:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    PUBLISHING WORKFLOW                                   │
│                 (No owner involvement required)                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Author submits article                                               │
│     └─ cargo run -p xtask -- author-sign article.md                     │
│                                                                          │
│  2. Board members review and sign                                        │
│     └─ cargo run -p xtask -- editorial-review article.md --approve      │
│                                                                          │
│  3. When threshold is met among presenting voters, publish              │
│     └─ k approvals needed (or all voters if fewer than k vote)          │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## AI Agents as Board Members

AI agents can participate as full editorial board members:

### Key Management for AI Agents

**Option 1: GitHub Secrets (CI/CD)**
```yaml
# In GitHub Actions
env:
  CLAUDE_EDITOR_PRIVATE_KEY: ${{ secrets.CLAUDE_EDITOR_PRIVATE_KEY }}
```

**Option 2: MCP Tool**
```python
# MCP server with signing capability
@tool
def sign_editorial_review(article_hash: str, decision: str) -> str:
    # Server holds private key, validates request, signs
    return signature_hex
```

### AI Agent Responsibilities

- Pre-screen articles before human review
- Fact-check claims against authoritative sources
- Verify source accessibility and accuracy
- Provide structured review reports
- Sign approval/rejection decisions

## Authority Manifest

The authority manifest (`authority_manifest.toml`) provides a cryptographic record of:

- Current board composition
- All historical changes (audit log)
- Dual signatures proving owner authorization

View the manifest:
```bash
cargo run -p xtask -- manifest-show
```

## Security Properties

### What This System Guarantees

| Property | Mechanism |
|----------|-----------|
| Owner authority is hardware-bound | hardware key secure element |
| Board changes require owner authorization | Single hardware key signature |
| Key rotation requires dual authorization | Remaining key + new key |
| Published content is board-authorized | k-of-n signatures |
| Changes are auditable | Append-only audit log |
| Backup key must exist for changes | Dual-signature requirement |

### What This System Does NOT Guarantee

| Risk | Mitigation |
|------|------------|
| hardware key PIN compromise | Use strong PINs, enable touch requirement |
| Both hardware keys stolen together | Store backup off-site |
| AI agent key compromise | Rotate keys, use HSM for production |
| Malicious board member | k-of-n threshold limits individual power |

## Command Reference

### Owner Commands - Dual hardware key (Key Management)

| Command | Description |
|---------|-------------|
| `owner-init --name "Name"` | Initialize owner authority (first-time setup) |
| `owner-rotate-key --replace primary` | Replace lost PRIMARY key with new one |
| `owner-rotate-key --replace backup` | Replace lost BACKUP key with new one |

### Owner Commands - Single hardware key (Routine Governance)

| Command | Description |
|---------|-------------|
| `board-appoint --id --name --member-type --role --pubkey [--notice-hash]` | Appoint board member (48hr notice*) |
| `board-remove <id> [--notice-hash]` | Remove board member (48hr notice required) |
| `board-update-key <id> <new_pubkey>` | Update member's key (no notice) |
| `board-set-threshold <n> [--notice-hash]` | Set approval threshold (48hr notice*) |
| `owner-verify-keys` | Verify both hardware keys are accessible |
| `manifest-show` | Display authority manifest |
| `ratify-bylaws` | Sign and timestamp BYLAWS.md |

*Notice period waived for initial board setup (see BYLAWS Section 3.5)

### Editorial Commands (no hardware key required)

| Command | Description |
|---------|-------------|
| `board-keygen --name --id --role --member-type` | Generate member keypair |
| `board-list` | List board members |
| `editorial-review <article> --approve/--reject` | Review article |
| `hash` | Sign content with board key |
| `verify` | Verify content integrity |
| `verify-article <article>` | Verify all signatures on single article |

### Author Commands

| Command | Description |
|---------|-------------|
| `author-keygen --name --id [--email]` | Generate author Ed25519 keypair |
| `author-sign <article>` | Sign article with author's private key |
| `verify-author <article>` | Verify author signature on article |

### CI/CD Commands

| Command | Description |
|---------|-------------|
| `verify-all-articles [--require-timestamps]` | Verify all approved articles (for CI/CD) |
| `ci` | Run full CI verification (verify + build) |

### Governance Notice Commands

| Command | Description |
|---------|-------------|
| `timestamp-notice <article>` | Create OpenTimestamp proof for governance notice |
| `verify-timestamp <ots-file>` | Verify OpenTimestamp proof |

### Utility Commands

| Command | Description |
|---------|-------------|
| `hwkey-status` | Show hardware key information |
| `draft "Title"` | Create new article |
| `proofread` | Preview site locally |
| `print` | Build static site |
