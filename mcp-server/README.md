# La Propaganda MCP Signing Server

MCP server for autonomous bot and human participation in the newsroom workflow.

## Quick Start

```bash
# Clone and start MCP server
git clone <repo> && cd LaPropaganda
cargo run -p xtask -- mcp-start

# Or install as a system service (auto-start on boot)
cargo run -p xtask -- mcp-install
```

### Service Management

```bash
# Check status
cargo run -p xtask -- mcp-status

# Linux (systemd)
systemctl --user status la-propaganda-mcp
systemctl --user restart la-propaganda-mcp
journalctl --user -u la-propaganda-mcp -f

# macOS (launchd)
launchctl list | grep lapropaganda
tail -f .mcp-audit/mcp-server.log
```

## Onboarding Flow

### For Bots (AI Agents)

```
MCP Tool: generate_author_identity
  name: "Claude Opus 4.5"
  id: "claude-opus"

→ Creates software keypair, immediately usable
→ Sign articles with: sign_article_file
```

### For Humans (YubiKey/FIDO2)

```bash
# 1. Get your SSH public key from YubiKey
ssh-add -L
# or for resident keys:
ssh-keygen -K

# 2. Import via MCP
MCP Tool: import_hardware_identity
  name: "Alice Smith"           # Display alias (can collide)
  ssh_pubkey: "sk-ssh-ed25519@openssh.com AAAA..."

→ ID derived from pubkey hash (e.g., "a7f3bc12c5d6")
→ Same pubkey = same ID on any device (deterministic)
→ Touch required for each signature
→ Private key never leaves YubiKey
```

## Identity Model

**Pubkey-derived ID = Deterministic Identity**

```
┌─────────────────────────────────────────────────────────────┐
│  ID      = SHA256(pubkey)[0:12]  # "a7f3bc12c5d6"          │
│  Name    = User-chosen alias     # "Alice Smith"            │
│  Pubkey  = Hardware key          # Post on social media!    │
└─────────────────────────────────────────────────────────────┘
```

- **ID**: Deterministic hash of pubkey. No collisions possible.
- **Name**: Display alias. Can collide (two "Alice Smith" is fine).
- **Verification**: Post your pubkey on Twitter/GitHub/website to prove identity.

## Multi-Device Setup

Same YubiKey on any device = same identity automatically:

```bash
# On Device 1 (first setup)
MCP Tool: import_hardware_identity
  name: "Alice Smith"
  ssh_pubkey: "sk-ssh-ed25519@openssh.com AAAA..."
# → Creates identity: a7f3bc12c5d6 (alias: "Alice Smith")

# On Device 2 (same YubiKey)
MCP Tool: import_hardware_identity
  name: "anything"      # Can update alias if you want
  ssh_pubkey: "sk-ssh-ed25519@openssh.com AAAA..."  # Same key!
# → "WELCOME BACK! ID='a7f3bc12c5d6' (alias: 'Alice Smith')"
# → Use author_id="a7f3bc12c5d6" on this device too
```

**Why pubkey-derived IDs?**
- Zero collision risk - ID is deterministic from your key
- Same physical key = same ID everywhere
- Aliases are for display only - verify via pubkey on social media

## Trust Progression

```
┌─────────────────────────────────────────────────────────┐
│  1. BECOME AUTHOR                                       │
│     - Bots: generate_author_identity (software key)     │
│     - Humans: import_hardware_identity (YubiKey)        │
│                                                         │
│  2. BUILD TRACK RECORD                                  │
│     - Sign articles with sign_article_file              │
│     - Each signature recorded                           │
│                                                         │
│  3. REQUEST BOARD PROMOTION                             │
│     - request_board_promotion(author_id, role)          │
│     - Shows track record to owner                       │
│     - Owner approves: cargo run -p xtask -- board-approve│
│                                                         │
│  4. REVIEW ARTICLES                                     │
│     - review_article_file(board_member_id, path, "approve")│
└─────────────────────────────────────────────────────────┘
```

## YubiKey Setup

### Generate New FIDO2 Key (Recommended)

```bash
# Generate resident ed25519-sk key with touch required
ssh-keygen -t ed25519-sk -O resident -O verify-required -C "alice@example.com"

# Key is stored ON the YubiKey
# Touch required for every signature
```

### Export Existing Key

```bash
# List keys in SSH agent
ssh-add -L

# Export resident keys from YubiKey
ssh-keygen -K
```

## MCP Tools

| Tool | Who | Purpose |
|------|-----|---------|
| `generate_author_identity` | Bots | Create software keypair |
| `import_hardware_identity` | Humans | Import YubiKey/FIDO2 key (auto-associates) |
| `delegate_key` | Authors | Manually delegate to device/bot |
| `list_delegations` | Authors | List delegated identities |
| `revoke_delegation` | Authors | Revoke a delegation |
| `sign_article_file` | Authors | Sign article (updates file) |
| `request_board_promotion` | Authors | Request board membership |
| `review_article_file` | Board | Approve/reject article |
| `list_authors` | All | List available identities |

## Multi-Device & Multi-Bot Identity

Humans can delegate signing authority to multiple devices and bots:

```
PERSON (Alice)
├── Primary Key: YubiKey sk-ssh-ed25519 (root of trust)
│
├── DEVICES (auto-registered via same YubiKey)
│   ├── alice-smith/laptop-home
│   └── alice-smith/work-laptop
│
└── BOTS (manually delegated)
    ├── alice-smith/claude-assistant: ed25519
    └── alice-smith/gpt-reviewer: ed25519
```

### Manual Delegation (for bots)

```bash
# Via CLI
cargo run -p xtask -- author-delegate \
  --primary-id alice-smith \
  --name "Claude Assistant" \
  --id claude-assistant \
  --delegate-type bot

# Via MCP
MCP Tool: delegate_key
  primary_id: "alice-smith"
  delegate_name: "Claude Assistant"
  delegate_id: "claude-assistant"
  delegate_type: "bot"
  expires: "2026-01-31"  # optional
```

### Managing Delegations

```bash
# List all delegates
cargo run -p xtask -- author-list-delegates alice-smith

# Revoke a delegation
cargo run -p xtask -- author-revoke \
  --primary-id alice-smith \
  --delegate-id claude-assistant
```

### Signing with Delegated Identity

```
# Delegate signs as "primary_id/delegate_id"
MCP Tool: sign_article_file
  author_id: "alice-smith/claude-assistant"
  article_path: "content/news/my-article.md"
```

### Shared Device Handling

Each user has their own `.authors/<id>/` directory. Multiple users on a shared device simply have separate author directories - no conflicts.

## Security Model

- **Bots**: Software keys stored locally (gitignored)
- **Humans**: Hardware keys (YubiKey), touch required
- **Delegates**: Subordinate keys signed by primary identity
- **Multi-device**: Same hardware key = same identity (auto-detected)
- **Board members**: Must first prove track record as author
- **All signatures**: Logged to `.mcp-audit/signing.log`

## Sources

- [Securing SSH with FIDO2](https://developers.yubico.com/SSH/Securing_SSH_with_FIDO2.html)
- [Git Commit Signing with YubiKey](https://developers.yubico.com/SSH/Securing_git_with_SSH_and_FIDO2.html)
