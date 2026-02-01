+++
title = "Multi-Signature Editorial Workflow Documentation"
date = 2026-02-01
template = "page.html"

[extra]
author = "Infrastructure Team"
summary = "Technical documentation for the new cryptographic publishing workflow, ensuring authenticity and editorial consensus."

# -----------------------------------------------------------------------------
# AUTHENTICITY LAYER (Author)
# -----------------------------------------------------------------------------
[extra.author_signature]
# The 'author_id' must be a valid slug (lowercase alphanumeric + hyphens)
# and correspond to a registered key in .authors/ (for verification).
author_id = "infra-team"
name = "Infrastructure Team"
# Ed25519 Public Key (Hex)
pubkey = "f9170c302aba12d374676d8a144ba58392fe3c85478d0de44420a36743ed73b6"
# Signature of the content body + some metadata
signature = "2447f5ecd311205b6ed06c1d76dad79cc3df02c3b95b0fc54f453a9a051c10fc92e43386eb05da73ffc3912533ba4f3cf25e39a7fe1f500a564d87ea94349309"
verified = true

# -----------------------------------------------------------------------------
# GOVERNANCE LAYER (Editorial Board)
# -----------------------------------------------------------------------------
[extra.editorial_approval]
required = 3
status = "approved"

# Array of board member signatures
# Each entry represents a cryptographic approval from a hardware-key-wielding member.
[[extra.editorial_signatures]]
board_member = "board-alice"
signature = "196080c1da386ef9ca780b70586abd8e452cfc9eba3a6257719e11027e766e3b1523785609eaa2f5d070414267a1aa842af4a1cda7c76f4eadb67ed9b4f37f02"
timestamp = "2026-01-31T07:07:04.255600-05:00"
decision = "approve"

[[extra.editorial_signatures]]
board_member = "board-bob"
signature = "9b467dc0ce210f49819e7cca723ed570c35ef67bbf4c538d1bef19fba672ce8e68fcdd07a0831598c4f416cb4c4ea896432ec18e45b0c2b0f8ac7fe2f3205900"
timestamp = "2026-01-31T07:07:08.742167-05:00"
decision = "approve"

[[extra.editorial_signatures]]
board_member = "board-charlie"
signature = "53a304e49c6ea37fa3b37c9efccc117222ed708b1238132b8cc0df651f55b3136f12c9fb3ad7127894602dfcdc9493c54f995ed4c22ee04782596bdf050acb0b"
timestamp = "2026-01-31T07:14:38.101127-05:00"
decision = "approve"
+++

# System Architecture

## Overview
La Propaganda uses a strictly typed, cryptographic workflow to ensure content integrity. This document demonstrates the correct FrontMatter structure required by the `xtask` toolchain.

## Key Changes for 2026

### 1. Robust TOML Structure
Previous versions relied on loose regex parsing. The new system uses the `toml` crate with strict struct mapping.
**Crucially, all security metadata is now nested under `[extra]`**:
- `[extra.author_signature]`
- `[extra.editorial_approval]`
- `[[extra.editorial_signatures]]` (Array)

### 2. Strict ID Validation
IDs for authors and board members must be slugs (only `a-z`, `0-9`, `-`). Path traversal attempts (like `../`) are rejected at the CLI level.

### 3. Hardware Key Enforcement
Editorial reviews now strictly require exact key ID matching. The `contains()` vulnerability has been patched.

### 4. Proof Mode Safety
Unsigned content checks (`--skip-sign`) are now gated behind the `LAPROPAGANDA_PROOF_MODE` environment variable to prevent accidental deployment of unverified news.

## CLI Commands

To participate in this workflow:

1.  **Drafting**: `cargo run -p xtask -- draft "My Story"`
2.  **Author Signing**: `cargo run -p xtask -- author-sign content/news/...`
3.  **Editorial Review**: `cargo run -p xtask -- review content/news/... <board-id> approve`
4.  **Verification**: `cargo run -p xtask -- verify`

This page itself serves as a structural test case for the validity of the new schema.
