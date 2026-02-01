//! La Propaganda Core - Shared cryptographic and identity utilities
//!
//! This crate provides common functionality used by both the xtask CLI
//! and the MCP signing server.

pub mod crypto;
pub mod identity;

pub use crypto::{
    calculate_endorsement_hash, calculate_hash, calculate_review_hash,
    create_consent_message, sha256, sign, verify_claim_consent, verify_signature,
};
pub use identity::{derive_id_from_pubkey, is_valid_slug, validate_slug};
