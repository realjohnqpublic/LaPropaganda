//! Identity utilities for author and board member management
//!
//! This module provides functions for deriving deterministic IDs from
//! public keys and validating slug formats.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

/// Derive a deterministic ID from pubkey hash
///
/// Returns first 12 hex characters (6 bytes) of SHA-256(pubkey_hex).
/// This provides ~48 bits of entropy, making collisions extremely unlikely
/// (probability ~1 in 280 trillion).
///
/// The same pubkey always produces the same ID, enabling identity
/// portability across devices.
pub fn derive_id_from_pubkey(pubkey_hex: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey_hex.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..6]) // 12 hex chars = 6 bytes
}

/// Validate slug format for IDs
///
/// Valid slugs:
/// - 2-50 characters long
/// - Start with lowercase letter
/// - Contain only lowercase letters, numbers, and hyphens
/// - Do not end with hyphen
///
/// Returns `Ok(())` if valid, `Err` with description if invalid.
pub fn validate_slug(slug: &str) -> Result<()> {
    if slug.len() < 2 || slug.len() > 50 {
        bail!("Slug must be 2-50 characters, got {}", slug.len());
    }

    let mut chars = slug.chars();
    if !chars
        .next()
        .map(|c| c.is_ascii_lowercase())
        .unwrap_or(false)
    {
        bail!("Slug must start with lowercase letter");
    }

    for c in chars {
        if !c.is_ascii_lowercase() && !c.is_ascii_digit() && c != '-' {
            bail!(
                "Slug can only contain lowercase letters, numbers, hyphens. Found: '{}'",
                c
            );
        }
    }

    if slug.ends_with('-') {
        bail!("Slug cannot end with hyphen");
    }

    Ok(())
}

/// Boolean version of validate_slug for quick checks
pub fn is_valid_slug(slug: &str) -> bool {
    validate_slug(slug).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_id_from_pubkey() {
        let pubkey = "abc123def456";
        let id = derive_id_from_pubkey(pubkey);
        assert_eq!(id.len(), 12); // 6 bytes = 12 hex chars

        // Should be deterministic
        let id2 = derive_id_from_pubkey(pubkey);
        assert_eq!(id, id2);

        // Different pubkey = different ID
        let id3 = derive_id_from_pubkey("different");
        assert_ne!(id, id3);
    }

    #[test]
    fn test_validate_slug() {
        // Valid slugs
        assert!(validate_slug("ab").is_ok());
        assert!(validate_slug("alice-smith").is_ok());
        assert!(validate_slug("claude-opus-4").is_ok());
        assert!(validate_slug("a1b2c3").is_ok());

        // Invalid: too short
        assert!(validate_slug("a").is_err());

        // Invalid: starts with number
        assert!(validate_slug("1abc").is_err());

        // Invalid: starts with hyphen
        assert!(validate_slug("-abc").is_err());

        // Invalid: ends with hyphen
        assert!(validate_slug("abc-").is_err());

        // Invalid: uppercase
        assert!(validate_slug("Alice").is_err());

        // Invalid: underscore
        assert!(validate_slug("alice_smith").is_err());

        // Invalid: space
        assert!(validate_slug("alice smith").is_err());
    }

    #[test]
    fn test_is_valid_slug() {
        assert!(is_valid_slug("valid-slug"));
        assert!(!is_valid_slug("Invalid"));
    }
}
