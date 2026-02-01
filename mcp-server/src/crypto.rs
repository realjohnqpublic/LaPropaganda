//! Cryptographic operations for MCP signing server
//!
//! This module re-exports the shared cryptographic functions from la_propaganda_core
//! and provides any MCP-specific helpers.

// Re-export all crypto functions from core
pub use la_propaganda_core::{
    calculate_hash as calculate_article_hash,
    calculate_review_hash,
    sha256,
    sign,
    verify_signature,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_calculate_article_hash() {
        let body = "  Hello, world!  \n";
        let hash = calculate_article_hash(body);
        assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes

        // Verify trimming works
        let body2 = "Hello, world!";
        let hash2 = calculate_article_hash(body2);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sign_and_verify() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let message = "test message hash";
        let signature = sign(&signing_key, message);

        let pubkey_hex = hex::encode(verifying_key.to_bytes());

        assert!(verify_signature(&pubkey_hex, message, &signature).is_ok());
    }
}
