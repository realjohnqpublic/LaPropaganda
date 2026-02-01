//! Cryptographic operations for MCP signing server
//!
//! This module provides Ed25519 signing and SHA-256 hashing operations
//! that are compatible with the xtask implementation.

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Calculate SHA-256 hash of article body (matches xtask/src/main.rs:461-464)
pub fn calculate_article_hash(body: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(body.trim().as_bytes()); // Trim to avoid whitespace issues
    hasher.finalize().to_vec()
}

/// Calculate SHA-256 hash of arbitrary data
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Calculate editorial review hash: SHA-256(article_hash + author_signature)
/// Matches xtask/src/main.rs editorial_review() logic
pub fn calculate_review_hash(article_hash_hex: &str, author_signature_hex: &str) -> Vec<u8> {
    let review_data = format!("{}{}", article_hash_hex, author_signature_hex);
    sha256(review_data.as_bytes())
}

/// Sign a message hash with Ed25519 private key
/// Returns signature as hex string
pub fn sign(signing_key: &SigningKey, hash_hex: &str) -> String {
    // Sign the hash hex string (matches xtask pattern)
    let signature = signing_key.sign(hash_hex.as_bytes());
    hex::encode(signature.to_bytes())
}

/// Verify an Ed25519 signature
pub fn verify_signature(pubkey_hex: &str, message: &str, signature_hex: &str) -> Result<()> {
    let pubkey_bytes = hex::decode(pubkey_hex)
        .context("Failed to decode public key hex")?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .context("Invalid public key")?;

    let sig_bytes = hex::decode(signature_hex)
        .context("Failed to decode signature hex")?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify(message.as_bytes(), &signature)
        .context("Signature verification failed")?;

    Ok(())
}

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
