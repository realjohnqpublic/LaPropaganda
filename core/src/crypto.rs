//! Cryptographic operations for article signing and verification
//!
//! This module provides Ed25519 signing and SHA-256 hashing operations
//! that are shared between the CLI (xtask) and MCP server.

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Calculate SHA-256 hash of article body
///
/// The body is trimmed before hashing to avoid whitespace issues.
pub fn calculate_hash(body: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(body.trim().as_bytes());
    hasher.finalize().to_vec()
}

/// Calculate SHA-256 hash of arbitrary bytes
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Calculate editorial review hash: SHA-256(article_hash + author_signature)
///
/// This creates a unique hash for the review that chains the author's signature.
pub fn calculate_review_hash(article_hash_hex: &str, author_signature_hex: &str) -> Vec<u8> {
    let review_data = format!("{}{}", article_hash_hex, author_signature_hex);
    sha256(review_data.as_bytes())
}

// ============================================================================
// ENDORSEMENT AND CLAIM OPERATIONS
// ============================================================================

/// Calculate endorsement hash: SHA-256(body + author_signature)
///
/// This binds the endorsement to both the content AND the original author's signature,
/// preventing endorsement of modified content.
pub fn calculate_endorsement_hash(body: &str, author_signature_hex: &str) -> Vec<u8> {
    let data = format!("{}{}", body.trim(), author_signature_hex);
    sha256(data.as_bytes())
}

/// Create the consent message for authorship claims.
///
/// Format: "I authorize {human_pubkey} to claim article {article_hash}"
/// The bot signs this message to grant consent.
pub fn create_consent_message(human_pubkey_hex: &str, article_hash_hex: &str) -> String {
    format!(
        "I authorize {} to claim article {}",
        human_pubkey_hex,
        article_hash_hex
    )
}

/// Verify bot's consent signature for authorship claim.
///
/// Returns Ok(()) if the consent is valid.
pub fn verify_claim_consent(
    bot_pubkey_hex: &str,
    human_pubkey_hex: &str,
    article_hash_hex: &str,
    consent_signature_hex: &str,
) -> Result<()> {
    let expected_message = create_consent_message(human_pubkey_hex, article_hash_hex);
    verify_signature(bot_pubkey_hex, &expected_message, consent_signature_hex)
}

/// Sign a message hash with Ed25519 private key
///
/// Returns the signature as a hex string.
pub fn sign(signing_key: &SigningKey, hash_hex: &str) -> String {
    // Sign the hash hex string (consistent with xtask pattern)
    let signature = signing_key.sign(hash_hex.as_bytes());
    hex::encode(signature.to_bytes())
}

/// Verify an Ed25519 signature
///
/// All inputs are hex-encoded strings.
pub fn verify_signature(pubkey_hex: &str, message: &str, signature_hex: &str) -> Result<()> {
    let pubkey_bytes = hex::decode(pubkey_hex).context("Invalid pubkey hex")?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array).context("Invalid public key")?;

    let sig_bytes = hex::decode(signature_hex).context("Invalid signature hex")?;
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
    fn test_calculate_hash() {
        let body = "  Hello, world!  \n";
        let hash = calculate_hash(body);
        assert_eq!(hash.len(), 32); // SHA-256 produces 32 bytes

        // Verify trimming works
        let body2 = "Hello, world!";
        let hash2 = calculate_hash(body2);
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

    #[test]
    fn test_review_hash() {
        let article_hash = "abc123";
        let author_sig = "def456";
        let review_hash = calculate_review_hash(article_hash, author_sig);
        assert_eq!(review_hash.len(), 32);

        // Should be deterministic
        let review_hash2 = calculate_review_hash(article_hash, author_sig);
        assert_eq!(review_hash, review_hash2);
    }

    #[test]
    fn test_endorsement_hash() {
        let body = "Article content";
        let author_sig = "abc123def456";
        let hash = calculate_endorsement_hash(body, author_sig);
        assert_eq!(hash.len(), 32);

        // Different signature = different hash
        let hash2 = calculate_endorsement_hash(body, "different_sig");
        assert_ne!(hash, hash2);

        // Different body = different hash
        let hash3 = calculate_endorsement_hash("Different content", author_sig);
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_consent_message_format() {
        let human_pubkey = "abc123";
        let article_hash = "def456";
        let msg = create_consent_message(human_pubkey, article_hash);
        assert_eq!(msg, "I authorize abc123 to claim article def456");
    }

    #[test]
    fn test_verify_claim_consent() {
        let mut csprng = OsRng;
        let bot_key = SigningKey::generate(&mut csprng);
        let bot_pubkey = hex::encode(bot_key.verifying_key().to_bytes());

        let human_pubkey = "human123";
        let article_hash = "article456";

        // Bot creates consent
        let consent_msg = create_consent_message(human_pubkey, article_hash);
        let consent_sig = sign(&bot_key, &consent_msg);

        // Verify consent
        assert!(verify_claim_consent(&bot_pubkey, human_pubkey, article_hash, &consent_sig).is_ok());

        // Wrong human pubkey should fail
        assert!(verify_claim_consent(&bot_pubkey, "wrong_human", article_hash, &consent_sig).is_err());

        // Wrong article hash should fail
        assert!(verify_claim_consent(&bot_pubkey, human_pubkey, "wrong_hash", &consent_sig).is_err());
    }
}
