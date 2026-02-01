//! Cryptographic signing operations
//!
//! This module handles:
//! - Editorial board key generation
//! - Global content signing
//! - Signature verification

use anyhow::{bail, Context, Result};
use console::style;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::path::Path;

use crate::content::calculate_global_hash;
use crate::types::Config;

/// Generate Ed25519 keypair for editorial board signing
pub fn generate_key() -> Result<()> {
    println!("{}", style("Generating Ed25519 keypair...").cyan().bold());

    // Create .editorial_board directory if it doesn't exist
    let key_dir = Path::new(".editorial_board");
    std::fs::create_dir_all(key_dir).context("Failed to create .editorial_board directory")?;

    // Generate keypair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Encode keys as hex
    let private_key_hex = hex::encode(signing_key.to_bytes());
    let public_key_hex = hex::encode(verifying_key.to_bytes());

    // Save private key to file
    let private_key_path = key_dir.join("private_key.secret");
    std::fs::write(&private_key_path, &private_key_hex)
        .context("Failed to write private key")?;

    // Update config.toml with public key using proper TOML updates
    let config_path = Path::new("config.toml");
    crate::config::update_config_field(config_path, "extra", "public_key", &public_key_hex)?;

    println!("{}", style("Keypair generated successfully!").green().bold());
    println!();
    println!("{}", style("Private key saved to:").yellow());
    println!("   {}", style(private_key_path.display()).cyan());
    println!("   {}", style("KEEP THIS SECRET! Never commit to git.").red().bold());
    println!();
    println!("{}", style("Public key added to config.toml:").yellow());
    println!("   {}...", style(&public_key_hex[..32]).cyan());
    println!();
    println!("{}", style("Next steps:").yellow().bold());
    println!("1. Add private key to GitHub Secrets:");
    println!("   {}", style("gh secret set EDITORIAL_BOARD_PRIVATE_KEY < .editorial_board/private_key.secret").cyan());
    println!("2. Commit public key:");
    println!("   {}", style("git add config.toml && git commit -m 'feat: Add public key for signature verification'").cyan());

    Ok(())
}

/// Load editorial board private key
pub fn load_private_key() -> Result<SigningKey> {
    // Try loading from environment variable first (CI)
    if let Ok(key_hex) = std::env::var("EDITORIAL_BOARD_PRIVATE_KEY") {
        let key_bytes = hex::decode(key_hex.trim())
            .context("Failed to decode private key from environment variable")?;
        let key_array: [u8; 32] = key_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Private key must be 32 bytes"))?;
        return Ok(SigningKey::from_bytes(&key_array));
    }

    // Try loading from file (local dev)
    let key_path = Path::new(".editorial_board/private_key.secret");
    if key_path.exists() {
        let key_hex = std::fs::read_to_string(key_path)
            .context("Failed to read private key file")?;
        let key_bytes = hex::decode(key_hex.trim())
            .context("Failed to decode private key from file")?;
        let key_array: [u8; 32] = key_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Private key must be 32 bytes"))?;
        return Ok(SigningKey::from_bytes(&key_array));
    }

    bail!("No signing key found. Run: cargo run -p xtask -- generate-key")
}

/// Sign the global content hash
pub fn sign_global_hash(hash_hex: &str) -> Result<String> {
    let signing_key = load_private_key()?;

    // Sign the hash hex string
    let signature = signing_key.sign(hash_hex.as_bytes());

    // Return signature as hex
    Ok(hex::encode(signature.to_bytes()))
}

/// Verify cryptographic signature of site content
pub fn verify_signature() -> Result<()> {
    println!("{}", style("Verifying cryptographic signature...").cyan().bold());

    // Step 1: Calculate current global hash
    let (calculated_hash, _) = calculate_global_hash()?;

    // Step 2: Load config.toml
    let config_path = Path::new("config.toml");
    let config_str = std::fs::read_to_string(config_path)
        .context("Failed to read config.toml")?;

    let config: Config = toml::from_str(&config_str)
        .context("Failed to parse config.toml")?;

    // Step 3: Extract public key
    let public_key_hex = config.extra.public_key
        .ok_or_else(|| anyhow::anyhow!("No public_key found in config.toml. Run: cargo run -p xtask -- generate-key"))?;

    // Step 4: Extract signature
    let signature_hex = config.extra.site_signature
        .ok_or_else(|| anyhow::anyhow!("No site_signature found in config.toml. Run: cargo run -p xtask -- hash"))?;

    // Step 5: Decode keys and signature
    let public_key_bytes = hex::decode(&public_key_hex)
        .context("Failed to decode public key")?;
    let public_key_array: [u8; 32] = public_key_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .context("Invalid public key")?;

    let signature_bytes = hex::decode(&signature_hex)
        .context("Failed to decode signature")?;
    let signature_array: [u8; 64] = signature_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_array);

    // Step 6: Verify signature
    verifying_key.verify(calculated_hash.as_bytes(), &signature)
        .context("Signature verification failed - content has been tampered or signed with different key")?;

    println!("{}", style("Signature VALID - Content signed by editorial board").green().bold());
    println!();
    println!("{}", style("Public key:").yellow());
    println!("   {}...", style(&public_key_hex[..32]).cyan());
    println!();
    println!("{}", style("Site hash:").yellow());
    println!("   {}...", style(&calculated_hash[..32]).cyan());
    println!();
    println!("{}", style("Content authenticity verified!").green().bold());

    Ok(())
}

/// Verify the site-wide signature (used in CI verification)
pub fn verify_site_signature() -> Result<()> {
    println!("{}", style("Verifying SITE-WIDE signature...").cyan());

    let config_path = Path::new("config.toml");
    let config_str = std::fs::read_to_string(config_path)
        .context("Failed to read config.toml")?;
    let config: Config = toml::from_str(&config_str)
        .context("Failed to parse config.toml")?;

    let pubkey_hex = config.extra.public_key
        .ok_or_else(|| anyhow::anyhow!("No site public key found in config.toml"))?;

    let signature_hex = config.extra.site_signature
        .ok_or_else(|| anyhow::anyhow!("No site signature found in config.toml"))?;

    let integrity_hash = config.extra.site_integrity
        .ok_or_else(|| anyhow::anyhow!("No site integrity hash found in config.toml"))?;

    // Verify
    let pubkey_bytes = hex::decode(&pubkey_hex)?;
    let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid site public key length"))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)?;

    let sig_bytes = hex::decode(&signature_hex)?;
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid site signature length"))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key.verify(integrity_hash.as_bytes(), &signature)
        .context("Site signature verification FAILED")?;

    println!("{}", style("Site signature VALID").green().bold());
    Ok(())
}
