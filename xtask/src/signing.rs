//! Cryptographic signing operations
//!
//! This module handles:
//! - Editorial board key generation
//! - Global content signing
//! - Signature verification

use anyhow::{Context, Result};
use console::style;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::Path;

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


