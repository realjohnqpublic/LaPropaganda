//! Author key generation and article signing
//!
//! This module handles:
//! - Author keypair generation
//! - Article signing
//! - Author signature verification

use anyhow::{bail, Context, Result};
use chrono::Local;
use console::style;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use regex::Regex;
use std::path::Path;

use crate::config::{load_config, validate_slug};
use crate::content::{calculate_hash, parse_file};
use crate::types::{AuthorSignature, EditorialApproval};

/// Generate Ed25519 keypair for an author
pub fn author_keygen(name: String, id: String, email: Option<String>) -> Result<()> {
    println!("{}", style(format!("Generating Ed25519 keypair for author: {}", name)).cyan().bold());

    // Validate ID format (slug)
    validate_slug(&id).context("Invalid author ID")?;

    // Create .authors/<id> directory
    let key_dir = Path::new(".authors").join(&id);
    if key_dir.exists() {
        bail!("Author {} already exists at {:?}", id, key_dir);
    }
    std::fs::create_dir_all(&key_dir).context("Failed to create author key directory")?;

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

    // Save author metadata
    let metadata = format!(
        "# Author: {}\n# ID: {}\n# Email: {}\n# Public Key: {}\n# Generated: {}\n",
        name,
        id,
        email.as_deref().unwrap_or("N/A"),
        public_key_hex,
        Local::now().format("%Y-%m-%d %H:%M:%S")
    );
    let metadata_path = key_dir.join("author.info");
    std::fs::write(&metadata_path, &metadata)
        .context("Failed to write author metadata")?;

    println!("{}", style("Author keypair generated successfully!").green().bold());
    println!();
    println!("{}", style("Private key saved to:").yellow());
    println!("   {}", style(private_key_path.display()).cyan());
    println!("   {}", style("KEEP THIS SECRET! Never commit to git.").red().bold());
    println!();
    println!("{}", style("Public key:").yellow());
    println!("   {}", style(&public_key_hex).cyan());
    println!();
    println!("{}", style("Next steps:").yellow().bold());
    println!("1. Use this public key when signing articles");
    println!("2. Sign articles with:");
    println!("   {}", style("cargo run -p xtask -- author-sign <article.md>").cyan());

    Ok(())
}

/// Load author private key from filesystem
pub fn load_author_private_key(author_id: &str) -> Result<SigningKey> {
    // Validate ID to prevent path traversal when loading key
    validate_slug(author_id).context("Invalid author ID")?;

    let key_path = Path::new(".authors").join(author_id).join("private_key.secret");
    if !key_path.exists() {
        bail!(
            "Author key not found for '{}'. Generate with: cargo run -p xtask -- author-keygen --name \"Name\" --id {}",
            author_id,
            author_id
        );
    }

    let key_hex = std::fs::read_to_string(&key_path)
        .context("Failed to read author private key")?;
    let key_bytes = hex::decode(key_hex.trim())
        .context("Failed to decode author private key")?;
    let key_array: [u8; 32] = key_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Author private key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&key_array))
}

/// Load author metadata
fn load_author_metadata(author_id: &str) -> Result<(String, Option<String>, String)> {
    validate_slug(author_id).context("Invalid author ID")?;

    let author_info_path = Path::new(".authors").join(author_id).join("author.info");
    let author_info = std::fs::read_to_string(&author_info_path)
        .context("Failed to read author metadata. Run author-keygen first.")?;

    // Extract name and email from metadata
    let name_re = Regex::new(r"# Author: (.+)")?;
    let email_re = Regex::new(r"# Email: (.+)")?;
    let pubkey_re = Regex::new(r"# Public Key: (.+)")?;

    let author_name = name_re.captures(&author_info)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let author_email = email_re.captures(&author_info)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .filter(|s| *s != "N/A")
        .map(|s| s.to_string());

    let author_pubkey = pubkey_re.captures(&author_info)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| anyhow::anyhow!("Could not find public key in author metadata"))?;

    Ok((author_name, author_email, author_pubkey))
}

/// Sign article as author
///
/// If `author_id_arg` is provided, uses that ID without prompting.
/// Otherwise, prompts interactively for the author ID.
pub fn author_sign(article_path: &Path, author_id_arg: Option<String>) -> Result<()> {
    println!("{}", style(format!("Signing article: {}", article_path.display())).cyan().bold());

    // Parse article
    let (_full_text, mut frontmatter, body) = parse_file(article_path)?;

    // Check if already has author signature
    if frontmatter.extra.author_signature.is_some() {
        bail!("Article already has author signature. Remove [extra.author_signature] section first to re-sign.");
    }

    // Get author ID (required for automation/bot compatibility)
    let author_id = match author_id_arg {
        Some(id) => {
            validate_slug(&id).context("Invalid author ID")?;
            id
        }
        None => {
            bail!(
                "Author ID is required. Use --author-id <id> to specify.\n\
                 Available authors can be found in .authors/ directory."
            );
        }
    };

    // Load author metadata
    let (author_name, author_email, author_pubkey) = load_author_metadata(&author_id)?;

    // Calculate article hash
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    // Load author private key and sign
    let signing_key = load_author_private_key(&author_id)?;
    let signature = signing_key.sign(hash_hex.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    println!("{}", style(format!("Signed as: {}", author_name)).green());

    // Update frontmatter struct
    frontmatter.extra.author_signature = Some(AuthorSignature {
        name: author_name.clone(),
        email: author_email,
        pubkey: author_pubkey,
        signature: signature_hex.clone(),
    });

    // Read threshold from config.toml (not hardcoded!)
    let config = load_config(std::path::Path::new("config.toml"))?;
    let threshold = config.extra.editorial_board
        .as_ref()
        .and_then(|b| b.threshold)
        .unwrap_or(3);

    // Add editorial approval section (status: pending)
    frontmatter.extra.editorial_approval = Some(EditorialApproval {
        required: threshold,
        status: "pending".to_string(),
    });

    // Write updated article
    let new_frontmatter_str = toml::to_string(&frontmatter)?;
    let new_content = format!("+++{}+++{}", new_frontmatter_str, body);
    std::fs::write(article_path, new_content)?;

    println!("{}", style("Article signed successfully!").green().bold());
    println!();
    println!("{}", style("Article hash:").yellow());
    println!("   {}...", style(&hash_hex[..32]).cyan());
    println!("{}", style("Author signature:").yellow());
    println!("   {}...", style(&signature_hex[..32]).cyan());
    println!();
    println!("{}", style("Next steps:").yellow().bold());
    println!("1. Submit article for editorial review");
    println!("2. Editorial board members review with:");
    println!("   {}", style("cargo run -p xtask -- editorial-review <article.md> --approve").cyan());

    Ok(())
}

/// Verify author signature on article
pub fn verify_author(article_path: &Path) -> Result<()> {
    println!("{}", style(format!("Verifying author signature: {}", article_path.display())).cyan().bold());

    let (_, frontmatter, body) = parse_file(article_path)?;

    // Extract author section
    let sig_data = frontmatter.extra.author_signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No author signature found in article"))?;

    let author_pubkey = &sig_data.pubkey;
    let author_signature = &sig_data.signature;

    // Calculate article hash
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    // Verify signature
    let pubkey_bytes = hex::decode(author_pubkey)
        .context("Failed to decode author public key")?;
    let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Author public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .context("Invalid author public key")?;

    let sig_bytes = hex::decode(author_signature)
        .context("Failed to decode author signature")?;
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Author signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key.verify(hash_hex.as_bytes(), &signature)
        .context("Author signature verification failed - article has been modified")?;

    println!("{}", style("Author signature VALID").green().bold());
    println!();
    println!("{}", style("Author public key:").yellow());
    println!("   {}...", style(&author_pubkey[..32]).cyan());
    println!();
    println!("{}", style("Article hash:").yellow());
    println!("   {}...", style(&hash_hex[..32]).cyan());

    Ok(())
}
