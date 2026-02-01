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
use la_propaganda_core::{
    calculate_endorsement_hash, create_consent_message, derive_id_from_pubkey,
    verify_claim_consent,
};
use rand::rngs::OsRng;
use regex::Regex;
use std::path::Path;

use crate::config::{load_config, validate_slug};
use crate::content::{calculate_hash, parse_file};
use crate::types::{AuthorSignature, AuthorshipClaim, EditorialApproval, EndorsementSignature};

// derive_id_from_pubkey is now imported from la_propaganda_core

/// Generate Ed25519 keypair for an author
///
/// If `import_pubkey` is provided, imports an existing public key (from hardware key)
/// instead of generating a new keypair. If `hardware_key` is true, marks the author
/// as using hardware key signing (no software private key stored).
pub fn author_keygen(
    name: String,
    id: String,
    email: Option<String>,
    import_pubkey: Option<String>,
    hardware_key: bool,
) -> Result<()> {
    // Validate ID format (slug)
    validate_slug(&id).context("Invalid author ID")?;

    // Create .authors/<id> directory
    let key_dir = Path::new(".authors").join(&id);
    if key_dir.exists() {
        bail!("Author {} already exists at {:?}", id, key_dir);
    }
    std::fs::create_dir_all(&key_dir).context("Failed to create author key directory")?;

    let (public_key_hex, has_software_key) = if let Some(pubkey) = import_pubkey {
        // Import existing public key (from hardware key)
        println!("{}", style(format!("Importing public key for author: {}", name)).cyan().bold());

        // Validate pubkey format
        let pubkey_bytes = hex::decode(&pubkey)
            .context("Public key must be valid hex")?;
        if pubkey_bytes.len() != 32 {
            bail!("Public key must be 32 bytes (64 hex characters)");
        }

        (pubkey, false)
    } else {
        // Generate new keypair
        println!("{}", style(format!("Generating Ed25519 keypair for author: {}", name)).cyan().bold());

        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let private_key_hex = hex::encode(signing_key.to_bytes());
        let public_key_hex = hex::encode(verifying_key.to_bytes());

        // Save private key to file
        let private_key_path = key_dir.join("private_key.secret");
        std::fs::write(&private_key_path, &private_key_hex)
            .context("Failed to write private key")?;

        println!("{}", style("Private key saved to:").yellow());
        println!("   {}", style(private_key_path.display()).cyan());
        println!("   {}", style("KEEP THIS SECRET! Never commit to git.").red().bold());

        (public_key_hex, true)
    };

    // Determine author type
    let author_type = if hardware_key { "human" } else { "ai_agent" };
    let key_storage = if has_software_key { "software" } else { "hardware" };

    // Save author metadata
    let metadata = format!(
        "# Author: {}\n# ID: {}\n# Email: {}\n# Public Key: {}\n# Generated: {}\n# Type: {}\n# Key Storage: {}\n",
        name,
        id,
        email.as_deref().unwrap_or("N/A"),
        public_key_hex,
        Local::now().format("%Y-%m-%d %H:%M:%S"),
        author_type,
        key_storage,
    );
    let metadata_path = key_dir.join("author.info");
    std::fs::write(&metadata_path, &metadata)
        .context("Failed to write author metadata")?;

    println!();
    println!("{}", style("Author registered successfully!").green().bold());
    println!();
    println!("{}", style("Public key:").yellow());
    println!("   {}", style(&public_key_hex).cyan());
    println!();
    println!("{}", style("Author type:").yellow());
    println!("   {} ({})", style(author_type).cyan(), key_storage);
    println!();
    println!("{}", style("Next steps:").yellow().bold());
    if hardware_key {
        println!("1. Hardware key registered (public key imported)");
        println!("2. Sign via MCP server (will prompt for YubiKey touch)");
        println!("   Verify key loaded: ssh-add -L");
    } else {
        println!("1. Sign articles with:");
        println!("   {}", style(format!("cargo run -p xtask -- author-sign <article.md> --author-id {}", id)).cyan());
    }

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

    // Derive consistent author_id from pubkey (same ID on any device)
    let derived_author_id = derive_id_from_pubkey(&author_pubkey);

    // Update frontmatter struct
    frontmatter.extra.author_signature = Some(AuthorSignature {
        author_id: derived_author_id,
        name: author_name.clone(),
        email: author_email,
        pubkey: author_pubkey,
        signature: signature_hex.clone(),
        verified: false, // Default unverified; verify by posting pubkey on social media
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

/// Delegate signing authority to another device or bot
pub fn author_delegate(
    primary_id: String,
    name: String,
    delegate_id: String,
    delegate_type: String,
    expires: Option<String>,
) -> Result<()> {
    println!("{}", style("DELEGATE SIGNING AUTHORITY").cyan().bold());
    println!();

    // Validate IDs
    validate_slug(&primary_id).context("Invalid primary author ID")?;
    validate_slug(&delegate_id).context("Invalid delegate ID")?;

    // Validate delegate type
    if delegate_type != "device" && delegate_type != "bot" {
        bail!("Delegate type must be 'device' or 'bot'");
    }

    // Check primary exists
    let primary_dir = Path::new(".authors").join(&primary_id);
    if !primary_dir.exists() {
        bail!("Primary author '{}' not found. Create with: cargo run -p xtask -- author-keygen --name \"Name\" --id {}", primary_id, primary_id);
    }

    // Read primary's public key
    let author_info_path = primary_dir.join("author.info");
    let author_info = std::fs::read_to_string(&author_info_path)
        .context("Failed to read primary author.info")?;

    let pubkey_re = Regex::new(r"# Public Key: (.+)")?;
    let primary_pubkey = pubkey_re.captures(&author_info)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| anyhow::anyhow!("Could not find public key in author.info"))?;

    // Create delegates directory
    let delegates_dir = primary_dir.join("delegates");
    let delegate_dir = delegates_dir.join(&delegate_id);

    if delegate_dir.exists() {
        bail!("Delegate '{}' already exists for primary '{}'", delegate_id, primary_id);
    }

    std::fs::create_dir_all(&delegate_dir)
        .context("Failed to create delegate directory")?;

    // Generate Ed25519 keypair for delegate
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let private_key_hex = hex::encode(signing_key.to_bytes());
    let delegate_pubkey = hex::encode(verifying_key.to_bytes());

    // Save private key
    let key_path = delegate_dir.join("private_key.secret");
    std::fs::write(&key_path, &private_key_hex)
        .context("Failed to write delegate private key")?;

    let timestamp = Local::now().format("%Y-%m-%dT%H:%M:%S%z").to_string();

    // Create delegation certificate
    let expires_toml = expires.as_ref()
        .map(|e| format!("\"{}\"", e))
        .unwrap_or_else(|| "false".to_string());

    let cert_content = format!(
        r#"# Delegation Certificate
# Signed by primary identity: {}

[delegation]
delegate_id = "{}"
delegate_pubkey = "{}"
delegate_type = "{}"
primary_id = "{}"
primary_pubkey = "{}"
created = "{}"
expires = {}
active = true
"#,
        primary_id,
        delegate_id,
        delegate_pubkey,
        delegate_type,
        primary_id,
        primary_pubkey,
        timestamp,
        expires_toml
    );

    let cert_path = delegate_dir.join("delegation.cert");
    std::fs::write(&cert_path, &cert_content)
        .context("Failed to write delegation certificate")?;

    // Save delegate metadata
    let delegate_info = format!(
        "# Delegate: {}\n# ID: {}\n# Type: {}\n# Primary: {}\n# Public Key: {}\n# Created: {}\n",
        name,
        delegate_id,
        delegate_type,
        primary_id,
        delegate_pubkey,
        timestamp
    );
    let info_path = delegate_dir.join("delegate.info");
    std::fs::write(&info_path, &delegate_info)
        .context("Failed to write delegate info")?;

    println!("{}", style("Delegation created successfully!").green().bold());
    println!();
    println!("{}", style("Primary:").yellow());
    println!("   {} ({})", style(&primary_id).cyan(), &primary_pubkey[..16]);
    println!();
    println!("{}", style("Delegate:").yellow());
    println!("   Name: {}", style(&name).cyan());
    println!("   ID:   {}/{}", style(&primary_id).dim(), style(&delegate_id).cyan());
    println!("   Type: {}", style(&delegate_type).cyan());
    println!("   Pubkey: {}...", style(&delegate_pubkey[..32]).cyan());
    if let Some(exp) = &expires {
        println!("   Expires: {}", style(exp).yellow());
    }
    println!();
    println!("{}", style("Private key saved to:").yellow());
    println!("   {}", style(key_path.display()).cyan());
    println!("   {}", style("KEEP THIS SECRET! Never commit to git.").red().bold());
    println!();
    println!("{}", style("Use with MCP:").yellow());
    println!("   Sign as: {}/{}", primary_id, delegate_id);

    Ok(())
}

/// List all delegated identities for an author
pub fn author_list_delegates(primary_id: &str) -> Result<()> {
    println!("{}", style(format!("DELEGATIONS FOR: {}", primary_id)).cyan().bold());
    println!();

    validate_slug(primary_id).context("Invalid author ID")?;

    let delegates_dir = Path::new(".authors").join(primary_id).join("delegates");

    if !delegates_dir.exists() {
        println!("{}", style("No delegations found.").dim());
        println!();
        println!("Create a delegation with:");
        println!("   {}", style(format!("cargo run -p xtask -- author-delegate --primary-id {} --name \"Name\" --id delegate-id --delegate-type bot", primary_id)).cyan());
        return Ok(());
    }

    let mut found = false;
    for entry in std::fs::read_dir(&delegates_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            found = true;
            let delegate_id = entry.file_name().to_string_lossy().to_string();
            let info_path = entry.path().join("delegate.info");
            let cert_path = entry.path().join("delegation.cert");

            let mut name = delegate_id.clone();
            let mut delegate_type = "unknown".to_string();
            let mut pubkey = String::new();
            let mut created = String::new();
            let mut active = true;

            // Parse delegate.info
            if info_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&info_path) {
                    for line in content.lines() {
                        if let Some(n) = line.strip_prefix("# Delegate:") {
                            name = n.trim().to_string();
                        }
                        if let Some(t) = line.strip_prefix("# Type:") {
                            delegate_type = t.trim().to_string();
                        }
                        if let Some(p) = line.strip_prefix("# Public Key:") {
                            pubkey = p.trim().to_string();
                        }
                        if let Some(c) = line.strip_prefix("# Created:") {
                            created = c.trim().to_string();
                        }
                    }
                }
            }

            // Check active status from cert
            if cert_path.exists() {
                if let Ok(content) = std::fs::read_to_string(&cert_path) {
                    active = !content.contains("active = false");
                }
            }

            // Check if private key exists (revoked keys are renamed)
            let has_key = entry.path().join("private_key.secret").exists();

            let status = if !active || !has_key {
                style("REVOKED").red().bold()
            } else {
                style("ACTIVE").green().bold()
            };

            println!("  {} [{}] {}",
                style(&delegate_id).cyan().bold(),
                style(&delegate_type).dim(),
                status
            );
            println!("    Name: {}", name);
            println!("    Full ID: {}/{}", primary_id, delegate_id);
            if !pubkey.is_empty() {
                println!("    Pubkey: {}...", &pubkey[..std::cmp::min(32, pubkey.len())]);
            }
            if !created.is_empty() {
                println!("    Created: {}", created);
            }
            println!();
        }
    }

    if !found {
        println!("{}", style("No delegations found.").dim());
    }

    Ok(())
}

/// Revoke a delegation
pub fn author_revoke(primary_id: &str, delegate_id: &str) -> Result<()> {
    println!("{}", style("REVOKE DELEGATION").cyan().bold());
    println!();

    validate_slug(primary_id).context("Invalid primary author ID")?;
    validate_slug(delegate_id).context("Invalid delegate ID")?;

    let delegate_dir = Path::new(".authors")
        .join(primary_id)
        .join("delegates")
        .join(delegate_id);

    if !delegate_dir.exists() {
        bail!("Delegation '{}/{}' not found", primary_id, delegate_id);
    }

    // Update delegation certificate to mark as inactive
    let cert_path = delegate_dir.join("delegation.cert");
    if cert_path.exists() {
        let content = std::fs::read_to_string(&cert_path)?;
        let updated = content.replace("active = true", "active = false");
        std::fs::write(&cert_path, updated)?;
    }

    // Rename private key to prevent signing
    let key_path = delegate_dir.join("private_key.secret");
    if key_path.exists() {
        let revoked_path = delegate_dir.join("private_key.revoked");
        std::fs::rename(&key_path, &revoked_path)
            .context("Failed to revoke private key")?;
    }

    println!("{}", style("Delegation revoked successfully!").green().bold());
    println!();
    println!("Delegate '{}/{}' can no longer sign articles.",
        style(primary_id).dim(),
        style(delegate_id).red()
    );
    println!();
    println!("{}", style("Note:").yellow());
    println!("   The delegation record is kept for audit purposes.");
    println!("   Private key has been renamed to private_key.revoked.");

    Ok(())
}

// ============================================================================
// ENDORSEMENT AND CLAIM FUNCTIONS
// ============================================================================

/// Endorse an article as a human vouching for Bot-authored content
pub fn endorse_article(article_path: &Path, endorser_id: &str) -> Result<()> {
    println!("{}", style("ENDORSE ARTICLE").cyan().bold());
    println!();

    validate_slug(endorser_id).context("Invalid endorser ID")?;

    // Parse article
    let (_full_text, mut frontmatter, body) = parse_file(article_path)?;

    // Check author signature exists
    let author_sig = frontmatter.extra.author_signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Article must have author signature before endorsement"))?
        .clone();

    // Check for duplicate endorsement
    if let Some(ref endorsements) = frontmatter.extra.endorsements {
        if endorsements.iter().any(|e| e.endorser_id == endorser_id || e.name == endorser_id) {
            bail!("'{}' has already endorsed this article", endorser_id);
        }
    }

    // Load endorser metadata and private key
    let (endorser_name, _, endorser_pubkey) = load_author_metadata(endorser_id)?;
    let signing_key = load_author_private_key(endorser_id)?;

    // Calculate endorsement hash using core function
    let endorsement_hash = calculate_endorsement_hash(&body, &author_sig.signature);
    let hash_hex = hex::encode(&endorsement_hash);

    // Sign
    let signature = signing_key.sign(hash_hex.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    let timestamp = chrono::Utc::now().to_rfc3339();

    // Derive consistent endorser_id from pubkey
    let derived_endorser_id = derive_id_from_pubkey(&endorser_pubkey);

    // Add endorsement
    if frontmatter.extra.endorsements.is_none() {
        frontmatter.extra.endorsements = Some(Vec::new());
    }
    if let Some(ref mut endorsements) = frontmatter.extra.endorsements {
        endorsements.push(EndorsementSignature {
            endorser_id: derived_endorser_id,
            name: endorser_name.clone(),
            pubkey: endorser_pubkey.clone(),
            signature: signature_hex.clone(),
            timestamp: timestamp.clone(),
        });
    }

    let total = frontmatter.extra.endorsements.as_ref().map(|e| e.len()).unwrap_or(0);

    // Write updated article
    let new_frontmatter_str = toml::to_string(&frontmatter)?;
    let new_content = format!("+++{}+++{}", new_frontmatter_str, body);
    std::fs::write(article_path, new_content)?;

    println!("{}", style("Endorsement added!").green().bold());
    println!();
    println!("  Endorser: {} ({})", style(&endorser_name).cyan(), &endorser_pubkey[..16]);
    println!("  Hash:     {}...", style(&hash_hex[..32]).dim());
    println!("  Total endorsements: {}", style(total).cyan().bold());

    Ok(())
}

/// Grant consent for a human to claim authorship (Bot must run this)
pub fn grant_claim_consent(article_path: &Path, bot_id: &str, human_pubkey: &str) -> Result<()> {
    println!("{}", style("GRANT CLAIM CONSENT").cyan().bold());
    println!();

    validate_slug(bot_id).context("Invalid bot author ID")?;

    // Parse article
    let (_full_text, frontmatter, body) = parse_file(article_path)?;

    // Verify bot is the author
    let author_sig = frontmatter.extra.author_signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Article has no author signature"))?;

    // Load bot's private key
    let signing_key = load_author_private_key(bot_id)?;
    let bot_pubkey = hex::encode(signing_key.verifying_key().to_bytes());

    // Verify the bot's pubkey matches the article's author
    if bot_pubkey != author_sig.pubkey {
        bail!(
            "Bot '{}' pubkey does not match article author pubkey. Only the original signer can grant claim consent.",
            bot_id
        );
    }

    // Calculate article hash
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    // Create consent message using core format
    let consent_message = create_consent_message(human_pubkey, &hash_hex);

    // Sign the consent message
    let signature = signing_key.sign(consent_message.as_bytes());
    let consent_signature = hex::encode(signature.to_bytes());

    println!("{}", style("Consent granted!").green().bold());
    println!();
    println!("  Bot ID:     {}", style(bot_id).cyan());
    println!("  Article:    {}", article_path.display());
    println!("  For human:  {}...", &human_pubkey[..std::cmp::min(24, human_pubkey.len())]);
    println!();
    println!("{}", style("Consent signature (give this to the human):").yellow().bold());
    println!();
    println!("  {}", style(&consent_signature).green());
    println!();
    println!("Human runs:");
    println!("  cargo run -p xtask -- claim-authorship {} --claimer-id <human-id> --consent-signature {}",
        article_path.display(),
        &consent_signature
    );

    Ok(())
}

/// Claim authorship of a Bot-signed article (Human runs this)
pub fn claim_authorship(article_path: &Path, claimer_id: &str, consent_signature: &str) -> Result<()> {
    println!("{}", style("CLAIM AUTHORSHIP").cyan().bold());
    println!();

    validate_slug(claimer_id).context("Invalid claimer ID")?;

    // Parse article
    let (_full_text, mut frontmatter, body) = parse_file(article_path)?;

    // Check author signature exists
    let author_sig = frontmatter.extra.author_signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Article has no author signature"))?
        .clone();

    // Check if already claimed
    if frontmatter.extra.authorship_claim.is_some() {
        bail!("Article already has an authorship claim");
    }

    // Load claimer metadata and private key
    let (claimer_name, _, claimer_pubkey) = load_author_metadata(claimer_id)?;
    let signing_key = load_author_private_key(claimer_id)?;

    // Calculate article hash
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    // Verify the consent signature using core function
    verify_claim_consent(&author_sig.pubkey, &claimer_pubkey, &hash_hex, consent_signature)
        .context("Invalid bot consent signature. The consent must be signed by the original author for this article.")?;

    // Sign the claim: Human signs over the bot's consent signature
    let signature = signing_key.sign(consent_signature.as_bytes());
    let claim_signature = hex::encode(signature.to_bytes());

    let timestamp = chrono::Utc::now().to_rfc3339();

    // Derive consistent claimer_id from pubkey
    let derived_claimer_id = derive_id_from_pubkey(&claimer_pubkey);

    // Create authorship claim
    frontmatter.extra.authorship_claim = Some(AuthorshipClaim {
        original_author_id: author_sig.author_id.clone(),
        original_pubkey: author_sig.pubkey.clone(),
        claimed_by_id: derived_claimer_id.clone(),
        claimed_by_name: claimer_name.clone(),
        claimed_by_pubkey: claimer_pubkey.clone(),
        bot_consent_signature: consent_signature.to_string(),
        claim_signature: claim_signature.clone(),
        timestamp,
    });

    // Write updated article
    let new_frontmatter_str = toml::to_string(&frontmatter)?;
    let new_content = format!("+++{}+++{}", new_frontmatter_str, body);
    std::fs::write(article_path, new_content)?;

    println!("{}", style("Authorship claimed!").green().bold());
    println!();
    println!("  Original author: {} ({}...)", author_sig.name, &author_sig.author_id);
    println!("  Claimed by:      {} ({})", style(&claimer_name).cyan().bold(), &derived_claimer_id);
    println!();
    println!("{}", style("The article now shows dual attribution:").yellow());
    println!("  - Original bot signature preserved (proof of creation)");
    println!("  - Human authorship claim added (proof of ownership)");

    Ok(())
}
