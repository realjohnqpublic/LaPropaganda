//! Editorial board operations
//!
//! This module handles:
//! - Board member key generation
//! - Editorial review (approve/reject)
//! - Board member listing
//! - Article verification

use anyhow::{bail, Context, Result};
use chrono::Local;
use console::style;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::author::verify_author;
use crate::config::validate_slug;
use crate::content::{calculate_hash, get_content_files, parse_file};
use crate::timestamp::try_create_opentimestamp;
use crate::types::{Config, EditorialSignature};

/// Generate Ed25519 keypair for editorial board member
pub fn board_keygen(name: String, id: String, role: String, member_type: String) -> Result<()> {
    println!("{}", style(format!("Generating Ed25519 keypair for board member: {}", name)).cyan().bold());

    // Validate member type
    if member_type != "human" && member_type != "ai_agent" {
        bail!("Member type must be 'human' or 'ai_agent'");
    }

    // Validate ID format
    validate_slug(&id).context("Invalid board member ID")?;

    // Create .editorial_board/board/<id> directory
    let key_dir = Path::new(".editorial_board/board").join(&id);
    if key_dir.exists() {
        bail!("Board member {} already exists at {:?}", id, key_dir);
    }
    std::fs::create_dir_all(&key_dir).context("Failed to create board member key directory")?;

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

    // Save member metadata
    let metadata = format!(
        "# Board Member: {}\n# ID: {}\n# Role: {}\n# Type: {}\n# Public Key: {}\n# Generated: {}\n",
        name,
        id,
        role,
        member_type,
        public_key_hex,
        Local::now().format("%Y-%m-%d %H:%M:%S")
    );
    let metadata_path = key_dir.join("member.info");
    std::fs::write(&metadata_path, &metadata)
        .context("Failed to write member metadata")?;

    println!("{}", style("Board member keypair generated successfully!").green().bold());
    println!();
    println!("{}", style("Private key saved to:").yellow());
    println!("   {}", style(private_key_path.display()).cyan());
    println!("   {}", style("KEEP THIS SECRET! Never commit to git.").red().bold());
    println!();
    println!("{}", style("Public key:").yellow());
    println!("   {}", style(&public_key_hex).cyan());
    println!();
    println!("{}", style("Next steps:").yellow().bold());
    println!("1. Add this member to config.toml under [extra.editorial_board.members]");
    println!("2. Or use: cargo run -p xtask -- board-appoint --id {} --name \"{}\" --pubkey {} --role \"{}\" --member-type {}",
             id, name, public_key_hex, role, member_type);

    Ok(())
}

/// Load board member private key
pub fn load_board_member_private_key(member_id: &str) -> Result<SigningKey> {
    validate_slug(member_id).context("Invalid board member ID")?;

    let key_path = Path::new(".editorial_board/board").join(member_id).join("private_key.secret");
    if !key_path.exists() {
        bail!(
            "Board member key not found for '{}'. Generate with: cargo run -p xtask -- board-keygen --name \"Name\" --id {} --role \"Role\"",
            member_id,
            member_id
        );
    }

    let key_hex = std::fs::read_to_string(&key_path)
        .context("Failed to read board member private key")?;
    let key_bytes = hex::decode(key_hex.trim())
        .context("Failed to decode board member private key")?;
    let key_array: [u8; 32] = key_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Board member private key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&key_array))
}

/// Review article as editorial board member
///
/// If `member_id_arg` is provided, uses that ID without prompting.
pub fn editorial_review(
    article_path: &Path,
    approve: bool,
    reject: bool,
    member_id_arg: Option<String>,
) -> Result<()> {
    if !approve && !reject {
        bail!("Must specify --approve or --reject");
    }

    let decision = if approve { "approve" } else { "reject" };

    println!("{}", style(format!("Editorial Review: {} - {}", article_path.display(), decision.to_uppercase())).cyan().bold());

    // Parse article
    let (_, mut frontmatter, body) = parse_file(article_path)?;

    // Check author signature exists
    let author_sig_data = frontmatter.extra.author_signature.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Article must have author signature before editorial review"))?;
    let author_signature = &author_sig_data.signature;

    // Verify author signature first
    println!("{}", style("Step 1: Verifying author signature...").yellow());
    verify_author(article_path)?;

    // Get member ID (required for automation/bot compatibility)
    let member_id = match member_id_arg {
        Some(id) => {
            validate_slug(&id).context("Invalid board member ID")?;
            id
        }
        None => {
            bail!(
                "Board member ID is required. Use --member-id <id> to specify.\n\
                 Available members can be found in .editorial_board/board/ directory."
            );
        }
    };

    // Check for duplicate review
    if let Some(signatures) = &frontmatter.extra.editorial_signatures {
        if signatures.iter().any(|s| s.board_member == member_id) {
            bail!("Board member '{}' has already reviewed this article.", member_id);
        }
    }

    // Load board member metadata
    let member_info_path = Path::new(".editorial_board/board").join(&member_id).join("member.info");
    let member_info = std::fs::read_to_string(&member_info_path)
        .context("Failed to read board member metadata. Run board-keygen first.")?;

    let name_re = Regex::new(r"# Board Member: (.+)")?;
    let member_name = name_re.captures(&member_info)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .unwrap_or("Unknown");

    // Calculate article hash
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    // Create review hash: SHA-256(article_hash + author_signature)
    let review_data = format!("{}{}", hash_hex, author_signature);
    let mut hasher = Sha256::new();
    hasher.update(review_data.as_bytes());
    let review_hash = hasher.finalize();
    let review_hash_hex = hex::encode(review_hash);

    // Sign review hash
    let signing_key = load_board_member_private_key(&member_id)?;
    let signature = signing_key.sign(review_hash_hex.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    println!("{}", style(format!("Step 2: Signing {} decision as: {}", decision, member_name)).yellow());

    // Update frontmatter with editorial signature
    let timestamp = Local::now().to_rfc3339();

    if frontmatter.extra.editorial_signatures.is_none() {
        frontmatter.extra.editorial_signatures = Some(Vec::new());
    }

    if let Some(signatures) = &mut frontmatter.extra.editorial_signatures {
        signatures.push(EditorialSignature {
            board_member: member_id.to_string(),
            signature: signature_hex.clone(),
            timestamp,
            decision: decision.to_string(),
        });
    }

    // Check threshold
    let required = frontmatter.extra.editorial_approval.as_ref().map(|a| a.required).unwrap_or(3);
    let approval_count = frontmatter.extra.editorial_signatures.as_ref()
        .map(|sigs| sigs.iter().filter(|s| s.decision == "approve").count())
        .unwrap_or(0);

    let sig_count = frontmatter.extra.editorial_signatures.as_ref().map(|s| s.len()).unwrap_or(0);

    println!("{}", style(format!("Step 3: Checking threshold ({}/{} signatures)", sig_count, required)).yellow());

    if approval_count >= required {
        if let Some(approval) = &mut frontmatter.extra.editorial_approval {
            approval.status = "approved".to_string();
        }
        println!("{}", style("Threshold reached! Article approved for publication.").green().bold());

        // Create OpenTimestamp proof of approval
        println!();
        let ots_path = article_path.with_extension("md.ots");
        try_create_opentimestamp(&hash_hex, &ots_path);
    } else {
        let remaining = if required > approval_count { required - approval_count } else { 0 };
        println!("{}", style(format!("{} more signature(s) needed", remaining)).yellow());
    }

    // Write updated article
    let new_frontmatter_str = toml::to_string(&frontmatter)?;
    let new_content = format!("+++{}+++{}", new_frontmatter_str, body);
    std::fs::write(article_path, new_content)?;

    println!("{}", style(format!("Editorial {} recorded successfully!", decision)).green().bold());
    println!();
    println!("{}", style("Review hash:").yellow());
    println!("   {}...", style(&review_hash_hex[..32]).cyan());
    println!("{}", style(format!("{} signature:", member_name)).yellow());
    println!("   {}...", style(&signature_hex[..32]).cyan());

    Ok(())
}

/// List editorial board members
pub fn board_list() -> Result<()> {
    println!("{}", style("Editorial Board Members").cyan().bold());
    println!();

    let config_path = Path::new("config.toml");
    let config_str = std::fs::read_to_string(config_path)
        .context("Failed to read config.toml")?;

    let config: Config = toml::from_str(&config_str)
        .context("Failed to parse config.toml")?;

    let members = config.extra.editorial_board
        .and_then(|b| b.members)
        .unwrap_or_default();

    if members.is_empty() {
        println!("{}", style("No board members found in config.toml").yellow());
        println!();
        println!("Add members with:");
        println!("  {}", style("cargo run -p xtask -- board-keygen --name \"Name\" --id member-id --role \"Role\"").cyan());
        return Ok(());
    }

    println!("| ID | Name | Role | Status |");
    println!("|---|---|---|---|");

    for member in members {
        let status = if member.active { "Active" } else { "Inactive" };
        println!("| {} | {} | {} | {} |", member.id, member.name, member.role, status);
    }

    Ok(())
}

/// Verify all signatures on an article
pub fn verify_article(article_path: &Path) -> Result<()> {
    println!("{}", style(format!("Verifying article: {}", article_path.display())).cyan());

    // 1. Verify author
    println!("{}", style("  Step 1: Author Signature").dim());
    verify_author(article_path)?;

    // Parse article
    let (_, frontmatter, body) = parse_file(article_path)?;

    // 2. Verify editorial signatures
    println!("{}", style("  Step 2: Editorial Signatures").dim());

    // Get author signature data for review hash calculation
    let author_sig_data = frontmatter.extra.author_signature.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing author signature (unexpected)"))?;
    let author_signature = &author_sig_data.signature;

    // Calculate base hashes
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    let mut hasher = Sha256::new();
    let review_data = format!("{}{}", hash_hex, author_signature);
    hasher.update(review_data.as_bytes());
    let review_hash = hasher.finalize();
    let review_hash_hex = hex::encode(review_hash);

    let signatures = frontmatter.extra.editorial_signatures.as_ref();

    if signatures.is_none() || signatures.unwrap().is_empty() {
        println!("{}", style("  No editorial signatures found").yellow());
        return Ok(()); // Valid integrity, just unapproved
    }

    let signatures = signatures.unwrap();
    let mut valid_approvals = 0;

    for sig in signatures {
        let member_info_path = Path::new(".editorial_board/board").join(&sig.board_member).join("member.info");
        if !member_info_path.exists() {
            println!("{}", style(format!("  Unknown board member: {}", sig.board_member)).yellow());
            continue;
        }

        let member_info = std::fs::read_to_string(&member_info_path)?;
        let pubkey_re = Regex::new(r"# Public Key: (.+)")?;
        let pubkey_hex = pubkey_re.captures(&member_info)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing public key for {}", sig.board_member))?;

        let pubkey_bytes = hex::decode(pubkey_hex)?;
        let pubkey_array: [u8; 32] = pubkey_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid key"))?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_array)?;

        let sig_bytes = hex::decode(&sig.signature)?;
        let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid signature"))?;
        let signature = Signature::from_bytes(&sig_array);

        if verifying_key.verify(review_hash_hex.as_bytes(), &signature).is_ok() {
            println!("  Valid signature from {}", sig.board_member);
            if sig.decision == "approve" {
                valid_approvals += 1;
            }
        } else {
            println!("{}", style(format!("  INVALID signature from {}", sig.board_member)).red().bold());
            bail!("Invalid editorial signature detected from {}", sig.board_member);
        }
    }

    // Check threshold
    let required = frontmatter.extra.editorial_approval.as_ref().map(|a| a.required).unwrap_or(3);
    let status = frontmatter.extra.editorial_approval.as_ref()
        .map(|a| a.status.clone())
        .unwrap_or_else(|| "pending".to_string());

    if valid_approvals >= required {
        if status == "approved" {
            println!("{}", style("  Article fully approved and verified").green().bold());
        } else {
            println!("{}", style("  Threshold met but status not 'approved'").yellow());
        }
    } else {
        println!("{}", style(format!("  Approvals: {}/{}", valid_approvals, required)).dim());
    }

    Ok(())
}

/// Verify all approved articles have valid signatures (for CI/CD pipeline)
pub fn verify_all_articles(require_timestamps: bool) -> Result<()> {
    println!("{}", style("CI/CD ARTICLE SIGNATURE VERIFICATION").cyan().bold());
    println!();

    // 1. Verify Site Signature - DISABLED (Removed feature)
    // verify_site_signature().context("Site signature verification failed - cannot proceed")?;

    let files = get_content_files();
    let mut approved_count = 0;
    let mut failed_count = 0;
    let mut pending_count = 0;
    let mut missing_timestamps = 0;

    for file in files {
        // Skip _index.md files
        if file.file_name().map(|f| f == "_index.md").unwrap_or(false) {
            continue;
        }

        let (_, frontmatter, _) = match parse_file(&file) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Check if article has author_signature section
        let has_author_sig = frontmatter.extra.author_signature.is_some();
        if !has_author_sig {
            continue;
        }

        // Check approval status
        let status = frontmatter.extra.editorial_approval.as_ref()
            .map(|a| a.status.clone())
            .unwrap_or_else(|| "pending".to_string());

        if status == "approved" {
            print!("  {} ... ", file.display());

            match verify_article(&file) {
                Ok(_) => {
                    // Check for OpenTimestamp proof
                    let ots_path = file.with_extension("md.ots");
                    if require_timestamps && !ots_path.exists() {
                        println!("{}", style("MISSING TIMESTAMP").yellow());
                        missing_timestamps += 1;
                        failed_count += 1;
                        continue;
                    }
                    println!("{}", style("VERIFIED").green());
                    approved_count += 1;
                }
                Err(e) => {
                    println!("{}", style("VERIFICATION FAILED").red());
                    println!("      {}", e);
                    failed_count += 1;
                }
            }
        } else {
            pending_count += 1;
        }
    }

    println!();
    println!("  Verified Approved Articles: {}", style(approved_count).green().bold());
    println!("  Pending Articles:           {}", style(pending_count).yellow());
    if failed_count > 0 {
        println!("  Failed Verifications:       {}", style(failed_count).red().bold());
    }
    if missing_timestamps > 0 {
        println!("  Missing Timestamps:         {}", style(missing_timestamps).yellow());
    }

    if failed_count > 0 {
        if require_timestamps && missing_timestamps > 0 {
            bail!("Verification failed: {} articles failed verification (including {} missing timestamps)", failed_count, missing_timestamps);
        }
        bail!("Verification failed: {} articles failed verification", failed_count);
    }

    Ok(())
}
