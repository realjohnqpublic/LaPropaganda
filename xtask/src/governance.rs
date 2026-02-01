//! Board governance operations
//!
//! This module handles owner-authorized governance actions:
//! - Board member appointment
//! - Board member removal
//! - Key updates
//! - Threshold changes
//!
//! All operations require a single hardware key signature (+ 48hr notice for some).

use anyhow::{bail, Context, Result};
use chrono::Utc;
use console::style;
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::config::{
    append_board_member, is_initial_board_setup, load_config, load_owner_keys,
    update_board_member_bool, update_board_member_field, update_board_threshold,
    update_last_modified, validate_slug,
};
use crate::hwkey;
use crate::timestamp::verify_notice_period;

/// Append governance action to audit log in authority manifest
fn append_single_to_audit_log(
    action: &str,
    target_id: &str,
    description: &str,
    sig: &hwkey::SingleSignature,
) -> Result<()> {
    let manifest_path = Path::new(".editorial_board/authority_manifest.toml");
    if !manifest_path.exists() {
        return Ok(()); // No manifest to update
    }

    let mut manifest = std::fs::read_to_string(manifest_path)?;

    let entry = format!(
        r#"
[[audit_log]]
action = "{}"
target_id = "{}"
description = "{}"
timestamp = "{}"
signed_by = "{}"
signature_prefix = "{}""#,
        action,
        target_id,
        description,
        sig.timestamp,
        sig.key_id,
        &sig.signature[..std::cmp::min(32, sig.signature.len())]
    );

    manifest.push_str(&entry);
    std::fs::write(manifest_path, manifest)?;

    Ok(())
}

/// Appoint a new board member (requires single hardware key)
pub fn board_appoint(
    id: String,
    name: String,
    member_type: String,
    role: String,
    pubkey: String,
    notice_hash: Option<String>,
) -> Result<()> {
    println!("{}", style("APPOINT EDITORIAL BOARD MEMBER").cyan().bold());
    println!("{}", style("   (Single hardware key + 48hr notice, except initial setup)").dim());
    println!();

    // Validate inputs
    if member_type != "human" && member_type != "ai_agent" {
        bail!("Member type must be 'human' or 'ai_agent'");
    }

    // SECURITY FIX: Use validate_slug instead of inline check
    validate_slug(&id).context("Invalid board member ID")?;

    // Validate pubkey is valid hex and correct length
    let pubkey_bytes = hex::decode(&pubkey)
        .context("Public key must be valid hex")?;
    if pubkey_bytes.len() != 32 {
        bail!("Public key must be 32 bytes (64 hex characters)");
    }

    // Load config and check if member already exists
    let config_path = Path::new("config.toml");
    let config = load_config(config_path)?;

    // Check if member exists
    if let Some(board) = &config.extra.editorial_board {
        if let Some(members) = &board.members {
            if members.iter().any(|m| m.id == id) {
                bail!("Board member '{}' already exists", id);
            }
        }
    }

    // Load owner keys for validation
    let (primary_key, backup_key) = load_owner_keys(&config)?;

    // Check notice period requirement (per BYLAWS Section 3.5)
    let is_initial = is_initial_board_setup(&config);
    if !is_initial {
        verify_notice_period(&notice_hash, "board-appoint")?;
    } else {
        println!("{}", style("Initial board setup - notice period waived").yellow());
    }

    println!("Appointing new board member:");
    println!("  ID:     {}", style(&id).cyan());
    println!("  Name:   {}", style(&name).cyan());
    println!("  Type:   {}", style(&member_type).cyan());
    println!("  Role:   {}", style(&role).cyan());
    println!("  Pubkey: {}...", style(&pubkey[..16]).cyan());
    println!();

    // Create appointment data
    let timestamp = Utc::now().to_rfc3339();
    let appointment_data = format!(
        "action:appoint\nid:{}\nname:{}\ntype:{}\nrole:{}\npubkey:{}\ntimestamp:{}",
        id, name, member_type, role, pubkey, timestamp
    );

    let mut hasher = Sha256::new();
    hasher.update(appointment_data.as_bytes());
    let appointment_hash = hex::encode(hasher.finalize());

    // Single key sign
    let single_sig = hwkey::single_sign(appointment_hash.as_bytes(), &[&primary_key, &backup_key])?;

    // Add member to config.toml
    let appointed_date = timestamp.split('T').next().unwrap_or(&timestamp);
    append_board_member(config_path, &id, &name, &member_type, &role, &pubkey, appointed_date)?;

    // Update last_modified
    update_last_modified(config_path, appointed_date)?;

    // Add to audit log in manifest
    append_single_to_audit_log("appoint", &id, &format!("Appointed {} as {}", name, role), &single_sig)?;

    println!();
    println!("{}", style("BOARD MEMBER APPOINTED SUCCESSFULLY").green().bold());
    println!();
    println!("Member {} ({}) can now participate in editorial reviews.", style(&name).cyan(), style(&id).dim());

    Ok(())
}

/// Remove a board member (requires single hardware key)
pub fn board_remove(id: String, notice_hash: Option<String>) -> Result<()> {
    println!("{}", style("REMOVE EDITORIAL BOARD MEMBER").cyan().bold());
    println!("{}", style("        (Single hardware key + 48hr notice required)").dim());
    println!();

    // Validate ID
    validate_slug(&id).context("Invalid board member ID")?;

    let config_path = Path::new("config.toml");
    let config = load_config(config_path)?;

    // Check member exists
    let member_exists = config.extra.editorial_board
        .as_ref()
        .and_then(|b| b.members.as_ref())
        .map(|members| members.iter().any(|m| m.id == id))
        .unwrap_or(false);

    if !member_exists {
        bail!("Board member '{}' not found", id);
    }

    // Load owner keys for validation
    let (primary_key, backup_key) = load_owner_keys(&config)?;

    // Verify notice period (per BYLAWS Section 3.5) - removal always requires notice
    verify_notice_period(&notice_hash, "board-remove")?;

    println!("Removing board member: {}", style(&id).red().bold());
    println!();

    // Create removal data
    let timestamp = Utc::now().to_rfc3339();
    let removal_data = format!("action:remove\nid:{}\ntimestamp:{}", id, timestamp);

    let mut hasher = Sha256::new();
    hasher.update(removal_data.as_bytes());
    let removal_hash = hex::encode(hasher.finalize());

    // Single key sign
    let single_sig = hwkey::single_sign(removal_hash.as_bytes(), &[&primary_key, &backup_key])?;

    // Set member to inactive (we don't delete, we deactivate for audit trail)
    update_board_member_bool(config_path, &id, "active", false)?;

    // Update last_modified
    let date = timestamp.split('T').next().unwrap_or(&timestamp);
    update_last_modified(config_path, date)?;

    // Add to audit log
    append_single_to_audit_log("remove", &id, &format!("Removed member {}", id), &single_sig)?;

    println!();
    println!("{}", style("BOARD MEMBER REMOVED SUCCESSFULLY").green().bold());
    println!();
    println!("Member {} has been deactivated and can no longer sign approvals.", style(&id).dim());

    Ok(())
}

/// Update a board member's key (requires single hardware key)
pub fn board_update_key(id: String, new_pubkey: String) -> Result<()> {
    println!("{}", style("UPDATE BOARD MEMBER KEY").cyan().bold());
    println!("{}", style("        (Single hardware key required)").dim());
    println!();

    // Validate ID
    validate_slug(&id).context("Invalid board member ID")?;

    // Validate pubkey
    let pubkey_bytes = hex::decode(&new_pubkey)
        .context("Public key must be valid hex")?;
    if pubkey_bytes.len() != 32 {
        bail!("Public key must be 32 bytes (64 hex characters)");
    }

    let config_path = Path::new("config.toml");
    let config = load_config(config_path)?;

    // Check member exists
    let member_exists = config.extra.editorial_board
        .as_ref()
        .and_then(|b| b.members.as_ref())
        .map(|members| members.iter().any(|m| m.id == id))
        .unwrap_or(false);

    if !member_exists {
        bail!("Board member '{}' not found", id);
    }

    // Load owner keys for validation
    let (primary_key, backup_key) = load_owner_keys(&config)?;

    println!("Updating key for member: {}", style(&id).cyan());
    println!("New pubkey: {}...", style(&new_pubkey[..16]).cyan());
    println!();

    // Create update data
    let timestamp = Utc::now().to_rfc3339();
    let update_data = format!("action:update_key\nid:{}\nnew_pubkey:{}\ntimestamp:{}", id, new_pubkey, timestamp);

    let mut hasher = Sha256::new();
    hasher.update(update_data.as_bytes());
    let update_hash = hex::encode(hasher.finalize());

    // Single key sign
    let single_sig = hwkey::single_sign(update_hash.as_bytes(), &[&primary_key, &backup_key])?;

    // Update pubkey in config
    update_board_member_field(config_path, &id, "pubkey", &new_pubkey)?;

    // Update last_modified
    let date = timestamp.split('T').next().unwrap_or(&timestamp);
    update_last_modified(config_path, date)?;

    // Add to audit log
    append_single_to_audit_log("update_key", &id, &format!("Updated key for {}", id), &single_sig)?;

    println!();
    println!("{}", style("BOARD MEMBER KEY UPDATED SUCCESSFULLY").green().bold());

    Ok(())
}

/// Set the approval threshold (requires single hardware key)
pub fn board_set_threshold(threshold: usize, notice_hash: Option<String>) -> Result<()> {
    println!("{}", style("SET APPROVAL THRESHOLD").cyan().bold());
    println!("{}", style("   (Single hardware key + 48hr notice, except initial setup)").dim());
    println!();

    if threshold < 1 {
        bail!("Threshold must be at least 1");
    }

    let config_path = Path::new("config.toml");
    let config = load_config(config_path)?;

    // Count active members
    let active_count = config.extra.editorial_board
        .as_ref()
        .and_then(|b| b.members.as_ref())
        .map(|members| members.iter().filter(|m| m.active).count())
        .unwrap_or(0);

    if threshold > active_count && active_count > 0 {
        bail!("Threshold ({}) cannot exceed number of active members ({})", threshold, active_count);
    }

    // Load owner keys for validation
    let (primary_key, backup_key) = load_owner_keys(&config)?;

    // Check notice period requirement (per BYLAWS Section 3.5)
    let is_initial = is_initial_board_setup(&config);
    if !is_initial {
        verify_notice_period(&notice_hash, "board-set-threshold")?;
    } else {
        println!("{}", style("Initial board setup - notice period waived").yellow());
    }

    println!("Setting approval threshold to: {}", style(threshold).cyan().bold());
    println!("Active board members: {}", active_count);
    println!();

    // Create threshold data
    let timestamp = Utc::now().to_rfc3339();
    let threshold_data = format!("action:set_threshold\nthreshold:{}\ntimestamp:{}", threshold, timestamp);

    let mut hasher = Sha256::new();
    hasher.update(threshold_data.as_bytes());
    let threshold_hash = hex::encode(hasher.finalize());

    // Single key sign
    let single_sig = hwkey::single_sign(threshold_hash.as_bytes(), &[&primary_key, &backup_key])?;

    // Update threshold in config
    update_board_threshold(config_path, threshold as i64)?;

    // Update last_modified
    let date = timestamp.split('T').next().unwrap_or(&timestamp);
    update_last_modified(config_path, date)?;

    // Add to audit log
    append_single_to_audit_log("set_threshold", "board", &format!("Set threshold to {}", threshold), &single_sig)?;

    println!();
    println!("{}", style("THRESHOLD UPDATED SUCCESSFULLY").green().bold());
    println!();
    println!("Now requires {}-of-{} signatures for content approval.", threshold, if active_count > 0 { active_count } else { threshold });

    Ok(())
}

/// Ratify bylaws with hardware key signature and OpenTimestamp
pub fn ratify_bylaws() -> Result<()> {
    println!("{}", style("BYLAWS RATIFICATION").green().bold());
    println!();

    let bylaws_path = Path::new("BYLAWS.md");
    if !bylaws_path.exists() {
        bail!("BYLAWS.md not found");
    }

    let bylaws_content = std::fs::read_to_string(bylaws_path)?;

    // Find the Signatures section and exclude it from hash
    let sig_marker = "## Signatures";
    let content_to_hash = if let Some(pos) = bylaws_content.find(sig_marker) {
        &bylaws_content[..pos]
    } else {
        &bylaws_content
    };

    let mut hasher = Sha256::new();
    hasher.update(content_to_hash.as_bytes());
    let hash = hex::encode(hasher.finalize());

    println!("Bylaws Hash (SHA-256): {}", style(&hash).cyan());
    println!();

    // Load owner keys from config
    let config = load_config(Path::new("config.toml"))?;
    let (primary_key, backup_key) = load_owner_keys(&config)?;

    // Require hardware key signature
    println!("{}", style("Step 1/2: Sign bylaws with hardware key").cyan().bold());
    let single_sig = hwkey::single_sign(hash.as_bytes(), &[&primary_key, &backup_key])?;

    // Create OpenTimestamp
    println!();
    println!("{}", style("Step 2/2: Creating OpenTimestamp proof").cyan().bold());
    let ots_path = Path::new(".editorial_board/timestamps/bylaws-ratification.ots");
    std::fs::create_dir_all(".editorial_board/timestamps")?;
    crate::timestamp::try_create_opentimestamp(&hash, ots_path);

    println!();
    println!("{}", style("BYLAWS RATIFIED").green().bold());
    println!();
    println!("Hash: {}", &hash);
    println!("Signed by: {}", single_sig.key_id);
    println!();
    println!("Update BYLAWS.md Signatures section with:");
    println!("  Bylaws Hash (SHA-256): {}", &hash);
    println!("  Signature: {}", &single_sig.signature[..64]);
    println!("  Hardware Key ID: {}", single_sig.key_id);

    Ok(())
}
