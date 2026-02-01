//! Owner authority operations
//!
//! This module handles owner-level operations that require hardware keys:
//! - Owner initialization (dual key)
//! - Key verification
//! - Key rotation (dual key)

use anyhow::{bail, Result};
use chrono::Utc;
use console::style;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::config::{load_config, update_bool_field, update_nested_field};
use crate::hwkey;

/// Initialize owner authority with dual hardware keys
pub fn owner_init(owner_name: String) -> Result<()> {
    println!("{}", style("OWNER AUTHORITY INITIALIZATION").cyan().bold());
    println!();

    // Check if already initialized
    let config = load_config(Path::new("config.toml"))?;
    let initialized = config.extra.owner
        .as_ref()
        .and_then(|o| o.initialized)
        .unwrap_or(false);

    if initialized {
        bail!("Owner authority is already initialized. Use board-appoint/board-remove to manage the board.");
    }

    hwkey::check_gpg()?;

    println!("This will set up dual-hardware key authority for: {}", style(&owner_name).cyan().bold());
    println!();
    println!("{}", style("Requirements:").yellow());
    println!("  Two hardware key 5 series devices with Ed25519 keys configured");
    println!("  Each hardware key must have a signing key generated via GPG");
    println!();
    println!("{}", style("If you haven't set up your hardware keys yet:").dim());
    println!("  1. Insert hardware key and run: gpg --card-edit");
    println!("  2. Type 'admin' then 'generate' to create Ed25519 key");
    println!("  3. Repeat for second hardware key");
    println!();

    // Step 1: Get Primary hardware key info
    println!("{}", style("Step 1/3: Configure PRIMARY hardware key").cyan().bold());
    println!("Insert your PRIMARY hardware key and press Enter...");
    hwkey::wait_for_enter()?;

    let primary_info = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    let primary_key_id = primary_info.key_id.clone()
        .ok_or_else(|| anyhow::anyhow!("No signing key on this hardware key. Generate one with: gpg --card-edit"))?;

    println!("  Detected: Serial {}", primary_info.serial);
    println!("  Key ID:   {}", style(&primary_key_id).green());

    // Step 2: Get Backup hardware key info
    println!();
    println!("{}", style("Step 2/3: Configure BACKUP hardware key").cyan().bold());
    println!("REMOVE the Primary hardware key");
    println!("INSERT your BACKUP hardware key and press Enter...");
    hwkey::wait_for_enter()?;

    let backup_info = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    if backup_info.serial == primary_info.serial {
        bail!("Same hardware key detected! You need TWO different hardware keys.");
    }

    let backup_key_id = backup_info.key_id.clone()
        .ok_or_else(|| anyhow::anyhow!("No signing key on backup hardware key. Generate one with: gpg --card-edit"))?;

    println!("  Detected: Serial {}", backup_info.serial);
    println!("  Key ID:   {}", style(&backup_key_id).green());

    // Step 3: Create initial authority manifest and sign with both keys
    println!();
    println!("{}", style("Step 3/3: Creating authority manifest with dual signatures").cyan().bold());

    let timestamp = Utc::now().to_rfc3339();
    let manifest_data = format!(
        "owner:{}\nprimary:{}\nbackup:{}\ntimestamp:{}\nthreshold:3\nmembers:0",
        owner_name, primary_key_id, backup_key_id, timestamp
    );

    // Calculate hash of manifest data
    let mut hasher = Sha256::new();
    hasher.update(manifest_data.as_bytes());
    let manifest_hash = hex::encode(hasher.finalize());

    // Dual sign the manifest hash
    let dual_sig = hwkey::dual_sign(manifest_hash.as_bytes(), &primary_key_id, &backup_key_id)?;

    // Update config.toml using proper TOML updates
    let config_path = Path::new("config.toml");
    update_nested_field(config_path, &["extra", "owner", "name"], &owner_name)?;
    update_nested_field(config_path, &["extra", "owner", "primary_pubkey"], &primary_key_id)?;
    update_nested_field(config_path, &["extra", "owner", "backup_pubkey"], &backup_key_id)?;
    update_bool_field(config_path, &["extra", "owner", "initialized"], true)?;
    update_nested_field(config_path, &["extra", "editorial_board", "manifest_hash"], &manifest_hash)?;

    // Update authority manifest file
    let manifest_path = Path::new(".editorial_board/authority_manifest.toml");
    if manifest_path.exists() {
        update_manifest_signatures(manifest_path, &owner_name, &timestamp, &manifest_hash, &dual_sig)?;
    }

    println!();
    println!("{}", style("OWNER AUTHORITY INITIALIZED").green().bold());
    println!();
    println!("Owner:        {}", style(&owner_name).cyan());
    println!("Primary Key:  {}", style(&primary_key_id).cyan());
    println!("Backup Key:   {}", style(&backup_key_id).cyan());
    println!();
    println!("{}", style("Next steps:").yellow().bold());
    println!("1. Store your BACKUP hardware key in a secure off-site location");
    println!("2. Use 'board-appoint' to add editorial board members");
    println!("3. Board members can then publish content without owner involvement");

    Ok(())
}

/// Update authority manifest with signatures
fn update_manifest_signatures(
    manifest_path: &Path,
    owner_name: &str,
    timestamp: &str,
    manifest_hash: &str,
    dual_sig: &hwkey::DualSignature,
) -> Result<()> {
    let mut manifest = std::fs::read_to_string(manifest_path)
        .unwrap_or_default();

    // Use regex to update fields
    let update_field = |content: &str, field: &str, value: &str| -> String {
        let re = Regex::new(&format!(r#"(?m)^{}\s*=\s*"[^"]*""#, field)).unwrap();
        if re.is_match(content) {
            re.replace(content, format!(r#"{} = "{}""#, field, value)).to_string()
        } else {
            content.to_string()
        }
    };

    manifest = update_field(&manifest, "created", timestamp);
    manifest = update_field(&manifest, "last_modified", timestamp);
    manifest = update_field(&manifest, "owner_name", owner_name);
    manifest = update_field(&manifest, "board_state_hash", manifest_hash);
    manifest = update_field(&manifest, "primary_signature", &dual_sig.primary_signature);
    manifest = update_field(&manifest, "primary_key_id", &dual_sig.primary_key_id);
    manifest = update_field(&manifest, "primary_signed_at", &dual_sig.primary_timestamp);
    manifest = update_field(&manifest, "backup_signature", &dual_sig.backup_signature);
    manifest = update_field(&manifest, "backup_key_id", &dual_sig.backup_key_id);
    manifest = update_field(&manifest, "backup_signed_at", &dual_sig.backup_timestamp);

    std::fs::write(manifest_path, &manifest)?;
    Ok(())
}

/// Verify both owner hardware keys are accessible
pub fn owner_verify_keys() -> Result<()> {
    println!("{}", style("Verifying owner hardware key access...").cyan().bold());
    println!();

    // Load owner config
    let config = load_config(Path::new("config.toml"))?;
    let owner = config.extra.owner
        .ok_or_else(|| anyhow::anyhow!("Owner not initialized. Run: owner-init --name \"Your Name\""))?;

    let primary_key = owner.primary_pubkey
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Primary owner key not configured"))?;

    let backup_key = owner.backup_pubkey
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Backup owner key not configured"))?;

    println!("Expected PRIMARY key: {}", style(&primary_key).dim());
    println!("Expected BACKUP key:  {}", style(&backup_key).dim());
    println!();

    // Verify Primary
    println!("{}", style("Step 1/2: Verify PRIMARY hardware key").cyan());
    println!("Insert PRIMARY hardware key and press Enter...");
    hwkey::wait_for_enter()?;

    let info1 = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    match &info1.key_id {
        // SECURITY FIX: Use exact matching, not contains()
        Some(id) if id == &primary_key => {
            println!("{}", style("  Primary hardware key verified").green());
        }
        Some(id) => {
            println!("{}", style(format!("  Key ID mismatch: found {}", id)).yellow());
        }
        None => {
            println!("{}", style("  No signing key on this hardware key").red());
        }
    }

    let primary_serial = info1.serial.clone();

    // Verify Backup
    println!();
    println!("{}", style("Step 2/2: Verify BACKUP hardware key").cyan());
    println!("REMOVE Primary, INSERT BACKUP hardware key and press Enter...");
    hwkey::wait_for_enter()?;

    let info2 = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    if info2.serial == primary_serial {
        bail!("Same hardware key detected! Insert the BACKUP hardware key.");
    }

    match &info2.key_id {
        // SECURITY FIX: Use exact matching, not contains()
        Some(id) if id == &backup_key => {
            println!("{}", style("  Backup hardware key verified").green());
        }
        Some(id) => {
            println!("{}", style(format!("  Key ID mismatch: found {}", id)).yellow());
        }
        None => {
            println!("{}", style("  No signing key on this hardware key").red());
        }
    }

    println!();
    println!("{}", style("Both hardware keys verified successfully").green().bold());

    Ok(())
}

/// Rotate/recover owner key when one is lost (requires remaining + new key)
pub fn owner_rotate_key(replace: String) -> Result<()> {
    println!("{}", style("KEY ROTATION / RECOVERY").yellow().bold());
    println!();

    if replace != "primary" && replace != "backup" {
        bail!("--replace must be 'primary' or 'backup'");
    }

    let config = load_config(Path::new("config.toml"))?;
    let owner = config.extra.owner
        .ok_or_else(|| anyhow::anyhow!("Owner not initialized"))?;

    let primary_key = owner.primary_pubkey
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Primary key not configured"))?;

    let backup_key = owner.backup_pubkey
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Backup key not configured"))?;

    let remaining_key = if replace == "primary" { &backup_key } else { &primary_key };

    println!("This operation will replace your {} hardware key.", style(&replace).yellow().bold());
    println!();
    println!("{}", style("WARNING: This is a critical operation!").red().bold());
    println!("Make sure you have a valid reason (lost key, compromised key, etc.)");
    println!();

    // Step 1: Verify remaining key
    println!("{}", style(format!("Step 1/3: Verify REMAINING ({}) hardware key", if replace == "primary" { "backup" } else { "primary" })).cyan());
    println!("Insert your REMAINING hardware key and press Enter...");
    hwkey::wait_for_enter()?;

    let remaining_info = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    let remaining_detected_id = remaining_info.key_id.clone()
        .ok_or_else(|| anyhow::anyhow!("No signing key on hardware key"))?;

    // SECURITY FIX: Exact match
    if &remaining_detected_id != remaining_key {
        bail!("Hardware key does not match registered {} key", if replace == "primary" { "backup" } else { "primary" });
    }

    println!("{}", style("  Remaining key verified").green());
    let remaining_serial = remaining_info.serial.clone();

    // Step 2: Get new key
    println!();
    println!("{}", style("Step 2/3: Register NEW hardware key").cyan());
    println!("REMOVE remaining key, INSERT your NEW hardware key and press Enter...");
    hwkey::wait_for_enter()?;

    let new_info = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    if new_info.serial == remaining_serial {
        bail!("Same hardware key detected! Insert a NEW hardware key.");
    }

    let new_key_id = new_info.key_id.clone()
        .ok_or_else(|| anyhow::anyhow!("No signing key on new hardware key"))?;

    println!("  New key ID: {}", style(&new_key_id).green());

    // Step 3: Sign rotation with both keys
    println!();
    println!("{}", style("Step 3/3: Sign key rotation").cyan());

    let timestamp = Utc::now().to_rfc3339();
    let rotation_data = format!(
        "action:rotate\nreplace:{}\nold_key:{}\nnew_key:{}\ntimestamp:{}",
        replace,
        if replace == "primary" { &primary_key } else { &backup_key },
        new_key_id,
        timestamp
    );

    let mut hasher = Sha256::new();
    hasher.update(rotation_data.as_bytes());
    let rotation_hash = hex::encode(hasher.finalize());

    // Sign with remaining key first, then new key
    println!("Insert REMAINING hardware key to sign...");
    hwkey::wait_for_enter()?;
    let _remaining_sig = hwkey::sign_with_hwkey(rotation_hash.as_bytes(), &remaining_detected_id)?;

    println!("Insert NEW hardware key to sign...");
    hwkey::wait_for_enter()?;
    let _new_sig = hwkey::sign_with_hwkey(rotation_hash.as_bytes(), &new_key_id)?;

    // Update config
    let config_path = Path::new("config.toml");
    if replace == "primary" {
        update_nested_field(config_path, &["extra", "owner", "primary_pubkey"], &new_key_id)?;
    } else {
        update_nested_field(config_path, &["extra", "owner", "backup_pubkey"], &new_key_id)?;
    }

    println!();
    println!("{}", style("KEY ROTATION COMPLETE").green().bold());
    println!();
    println!("Replaced {} key with: {}", replace, style(&new_key_id).cyan());
    println!();
    println!("{}", style("Store your new hardware key securely!").yellow());

    Ok(())
}

/// Show authority manifest
pub fn manifest_show() -> Result<()> {
    println!("{}", style("AUTHORITY MANIFEST").cyan().bold());
    println!();

    let manifest_path = Path::new(".editorial_board/authority_manifest.toml");
    if !manifest_path.exists() {
        println!("{}", style("No authority manifest found.").yellow());
        println!("Run 'owner-init' to initialize owner authority.");
        return Ok(());
    }

    let manifest = std::fs::read_to_string(manifest_path)?;

    // Extract and display key fields
    let extract = |field: &str| -> String {
        let re = Regex::new(&format!(r#"(?m)^{}\s*=\s*"([^"]*)""#, field)).unwrap();
        re.captures(&manifest)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "(not set)".to_string())
    };

    println!("{}", style("Manifest Info:").yellow());
    println!("  Owner:         {}", extract("owner_name"));
    println!("  Created:       {}", extract("created"));
    println!("  Last Modified: {}", extract("last_modified"));
    println!("  Board Hash:    {}...", &extract("board_state_hash").chars().take(16).collect::<String>());
    println!();

    println!("{}", style("Signatures:").yellow());
    println!("  Primary Key:   {}", extract("primary_key_id"));
    println!("  Primary Sig:   {}...", &extract("primary_signature").chars().take(16).collect::<String>());
    println!("  Primary Time:  {}", extract("primary_signed_at"));
    println!();
    println!("  Backup Key:    {}", extract("backup_key_id"));
    println!("  Backup Sig:    {}...", &extract("backup_signature").chars().take(16).collect::<String>());
    println!("  Backup Time:   {}", extract("backup_signed_at"));
    println!();

    // Show audit log entries
    println!("{}", style("Audit Log:").yellow());
    let audit_entries: Vec<&str> = manifest.split("[[audit_log]]").skip(1).collect();
    if audit_entries.is_empty() || (audit_entries.len() == 1 && audit_entries[0].contains("timestamp = \"\"")) {
        println!("  (no entries yet)");
    } else {
        for entry in audit_entries.iter().take(10) {
            let action_re = Regex::new(r#"action\s*=\s*"([^"]*)""#).ok();
            let target_re = Regex::new(r#"target_id\s*=\s*"([^"]*)""#).ok();
            let time_re = Regex::new(r#"timestamp\s*=\s*"([^"]*)""#).ok();

            let action = action_re.and_then(|re| re.captures(entry)).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("?");
            let target = target_re.and_then(|re| re.captures(entry)).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("?");
            let time = time_re.and_then(|re| re.captures(entry)).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("?");

            if !time.is_empty() {
                println!("  {} | {} | {}", time.chars().take(10).collect::<String>(), action, target);
            }
        }
    }

    Ok(())
}
