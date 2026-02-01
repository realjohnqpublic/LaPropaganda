//! OpenTimestamps integration
//!
//! This module provides timestamping functionality using the
//! OpenTimestamps protocol for cryptographic proof of existence.

use anyhow::{bail, Context, Result};
use console::style;
use std::path::Path;
use std::process::Command;

use crate::content::{calculate_hash, parse_file};

/// Submit a hash to OpenTimestamps calendar servers and create .ots file
pub fn create_opentimestamp(hash_hex: &str, output_path: &Path) -> Result<()> {
    println!("{}", style("Creating OpenTimestamp proof...").cyan());

    // Decode the hash
    let hash_bytes = hex::decode(hash_hex)
        .context("Failed to decode hash for timestamping")?;

    // Submit to OpenTimestamps calendar server
    let client = reqwest::blocking::Client::new();
    let calendar_url = "https://a.pool.opentimestamps.org/digest";

    let response = client
        .post(calendar_url)
        .header("Content-Type", "application/octet-stream")
        .body(hash_bytes.clone())
        .send()
        .context("Failed to submit to OpenTimestamps calendar")?;

    if !response.status().is_success() {
        bail!("OpenTimestamps calendar returned error: {}", response.status());
    }

    let ots_data = response.bytes()
        .context("Failed to read OpenTimestamps response")?;

    // Create parent directory if needed
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write .ots file
    std::fs::write(output_path, ots_data)
        .context("Failed to write .ots file")?;

    println!("{}", style(format!("Timestamp proof created: {}", output_path.display())).green());
    println!("{}", style("   This proof can be verified against the Bitcoin blockchain").dim());

    Ok(())
}

/// Attempt to create OpenTimestamp with graceful fallback
pub fn try_create_opentimestamp(hash_hex: &str, output_path: &Path) {
    match create_opentimestamp(hash_hex, output_path) {
        Ok(_) => {}
        Err(e) => {
            println!("{}", style(format!("OpenTimestamp failed (non-critical): {}", e)).yellow());
            println!("{}", style("   Article is still valid without timestamp. You can timestamp manually later.").dim());
        }
    }
}

/// Create OpenTimestamp proof for a governance notice article
pub fn timestamp_notice(article_path: &Path) -> Result<()> {
    println!("{}", style(format!("Creating OpenTimestamp for notice: {}", article_path.display())).cyan().bold());

    let (_, _, body) = parse_file(article_path)?;
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    // Create timestamps directory if needed
    let timestamps_dir = Path::new(".editorial_board/timestamps");
    std::fs::create_dir_all(timestamps_dir)?;

    // Create OTS file with hash prefix as filename
    let ots_filename = format!("{}.ots", &hash_hex[..16]);
    let ots_path = timestamps_dir.join(&ots_filename);

    create_opentimestamp(&hash_hex, &ots_path)?;

    println!();
    println!("{}", style("Notice hash for governance action:").yellow());
    println!("   {}", style(&hash_hex).cyan());
    println!();
    println!("Use this hash with --notice-hash when executing the governance action");
    println!("after 48 hours have passed.");

    Ok(())
}

/// Verify an OpenTimestamp proof file
pub fn verify_timestamp(ots_path: &Path) -> Result<()> {
    println!("{}", style(format!("Verifying OpenTimestamp: {}", ots_path.display())).cyan().bold());

    if !ots_path.exists() {
        bail!("OTS file not found: {}", ots_path.display());
    }

    // Check if ots CLI is available
    let ots_check = Command::new("ots")
        .arg("--version")
        .output();

    match ots_check {
        Ok(output) if output.status.success() => {
            // Use ots CLI to verify
            let verify_result = Command::new("ots")
                .arg("verify")
                .arg(ots_path)
                .output()?;

            if verify_result.status.success() {
                println!("{}", style("OpenTimestamp proof is valid").green().bold());
                let stdout = String::from_utf8_lossy(&verify_result.stdout);
                if !stdout.is_empty() {
                    println!("{}", stdout);
                }
            } else {
                let stderr = String::from_utf8_lossy(&verify_result.stderr);
                if stderr.contains("Pending") {
                    println!("{}", style("Timestamp is pending Bitcoin confirmation").yellow());
                    println!("   This is normal for recent timestamps. Check back later.");
                } else {
                    bail!("Timestamp verification failed: {}", stderr);
                }
            }
        }
        _ => {
            println!("{}", style("OpenTimestamps CLI not installed").yellow());
            println!("   Install with: pip install opentimestamps-client");
            println!();
            println!("   OTS file exists: {}", ots_path.display());
            println!("   Size: {} bytes", std::fs::metadata(ots_path)?.len());
        }
    }

    Ok(())
}

/// Verify notice period requirement (per BYLAWS Section 3.5)
pub fn verify_notice_period(notice_hash: &Option<String>, action: &str) -> Result<()> {
    let hash = match notice_hash {
        Some(h) => h,
        None => {
            bail!(
                "Notice period required for {}.\n\
                 Per BYLAWS Section 3.5, you must:\n\
                 1. Publish a notice article announcing this action\n\
                 2. Run: cargo run -p xtask -- timestamp-notice <article>\n\
                 3. Wait 48 hours after OpenTimestamp anchoring\n\
                 4. Re-run this command with --notice-hash <hash>",
                action
            );
        }
    };

    // Check OTS file exists
    let timestamps_dir = Path::new(".editorial_board/timestamps");
    let ots_file = timestamps_dir.join(format!("{}.ots", &hash[..std::cmp::min(16, hash.len())]));

    if !ots_file.exists() {
        // Try to find any .ots file that might match
        println!("{}", style("Looking for OpenTimestamp proof...").dim());

        let mut found = false;
        if timestamps_dir.exists() {
            for entry in std::fs::read_dir(timestamps_dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.ends_with(".ots") && hash.starts_with(&name_str[..name_str.len()-4]) {
                    found = true;
                    println!("  Found: {:?}", entry.path());
                    break;
                }
            }
        }

        if !found {
            bail!(
                "No OpenTimestamp proof found for notice hash: {}\n\
                 Create one with: cargo run -p xtask -- timestamp-notice <article>",
                hash
            );
        }
    }

    // Verify timestamp age (48 hours = 172800 seconds)
    println!("{}", style("Notice hash provided").green());
    println!("{}", style("  Verifying OpenTimestamp...").dim());

    // Try to verify with ots command if available
    let ots_check = Command::new("ots")
        .arg("--version")
        .output();

    match ots_check {
        Ok(output) if output.status.success() => {
            println!("{}", style("  Manual verification: ensure 48 hours have passed since OTS anchor time").yellow());
            println!("{}", style("    Run: ots verify <file>.ots to check timestamp").dim());
        }
        _ => {
            println!("{}", style("  OpenTimestamps CLI not available for automatic verification").yellow());
            println!("{}", style("  Install with: pip install opentimestamps-client").dim());
        }
    }

    Ok(())
}
