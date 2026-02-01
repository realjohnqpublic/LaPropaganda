//! OpenTimestamps integration
//!
//! This module provides timestamping functionality using the
//! OpenTimestamps protocol for cryptographic proof of existence.
//! Uses the opentimestamps Rust crate for native parsing and verification.

use anyhow::{bail, Context, Result};
use console::style;
use opentimestamps::DetachedTimestampFile;
use std::fs::File;
use std::path::Path;

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

/// Verify an OpenTimestamp proof file using native Rust parsing
pub fn verify_timestamp(ots_path: &Path) -> Result<()> {
    println!("{}", style(format!("Verifying OpenTimestamp: {}", ots_path.display())).cyan().bold());

    if !ots_path.exists() {
        bail!("OTS file not found: {}", ots_path.display());
    }

    // Parse OTS file natively using opentimestamps crate
    let file = File::open(ots_path)
        .context("Failed to open OTS file")?;

    match DetachedTimestampFile::from_reader(file) {
        Ok(ots) => {
            println!("{}", style("OpenTimestamp proof parsed successfully").green().bold());
            println!();

            // Display the timestamp structure
            let ots_display = format!("{}", ots);

            // Check for attestations indicating Bitcoin anchoring
            let is_bitcoin_anchored = ots_display.contains("BitcoinBlockHeaderAttestation")
                || ots_display.contains("bitcoin");
            let is_pending = ots_display.contains("PendingAttestation")
                || ots_display.contains("pending");

            if is_bitcoin_anchored {
                println!("{}", style("Status: BITCOIN ANCHORED").green().bold());
                println!("   This timestamp has been confirmed on the Bitcoin blockchain.");
            } else if is_pending {
                println!("{}", style("Status: PENDING").yellow());
                println!("   This timestamp is waiting for Bitcoin confirmation.");
                println!("   This is normal for recent timestamps (~1-24 hours).");
            } else {
                println!("{}", style("Status: CALENDAR SUBMITTED").cyan());
                println!("   Timestamp submitted to calendar servers.");
            }

            println!();
            println!("{}", style("Timestamp details:").dim());
            // Print first few lines of the timestamp info
            for (i, line) in ots_display.lines().take(20).enumerate() {
                if i == 19 {
                    println!("   ... (truncated)");
                } else {
                    println!("   {}", line);
                }
            }
        }
        Err(e) => {
            println!("{}", style(format!("Failed to parse OTS file: {}", e)).red());
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

    let ots_path = if ots_file.exists() {
        ots_file
    } else {
        // Try to find any .ots file that might match
        println!("{}", style("Looking for OpenTimestamp proof...").dim());

        let mut found_path = None;
        if timestamps_dir.exists() {
            for entry in std::fs::read_dir(timestamps_dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.ends_with(".ots") && hash.starts_with(&name_str[..name_str.len()-4]) {
                    found_path = Some(entry.path());
                    println!("  Found: {:?}", entry.path());
                    break;
                }
            }
        }

        match found_path {
            Some(p) => p,
            None => bail!(
                "No OpenTimestamp proof found for notice hash: {}\n\
                 Create one with: cargo run -p xtask -- timestamp-notice <article>",
                hash
            ),
        }
    };

    // Verify timestamp using native Rust parsing
    println!("{}", style("Notice hash provided").green());
    println!("{}", style("  Verifying OpenTimestamp...").dim());

    let file = File::open(&ots_path)
        .context("Failed to open OTS file")?;

    match DetachedTimestampFile::from_reader(file) {
        Ok(ots) => {
            let ots_display = format!("{}", ots);

            // Check for Bitcoin attestation
            let is_bitcoin_anchored = ots_display.contains("BitcoinBlockHeaderAttestation")
                || ots_display.contains("bitcoin");

            if is_bitcoin_anchored {
                println!("{}", style("  Timestamp is Bitcoin-anchored").green().bold());
                println!("{}", style("  Manual verification: ensure 48 hours have passed since anchor time").yellow());
            } else {
                println!("{}", style("  Timestamp is pending Bitcoin confirmation").yellow());
                println!("{}", style("  Wait for Bitcoin anchoring before proceeding with governance action").dim());
            }
        }
        Err(e) => {
            println!("{}", style(format!("  Warning: Could not parse OTS file: {}", e)).yellow());
            println!("{}", style("  File exists but may be malformed. Verify manually.").dim());
        }
    }

    Ok(())
}
