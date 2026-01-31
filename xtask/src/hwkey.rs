//! Hardware key support via GPG OpenPGP card interface
//!
//! This module provides Ed25519 signing using hardware security keys
//! (e.g., YubiKey, Nitrokey, OnlyKey, etc.) via the GPG smartcard interface.
//! The private key never leaves the hardware secure element.

use anyhow::{bail, Context, Result};
use console::style;
use std::process::{Command, Stdio};

/// Information about a detected hardware key
#[derive(Debug, Clone)]
pub struct HwKeyInfo {
    pub serial: String,
    pub card_type: String,
    pub key_id: Option<String>,
    pub fingerprint: Option<String>,
}

/// Result of a dual-signature operation
#[derive(Debug, Clone)]
pub struct DualSignature {
    pub primary_signature: String,
    pub primary_key_id: String,
    pub primary_timestamp: String,
    pub backup_signature: String,
    pub backup_key_id: String,
    pub backup_timestamp: String,
}

/// Result of a single-signature operation
#[derive(Debug, Clone)]
pub struct SingleSignature {
    pub signature: String,
    pub key_id: String,
    pub timestamp: String,
    pub hwkey_serial: String,
}

/// Check if GPG is available
pub fn check_gpg() -> Result<()> {
    let output = Command::new("gpg")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match output {
        Ok(status) if status.success() => Ok(()),
        _ => bail!("GPG is not installed or not in PATH. Install with: brew install gnupg"),
    }
}

/// Detect if a hardware key is present and get its info
pub fn detect_hwkey() -> Result<Option<HwKeyInfo>> {
    check_gpg()?;

    let output = Command::new("gpg")
        .args(["--card-status"])
        .output()
        .context("Failed to run gpg --card-status")?;

    if !output.status.success() {
        // No card present or error
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse card info
    let serial = extract_field(&stdout, "Serial number")
        .unwrap_or_else(|| "unknown".to_string());
    let card_type = extract_field(&stdout, "Application type")
        .unwrap_or_else(|| "OpenPGP".to_string());

    // Try to get the signing key fingerprint
    let fingerprint = extract_field(&stdout, "Signature key");
    let key_id = fingerprint.as_ref().map(|fp| {
        // Last 16 chars of fingerprint is the key ID
        if fp.len() >= 16 {
            fp[fp.len() - 16..].to_string()
        } else {
            fp.clone()
        }
    });

    Ok(Some(HwKeyInfo {
        serial,
        card_type,
        key_id,
        fingerprint,
    }))
}

/// Extract a field value from gpg --card-status output
fn extract_field(output: &str, field_name: &str) -> Option<String> {
    for line in output.lines() {
        if line.contains(field_name) {
            // Format is typically "Field name ....: value"
            if let Some(pos) = line.find(':') {
                let value = line[pos + 1..].trim();
                // Remove any trailing info and clean up
                let value = value.split_whitespace().next().unwrap_or(value);
                if !value.is_empty() && value != "[none]" {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// Get the Ed25519 public key from hardware key in hex format
pub fn get_hwkey_pubkey() -> Result<String> {
    let info = detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    let key_id = info.key_id
        .ok_or_else(|| anyhow::anyhow!("No signing key found on hardware key. Generate one first."))?;

    // Export the public key
    let output = Command::new("gpg")
        .args(["--export", "--armor", &key_id])
        .output()
        .context("Failed to export public key")?;

    if !output.status.success() {
        bail!("Failed to export public key: {}", String::from_utf8_lossy(&output.stderr));
    }

    // The GPG armor format is complex - for Ed25519, we need to extract the raw key
    // For simplicity, we'll store the full GPG key ID and use GPG for verification
    Ok(key_id)
}

/// Sign data using hardware key via GPG
/// Returns the signature in hex format
pub fn sign_with_hwkey(data: &[u8], key_id: &str) -> Result<String> {
    check_gpg()?;

    // Verify hardware key is present
    let info = detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected. Insert hardware key and try again."))?;

    println!("{}", style(format!("  Hardware key detected: Serial {}", info.serial)).dim());

    // Create temp file for data
    let temp_dir = std::env::temp_dir();
    let data_path = temp_dir.join("la_propaganda_sign_data");
    let sig_path = temp_dir.join("la_propaganda_sign_data.sig");

    // Clean up any existing files
    let _ = std::fs::remove_file(&data_path);
    let _ = std::fs::remove_file(&sig_path);

    std::fs::write(&data_path, data)
        .context("Failed to write data for signing")?;

    println!("{}", style("  Touch hardware key to sign...").yellow().bold());

    // Sign with GPG (detached binary signature)
    let output = Command::new("gpg")
        .args([
            "--detach-sign",
            "--local-user", key_id,
            "--output", sig_path.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .stdin(Stdio::inherit())  // Allow PIN entry
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("Failed to run GPG sign command")?;

    // Clean up data file
    let _ = std::fs::remove_file(&data_path);

    if !output.success() {
        let _ = std::fs::remove_file(&sig_path);
        bail!("GPG signing failed. Make sure you entered the correct PIN and touched the hardware key.");
    }

    // Read signature
    let signature = std::fs::read(&sig_path)
        .context("Failed to read signature file")?;

    // Clean up
    let _ = std::fs::remove_file(&sig_path);

    // Return signature as hex
    Ok(hex::encode(signature))
}

/// Verify a GPG signature
pub fn verify_gpg_signature(data: &[u8], signature_hex: &str, _key_id: &str) -> Result<()> {
    check_gpg()?;

    let signature = hex::decode(signature_hex)
        .context("Invalid signature hex")?;

    let temp_dir = std::env::temp_dir();
    let data_path = temp_dir.join("la_propaganda_verify_data");
    let sig_path = temp_dir.join("la_propaganda_verify_data.sig");

    std::fs::write(&data_path, data)?;
    std::fs::write(&sig_path, &signature)?;

    let output = Command::new("gpg")
        .args([
            "--verify",
            sig_path.to_str().unwrap(),
            data_path.to_str().unwrap(),
        ])
        .output()
        .context("Failed to run GPG verify")?;

    // Clean up
    let _ = std::fs::remove_file(&data_path);
    let _ = std::fs::remove_file(&sig_path);

    if !output.status.success() {
        bail!("Signature verification failed");
    }

    Ok(())
}

/// Wait for user to press Enter
pub fn wait_for_enter() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(())
}

/// Perform single hardware key signing (for routine governance operations)
pub fn single_sign(data: &[u8], expected_key_ids: &[&str]) -> Result<SingleSignature> {
    println!();
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!("{}", style("              OWNER AUTHORITY OPERATION").cyan().bold());
    println!("{}", style("       Single hardware key required for this action").cyan());
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!();

    println!("{}", style("Insert either hardware key (Primary or Backup) and press Enter...").cyan());
    wait_for_enter()?;

    let info = detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected. Insert your hardware key."))?;

    let detected_key_id = info.key_id.clone()
        .ok_or_else(|| anyhow::anyhow!("No signing key found on this hardware key."))?;

    // Verify it's one of the expected keys
    let is_valid = expected_key_ids.iter().any(|expected| {
        detected_key_id.contains(expected) || expected.contains(&detected_key_id)
    });

    if !is_valid && !expected_key_ids.is_empty() && !expected_key_ids[0].is_empty() {
        println!("{}", style(format!("  Warning: Detected key {} may not match registered owner keys", detected_key_id)).yellow());
    }

    let signature = sign_with_hwkey(data, &detected_key_id)?;
    let timestamp = chrono::Utc::now().to_rfc3339();

    println!("{}", style("  ✓ Signature obtained").green());

    Ok(SingleSignature {
        signature,
        key_id: detected_key_id,
        timestamp,
        hwkey_serial: info.serial,
    })
}

/// Perform dual hardware key signing (requires both primary and backup keys)
/// Used ONLY for key rotation/recovery operations.
pub fn dual_sign(data: &[u8], primary_key_id: &str, backup_key_id: &str) -> Result<DualSignature> {
    println!();
    println!("{}", style("═══════════════════════════════════════════════════════════════").yellow());
    println!("{}", style("              KEY MANAGEMENT OPERATION").yellow().bold());
    println!("{}", style("     Both hardware keys required for this action").yellow());
    println!("{}", style("═══════════════════════════════════════════════════════════════").yellow());
    println!();

    // Step 1: Sign with Primary hardware key
    println!("{}", style("Step 1/2: Insert PRIMARY hardware key").cyan().bold());
    println!("         Key ID: {}", style(primary_key_id).dim());
    println!("         Press Enter when ready...");
    wait_for_enter()?;

    let info = detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected. Insert PRIMARY hardware key."))?;

    // Verify it's the expected key (if we have the info)
    if let Some(ref detected_id) = info.key_id {
        if !detected_id.contains(primary_key_id) && !primary_key_id.contains(detected_id) {
            println!("{}", style(format!("  Warning: Detected key {} may not match expected {}", detected_id, primary_key_id)).yellow());
        }
    }

    let primary_signature = sign_with_hwkey(data, primary_key_id)?;
    let primary_timestamp = chrono::Utc::now().to_rfc3339();
    println!("{}", style("  ✓ Primary signature obtained").green());

    // Step 2: Sign with Backup hardware key
    println!();
    println!("{}", style("Step 2/2: REMOVE Primary hardware key").cyan().bold());
    println!("         INSERT BACKUP hardware key");
    println!("         Key ID: {}", style(backup_key_id).dim());
    println!("         Press Enter when ready...");
    wait_for_enter()?;

    // Verify a different hardware key is now present
    let info2 = detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected. Insert BACKUP hardware key."))?;

    if info2.serial == info.serial {
        bail!("Same hardware key detected (serial: {}). You must insert the BACKUP hardware key.", info.serial);
    }

    let backup_signature = sign_with_hwkey(data, backup_key_id)?;
    let backup_timestamp = chrono::Utc::now().to_rfc3339();
    println!("{}", style("  ✓ Backup signature obtained").green());

    println!();
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!("{}", style("        ✅ DUAL-SIGNATURE COMPLETE").green().bold());
    println!("{}", style("           Owner authority verified").green());
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());

    Ok(DualSignature {
        primary_signature,
        primary_key_id: primary_key_id.to_string(),
        primary_timestamp,
        backup_signature,
        backup_key_id: backup_key_id.to_string(),
        backup_timestamp,
    })
}

/// Initialize a new Ed25519 key on the hardware key
/// This generates the key directly on the secure element (key never leaves device)
pub fn generate_key_on_hwkey() -> Result<String> {
    check_gpg()?;

    let info = detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    println!("{}", style(format!("Detected hardware key: Serial {}", info.serial)).cyan());

    if info.key_id.is_some() {
        bail!("This hardware key already has a signing key. Use a fresh key or reset it first.");
    }

    println!();
    println!("{}", style("Generating Ed25519 key on hardware key...").yellow());
    println!("{}", style("This will require setting a PIN and Admin PIN.").dim());
    println!();

    // For key generation, we need to use gpg --card-edit interactively
    // This is complex to automate, so we'll guide the user
    println!("{}", style("Please run the following commands manually:").yellow().bold());
    println!();
    println!("  gpg --card-edit");
    println!("  > admin");
    println!("  > generate");
    println!("  > (follow prompts to generate Ed25519 key)");
    println!("  > quit");
    println!();
    println!("After generation, run this command again to retrieve the key ID.");

    bail!("Manual key generation required. See instructions above.");
}

/// Display hardware key status
pub fn print_hwkey_status() -> Result<()> {
    check_gpg()?;

    match detect_hwkey()? {
        Some(info) => {
            println!("{}", style("Hardware Key Status").cyan().bold());
            println!("  Card Type:    {}", info.card_type);
            println!("  Serial:       {}", info.serial);
            match &info.key_id {
                Some(id) => println!("  Signing Key:  {}", id),
                None => println!("  Signing Key:  {}", style("Not configured").yellow()),
            }
            if let Some(fp) = &info.fingerprint {
                println!("  Fingerprint:  {}", fp);
            }
        }
        None => {
            println!("{}", style("No hardware key detected").yellow());
            println!("Insert a hardware key and try again.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_field() {
        let output = r#"
Reader ...........: Generic Smart Card Reader
Application ID ...: D2760001240100000006123456780000
Application type .: OpenPGP
Version ..........: 3.4
Serial number ....: 12345678
Name of cardholder: [not set]
"#;
        assert_eq!(extract_field(output, "Serial number"), Some("12345678".to_string()));
        assert_eq!(extract_field(output, "Application type"), Some("OpenPGP".to_string()));
    }
}
