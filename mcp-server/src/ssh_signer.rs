//! SSH agent signing for hardware keys (YubiKey/FIDO2)
//!
//! This module provides SSH agent integration for signing with hardware
//! security keys. When a human uses Claude Desktop with a YubiKey, the
//! AI can request signatures via the SSH agent, prompting the user to
//! touch their hardware key.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use ssh_agent_client_rs::Client as SshAgentClient;
use std::env;
use std::path::Path;

/// Sign data using SSH agent (prompts for YubiKey touch for SK keys)
///
/// # Arguments
/// * `pubkey_hex` - The Ed25519 public key (hex encoded, 64 chars)
/// * `data` - The data to sign (typically a hash hex string)
///
/// # Returns
/// The Ed25519 signature as hex string (128 chars)
pub fn sign_with_ssh_agent(pubkey_hex: &str, data: &[u8]) -> Result<String> {
    let socket_path = env::var("SSH_AUTH_SOCK")
        .context("SSH_AUTH_SOCK not set. Ensure ssh-agent is running and key is loaded.")?;

    let pubkey_bytes = hex::decode(pubkey_hex).context("Invalid pubkey hex")?;

    if pubkey_bytes.len() != 32 {
        bail!(
            "Expected 32-byte Ed25519 pubkey, got {} bytes",
            pubkey_bytes.len()
        );
    }

    // Connect to SSH agent
    let socket_path = Path::new(&socket_path);
    let mut client =
        SshAgentClient::connect(socket_path).context("Failed to connect to SSH agent")?;

    // List keys and find the matching one
    let keys = client
        .list_identities()
        .context("Failed to list SSH agent keys")?;

    let matching_key = keys
        .iter()
        .find(|k| {
            // Try to extract Ed25519 pubkey and compare
            extract_ed25519_pubkey_from_key(k) == Some(pubkey_bytes.clone())
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Hardware key not found in ssh-agent. Run: ssh-add -l\n\
             Expected pubkey: {}...",
                &pubkey_hex[..16]
            )
        })?;

    eprintln!(
        "[SSH AGENT] Requesting signature for key: {}",
        matching_key.comment()
    );
    eprintln!("[SSH AGENT] Touch your YubiKey/hardware key if prompted...");

    // Request signature
    let response = client
        .sign(matching_key, Bytes::copy_from_slice(data))
        .context("SSH agent signing failed. Did you touch your hardware key?")?;

    // Get the raw signature bytes
    let sig_bytes = response.as_bytes();

    // For Ed25519, the signature should be 64 bytes
    if sig_bytes.len() != 64 {
        bail!(
            "Expected 64-byte Ed25519 signature, got {} bytes",
            sig_bytes.len()
        );
    }

    Ok(hex::encode(sig_bytes))
}

/// Extract 32-byte Ed25519 pubkey from an SSH public key
fn extract_ed25519_pubkey_from_key(key: &ssh_key::PublicKey) -> Option<Vec<u8>> {
    // Get the key data
    use ssh_key::Algorithm;

    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::SkEd25519 => {
            // Try to get the Ed25519-specific data
            if let ssh_key::public::KeyData::Ed25519(ed_key) = key.key_data() {
                Some(ed_key.as_ref().to_vec())
            } else if let ssh_key::public::KeyData::SkEd25519(sk_key) = key.key_data() {
                Some(sk_key.public_key().as_ref().to_vec())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Check if SSH agent is available
pub fn is_ssh_agent_available() -> bool {
    env::var("SSH_AUTH_SOCK").is_ok()
}

/// List available Ed25519 keys in SSH agent
pub fn list_ssh_keys() -> Result<Vec<SshKeyInfo>> {
    let socket_path = env::var("SSH_AUTH_SOCK").context("SSH_AUTH_SOCK not set")?;

    let socket_path = Path::new(&socket_path);
    let mut client =
        SshAgentClient::connect(socket_path).context("Failed to connect to SSH agent")?;

    let keys = client.list_identities().context("Failed to list keys")?;

    let mut result = Vec::new();
    for key in keys {
        if let Some(pubkey) = extract_ed25519_pubkey_from_key(&key) {
            use ssh_key::Algorithm;
            let is_sk = matches!(key.algorithm(), Algorithm::SkEd25519);
            let key_type = format!("{:?}", key.algorithm());

            result.push(SshKeyInfo {
                pubkey_hex: hex::encode(&pubkey),
                comment: key.comment().to_string(),
                is_sk,
                key_type,
            });
        }
    }

    Ok(result)
}

/// Information about an SSH key
#[derive(Debug, Clone)]
pub struct SshKeyInfo {
    /// Ed25519 public key as hex (64 chars)
    pub pubkey_hex: String,
    /// Key comment (usually email or description)
    pub comment: String,
    /// Whether this is a FIDO2/SK key (requires touch)
    pub is_sk: bool,
    /// Original key type (e.g., "SkEd25519")
    pub key_type: String,
}
