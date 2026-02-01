//! Key management for MCP signing server
//!
//! Loads private keys from existing .authors/ and .editorial_board/board/ directories.
//! Supports hierarchical identity model with delegation:
//!   - Primary identities (authors with hardware or software keys)
//!   - Delegated identities (devices/bots authorized by a primary)

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use std::path::Path;
use walkdir::WalkDir;

/// Type of identity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Author,
    BoardMember,
}

/// Type of delegated identity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegateType {
    /// Another device owned by the same person (laptop, phone, etc.)
    Device,
    /// A bot/agent acting on behalf of the person
    Bot,
}

/// Information about a delegation certificate
#[derive(Debug, Clone)]
pub struct DelegationInfo {
    /// Delegate's ID (unique within primary's delegates)
    pub delegate_id: String,
    /// Delegate's public key (hex)
    pub delegate_pubkey: String,
    /// Primary identity ID that issued the delegation
    pub primary_id: String,
    /// Primary identity's public key (hex)
    pub primary_pubkey: String,
    /// Type of delegate
    pub delegate_type: DelegateType,
    /// When the delegation was created
    pub created: String,
    /// When the delegation expires (None = never)
    pub expires: Option<String>,
    /// Whether delegation is still active (not revoked)
    pub active: bool,
}

/// Metadata about an identity
#[derive(Debug, Clone)]
pub struct IdentityInfo {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub role: Option<String>,
    pub pubkey: String,
    pub key_type: KeyType,
    /// If this is a delegated identity, contains delegation info
    pub delegation: Option<DelegationInfo>,
}

/// Key store that holds loaded signing keys
pub struct KeyStore {
    /// Loaded signing keys indexed by identity ID
    keys: HashMap<String, SigningKey>,
    /// Identity metadata indexed by ID
    identities: HashMap<String, IdentityInfo>,
    /// Delegations indexed by "primary_id/delegate_id"
    delegations: HashMap<String, DelegationInfo>,
}

impl KeyStore {
    /// Create a new empty key store
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            identities: HashMap::new(),
            delegations: HashMap::new(),
        }
    }

    /// Load all keys from .authors/ and .editorial_board/board/ directories
    pub fn load_all(&mut self, base_path: &Path) -> Result<()> {
        let authors_dir = base_path.join(".authors");
        let board_dir = base_path.join(".editorial_board/board");

        // Load authors (including their delegates)
        if authors_dir.exists() {
            self.load_from_directory(&authors_dir, KeyType::Author)?;
        }

        // Load board members
        if board_dir.exists() {
            self.load_from_directory(&board_dir, KeyType::BoardMember)?;
        }

        Ok(())
    }

    /// Load keys from a directory
    fn load_from_directory(&mut self, dir: &Path, key_type: KeyType) -> Result<()> {
        for entry in WalkDir::new(dir).min_depth(1).max_depth(1) {
            let entry = entry?;
            if entry.file_type().is_dir() {
                let id = entry.file_name().to_string_lossy().to_string();
                let key_path = entry.path().join("private_key.secret");

                // Check for private key OR hardware key (no private key but has author.info)
                let info_path = entry.path().join("author.info");
                let has_key_or_hardware = key_path.exists() || info_path.exists();

                if has_key_or_hardware {
                    match self.load_identity(&id, entry.path(), key_type, None) {
                        Ok(()) => {
                            tracing::info!(id = %id, key_type = ?key_type, "Loaded identity");
                        }
                        Err(e) => {
                            tracing::warn!(id = %id, error = %e, "Failed to load identity");
                        }
                    }
                }

                // Load delegates for authors
                if key_type == KeyType::Author {
                    let delegates_dir = entry.path().join("delegates");
                    if delegates_dir.exists() {
                        self.load_delegates(&id, &delegates_dir)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Load delegated identities from an author's delegates directory
    fn load_delegates(&mut self, primary_id: &str, delegates_dir: &Path) -> Result<()> {
        for entry in WalkDir::new(delegates_dir).min_depth(1).max_depth(1) {
            let entry = entry?;
            if entry.file_type().is_dir() {
                let delegate_id = entry.file_name().to_string_lossy().to_string();
                let key_path = entry.path().join("private_key.secret");
                let cert_path = entry.path().join("delegation.cert");

                // Must have both private key and delegation certificate
                if key_path.exists() && cert_path.exists() {
                    // Parse delegation certificate
                    if let Ok(delegation) = self.parse_delegation_cert(&cert_path, primary_id) {
                        if delegation.active {
                            // Check expiration
                            let expired = delegation.expires.as_ref().map_or(false, |exp| {
                                chrono::DateTime::parse_from_rfc3339(exp)
                                    .map(|dt| dt < chrono::Utc::now())
                                    .unwrap_or(false)
                            });

                            if !expired {
                                // Load as a signing identity with delegation context
                                let full_id = format!("{}/{}", primary_id, delegate_id);
                                match self.load_identity(&full_id, entry.path(), KeyType::Author, Some(delegation.clone())) {
                                    Ok(()) => {
                                        // Store delegation
                                        self.delegations.insert(full_id.clone(), delegation);
                                        tracing::info!(
                                            delegate = %delegate_id,
                                            primary = %primary_id,
                                            "Loaded delegated identity"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            delegate = %delegate_id,
                                            primary = %primary_id,
                                            error = %e,
                                            "Failed to load delegated identity"
                                        );
                                    }
                                }
                            } else {
                                tracing::info!(
                                    delegate = %delegate_id,
                                    primary = %primary_id,
                                    "Skipping expired delegation"
                                );
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Parse a delegation certificate file
    fn parse_delegation_cert(&self, cert_path: &Path, primary_id: &str) -> Result<DelegationInfo> {
        let content = std::fs::read_to_string(cert_path)?;
        let cert: toml::Value = toml::from_str(&content)?;

        let delegation = cert.get("delegation")
            .ok_or_else(|| anyhow::anyhow!("Missing [delegation] section"))?;

        let delegate_id = delegation.get("delegate_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing delegate_id"))?
            .to_string();

        let delegate_pubkey = delegation.get("delegate_pubkey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing delegate_pubkey"))?
            .to_string();

        let primary_pubkey = delegation.get("primary_pubkey")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing primary_pubkey"))?
            .to_string();

        let delegate_type_str = delegation.get("delegate_type")
            .and_then(|v| v.as_str())
            .unwrap_or("bot");
        let delegate_type = match delegate_type_str {
            "device" => DelegateType::Device,
            _ => DelegateType::Bot,
        };

        let created = delegation.get("created")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let expires = delegation.get("expires")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let active = delegation.get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        Ok(DelegationInfo {
            delegate_id,
            delegate_pubkey,
            primary_id: primary_id.to_string(),
            primary_pubkey,
            delegate_type,
            created,
            expires,
            active,
        })
    }

    /// Load a single identity
    fn load_identity(
        &mut self,
        id: &str,
        dir: &Path,
        key_type: KeyType,
        delegation: Option<DelegationInfo>,
    ) -> Result<()> {
        // Load private key (if present - hardware keys don't have one)
        let key_path = dir.join("private_key.secret");
        let (signing_key, pubkey) = if key_path.exists() {
            let key_hex = std::fs::read_to_string(&key_path)
                .context("Failed to read private key")?;
            let key_bytes = hex::decode(key_hex.trim())
                .context("Failed to decode private key hex")?;
            let key_array: [u8; 32] = key_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Private key must be 32 bytes"))?;
            let signing_key = SigningKey::from_bytes(&key_array);
            let verifying_key = signing_key.verifying_key();
            let pubkey = hex::encode(verifying_key.to_bytes());
            (Some(signing_key), pubkey)
        } else {
            // Hardware key - get pubkey from info file or delegation
            let pubkey = delegation
                .as_ref()
                .map(|d| d.delegate_pubkey.clone())
                .or_else(|| parse_pubkey_from_info(dir, key_type).ok())
                .ok_or_else(|| anyhow::anyhow!("No private key and no pubkey in metadata"))?;
            (None, pubkey)
        };

        // Determine info file path based on whether this is a delegate
        let info_path = if delegation.is_some() {
            dir.join("delegate.info")
        } else {
            match key_type {
                KeyType::Author => dir.join("author.info"),
                KeyType::BoardMember => dir.join("member.info"),
            }
        };

        let (name, email, role) = if info_path.exists() {
            parse_info_file(&info_path, key_type)?
        } else {
            (id.to_string(), None, None)
        };

        // Store signing key if available
        if let Some(sk) = signing_key {
            self.keys.insert(id.to_string(), sk);
        }

        self.identities.insert(
            id.to_string(),
            IdentityInfo {
                id: id.to_string(),
                name,
                email,
                role,
                pubkey,
                key_type,
                delegation,
            },
        );

        Ok(())
    }

    /// Get a signing key by ID
    pub fn get_signing_key(&self, id: &str) -> Option<&SigningKey> {
        self.keys.get(id)
    }

    /// Get identity metadata by ID
    pub fn get_identity(&self, id: &str) -> Option<&IdentityInfo> {
        self.identities.get(id)
    }

    /// List all identities, optionally filtered by type
    pub fn list_identities(&self, filter: Option<KeyType>) -> Vec<&IdentityInfo> {
        self.identities
            .values()
            .filter(|info| filter.map_or(true, |t| info.key_type == t))
            .collect()
    }

    /// Check if an identity exists
    pub fn has_identity(&self, id: &str) -> bool {
        self.identities.contains_key(id)
    }

    /// Check if an identity has a signing key (false for hardware keys)
    pub fn has_signing_key(&self, id: &str) -> bool {
        self.keys.contains_key(id)
    }

    /// Register a new identity dynamically (used by MCP key generation tools)
    pub fn register_identity(
        &mut self,
        id: &str,
        signing_key: SigningKey,
        name: String,
        email: Option<String>,
        role: Option<String>,
        key_type: KeyType,
    ) {
        let verifying_key = signing_key.verifying_key();
        let pubkey = hex::encode(verifying_key.to_bytes());

        self.keys.insert(id.to_string(), signing_key);
        self.identities.insert(
            id.to_string(),
            IdentityInfo {
                id: id.to_string(),
                name,
                email,
                role,
                pubkey,
                key_type,
                delegation: None,
            },
        );
    }

    /// Register a delegated identity
    pub fn register_delegation(
        &mut self,
        primary_id: &str,
        delegate_id: &str,
        signing_key: SigningKey,
        name: String,
        delegation_info: DelegationInfo,
    ) {
        let full_id = format!("{}/{}", primary_id, delegate_id);
        let verifying_key = signing_key.verifying_key();
        let pubkey = hex::encode(verifying_key.to_bytes());

        self.keys.insert(full_id.clone(), signing_key);
        self.delegations.insert(full_id.clone(), delegation_info.clone());
        self.identities.insert(
            full_id,
            IdentityInfo {
                id: delegate_id.to_string(),
                name,
                email: None,
                role: None,
                pubkey,
                key_type: KeyType::Author,
                delegation: Some(delegation_info),
            },
        );
    }

    /// List all delegations for a primary identity
    pub fn list_delegations(&self, primary_id: &str) -> Vec<&DelegationInfo> {
        self.delegations
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("{}/", primary_id)))
            .map(|(_, v)| v)
            .collect()
    }

    /// Get a delegation by full ID (primary_id/delegate_id)
    pub fn get_delegation(&self, full_id: &str) -> Option<&DelegationInfo> {
        self.delegations.get(full_id)
    }

    /// Revoke a delegation (marks as inactive)
    pub fn revoke_delegation(&mut self, full_id: &str) -> bool {
        if let Some(delegation) = self.delegations.get_mut(full_id) {
            delegation.active = false;
            // Remove signing key access
            self.keys.remove(full_id);
            true
        } else {
            false
        }
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse an author.info, member.info, or delegate.info file
fn parse_info_file(
    path: &Path,
    key_type: KeyType,
) -> Result<(String, Option<String>, Option<String>)> {
    let content = std::fs::read_to_string(path)?;
    let mut name = String::new();
    let mut email = None;
    let mut role = None;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            let line = line.trim_start_matches('#').trim();

            // Common fields
            if let Some(value) = line.strip_prefix("Email:") {
                let v = value.trim();
                if v != "N/A" {
                    email = Some(v.to_string());
                }
            }

            // Delegate-specific
            if let Some(value) = line.strip_prefix("Delegate:") {
                name = value.trim().to_string();
            }

            match key_type {
                KeyType::Author => {
                    if let Some(value) = line.strip_prefix("Author:") {
                        name = value.trim().to_string();
                    }
                }
                KeyType::BoardMember => {
                    if let Some(value) = line.strip_prefix("Board Member:") {
                        name = value.trim().to_string();
                    } else if let Some(value) = line.strip_prefix("Role:") {
                        role = Some(value.trim().to_string());
                    }
                }
            }
        }
    }

    Ok((name, email, role))
}

/// Extract public key from info file (for hardware keys that don't have private_key.secret)
fn parse_pubkey_from_info(dir: &Path, key_type: KeyType) -> Result<String> {
    let info_path = match key_type {
        KeyType::Author => dir.join("author.info"),
        KeyType::BoardMember => dir.join("member.info"),
    };

    let content = std::fs::read_to_string(&info_path)?;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            let line = line.trim_start_matches('#').trim();
            if let Some(value) = line.strip_prefix("Public Key:") {
                return Ok(value.trim().to_string());
            }
        }
    }
    Err(anyhow::anyhow!("No public key found in info file"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_key_store_load() {
        // Create temp directory with test author
        let temp_dir = TempDir::new().unwrap();
        let authors_dir = temp_dir.path().join(".authors/test-author");
        fs::create_dir_all(&authors_dir).unwrap();

        // Generate test key
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        fs::write(
            authors_dir.join("private_key.secret"),
            hex::encode(signing_key.to_bytes()),
        )
        .unwrap();

        fs::write(
            authors_dir.join("author.info"),
            "# Author: Test Author\n# ID: test-author\n# Email: test@example.com\n",
        )
        .unwrap();

        // Load
        let mut store = KeyStore::new();
        store.load_all(temp_dir.path()).unwrap();

        assert!(store.has_identity("test-author"));
        let info = store.get_identity("test-author").unwrap();
        assert_eq!(info.name, "Test Author");
        assert_eq!(info.email.as_deref(), Some("test@example.com"));
    }
}
