//! Key management for MCP signing server
//!
//! Loads private keys from existing .authors/ and .editorial_board/board/ directories.

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

/// Metadata about an identity
#[derive(Debug, Clone)]
pub struct IdentityInfo {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    pub role: Option<String>,
    pub pubkey: String,
    pub key_type: KeyType,
}

/// Key store that holds loaded signing keys
pub struct KeyStore {
    /// Loaded signing keys indexed by identity ID
    keys: HashMap<String, SigningKey>,
    /// Identity metadata indexed by ID
    identities: HashMap<String, IdentityInfo>,
}

impl KeyStore {
    /// Create a new empty key store
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            identities: HashMap::new(),
        }
    }

    /// Load all keys from .authors/ and .editorial_board/board/ directories
    pub fn load_all(&mut self, base_path: &Path) -> Result<()> {
        let authors_dir = base_path.join(".authors");
        let board_dir = base_path.join(".editorial_board/board");

        // Load authors
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

                if key_path.exists() {
                    match self.load_identity(&id, entry.path(), key_type) {
                        Ok(()) => {
                            tracing::info!(id = %id, key_type = ?key_type, "Loaded identity");
                        }
                        Err(e) => {
                            tracing::warn!(id = %id, error = %e, "Failed to load identity");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Load a single identity
    fn load_identity(&mut self, id: &str, dir: &Path, key_type: KeyType) -> Result<()> {
        // Load private key
        let key_path = dir.join("private_key.secret");
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

        // Load metadata
        let info_path = match key_type {
            KeyType::Author => dir.join("author.info"),
            KeyType::BoardMember => dir.join("member.info"),
        };

        let (name, email, role) = if info_path.exists() {
            parse_info_file(&info_path, key_type)?
        } else {
            (id.to_string(), None, None)
        };

        // Store
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
        self.keys.contains_key(id)
    }
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse an author.info or member.info file
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

            match key_type {
                KeyType::Author => {
                    if let Some(value) = line.strip_prefix("Author:") {
                        name = value.trim().to_string();
                    } else if let Some(value) = line.strip_prefix("Email:") {
                        let v = value.trim();
                        if v != "N/A" {
                            email = Some(v.to_string());
                        }
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
