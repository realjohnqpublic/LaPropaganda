//! Configuration file management with safe TOML updates
//!
//! This module provides helpers for reading and updating TOML configuration
//! files while preserving comments and formatting.

use anyhow::{bail, Context, Result};
use regex::Regex;
use std::path::Path;
use toml_edit::{value, DocumentMut, Item};

use crate::types::Config;

/// Load and parse config.toml
pub fn load_config(config_path: &Path) -> Result<Config> {
    let content = std::fs::read_to_string(config_path)
        .context("Failed to read config.toml")?;
    let config: Config = toml::from_str(&content)
        .context("Failed to parse config.toml")?;
    Ok(config)
}

/// Load config.toml as a toml_edit DocumentMut for safe updates
pub fn load_config_document(config_path: &Path) -> Result<DocumentMut> {
    let content = std::fs::read_to_string(config_path)
        .context("Failed to read config.toml")?;
    let doc = content.parse::<DocumentMut>()
        .context("Failed to parse config.toml as document")?;
    Ok(doc)
}

/// Save a toml_edit DocumentMut back to file
pub fn save_config_document(config_path: &Path, doc: &DocumentMut) -> Result<()> {
    std::fs::write(config_path, doc.to_string())
        .context("Failed to write config.toml")?;
    Ok(())
}

/// Update a simple string field in config.toml
///
/// # Arguments
/// * `config_path` - Path to config.toml
/// * `section` - Section name (e.g., "extra")
/// * `field` - Field name within the section
/// * `new_value` - New value to set
pub fn update_config_field(config_path: &Path, section: &str, field: &str, new_value: &str) -> Result<()> {
    let mut doc = load_config_document(config_path)?;

    if let Some(section_item) = doc.get_mut(section) {
        if let Some(table) = section_item.as_table_mut() {
            table[field] = value(new_value);
        } else {
            bail!("Section '{}' is not a table", section);
        }
    } else {
        bail!("Section '{}' not found in config.toml", section);
    }

    save_config_document(config_path, &doc)
}

/// Update a nested field in config.toml (e.g., extra.owner.primary_pubkey)
pub fn update_nested_field(config_path: &Path, path: &[&str], new_value: &str) -> Result<()> {
    if path.is_empty() {
        bail!("Field path cannot be empty");
    }

    let mut doc = load_config_document(config_path)?;

    let mut current: &mut Item = doc.as_item_mut();
    for (i, key) in path.iter().enumerate() {
        if i == path.len() - 1 {
            // Last element - set the value
            if let Some(table) = current.as_table_mut() {
                table[*key] = value(new_value);
            } else {
                bail!("Parent of '{}' is not a table", key);
            }
        } else {
            // Navigate deeper
            current = current.get_mut(*key)
                .ok_or_else(|| anyhow::anyhow!("Key '{}' not found", key))?;
        }
    }

    save_config_document(config_path, &doc)
}

/// Update a boolean field in config.toml
pub fn update_bool_field(config_path: &Path, path: &[&str], new_value: bool) -> Result<()> {
    if path.is_empty() {
        bail!("Field path cannot be empty");
    }

    let mut doc = load_config_document(config_path)?;

    let mut current: &mut Item = doc.as_item_mut();
    for (i, key) in path.iter().enumerate() {
        if i == path.len() - 1 {
            if let Some(table) = current.as_table_mut() {
                table[*key] = value(new_value);
            } else {
                bail!("Parent of '{}' is not a table", key);
            }
        } else {
            current = current.get_mut(*key)
                .ok_or_else(|| anyhow::anyhow!("Key '{}' not found", key))?;
        }
    }

    save_config_document(config_path, &doc)
}



/// Update a board member's field (e.g., active status or pubkey)
pub fn update_board_member_field(
    config_path: &Path,
    member_id: &str,
    field: &str,
    new_value: &str,
) -> Result<()> {
    let mut doc = load_config_document(config_path)?;

    let members = doc
        .get_mut("extra")
        .and_then(|e| e.get_mut("editorial_board"))
        .and_then(|b| b.get_mut("members"))
        .and_then(|m| m.as_array_of_tables_mut())
        .ok_or_else(|| anyhow::anyhow!("Could not find editorial_board.members"))?;

    let mut found = false;
    for member in members.iter_mut() {
        if let Some(id) = member.get("id").and_then(|v| v.as_str()) {
            if id == member_id {
                member[field] = value(new_value);
                found = true;
                break;
            }
        }
    }

    if !found {
        bail!("Board member '{}' not found", member_id);
    }

    save_config_document(config_path, &doc)
}

/// Update a board member's boolean field (e.g., active)
pub fn update_board_member_bool(
    config_path: &Path,
    member_id: &str,
    field: &str,
    new_value: bool,
) -> Result<()> {
    let mut doc = load_config_document(config_path)?;

    let members = doc
        .get_mut("extra")
        .and_then(|e| e.get_mut("editorial_board"))
        .and_then(|b| b.get_mut("members"))
        .and_then(|m| m.as_array_of_tables_mut())
        .ok_or_else(|| anyhow::anyhow!("Could not find editorial_board.members"))?;

    let mut found = false;
    for member in members.iter_mut() {
        if let Some(id) = member.get("id").and_then(|v| v.as_str()) {
            if id == member_id {
                member[field] = value(new_value);
                found = true;
                break;
            }
        }
    }

    if !found {
        bail!("Board member '{}' not found", member_id);
    }

    save_config_document(config_path, &doc)
}

/// Update the editorial board threshold
pub fn update_board_threshold(config_path: &Path, threshold: i64) -> Result<()> {
    let mut doc = load_config_document(config_path)?;

    if let Some(board) = doc
        .get_mut("extra")
        .and_then(|e| e.get_mut("editorial_board"))
        .and_then(|b| b.as_table_mut())
    {
        board["threshold"] = value(threshold);
    } else {
        bail!("Could not find [extra.editorial_board]");
    }

    save_config_document(config_path, &doc)
}

/// Update last_modified in editorial_board
pub fn update_last_modified(config_path: &Path, date: &str) -> Result<()> {
    let mut doc = load_config_document(config_path)?;

    if let Some(board) = doc
        .get_mut("extra")
        .and_then(|e| e.get_mut("editorial_board"))
        .and_then(|b| b.as_table_mut())
    {
        board["last_modified"] = value(date);
    } else {
        bail!("Could not find [extra.editorial_board]");
    }

    save_config_document(config_path, &doc)
}

/// Append a new board member to config.toml
pub fn append_board_member(
    config_path: &Path,
    id: &str,
    name: &str,
    member_type: &str,
    role: &str,
    pubkey: &str,
    appointed: &str,
) -> Result<()> {
    // For appending array items, we'll use the raw file approach since toml_edit
    // has complex handling for array of tables
    let mut content = std::fs::read_to_string(config_path)?;

    let new_member = format!(r#"

[[extra.editorial_board.members]]
id = "{}"
name = "{}"
type = "{}"
role = "{}"
pubkey = "{}"
active = true
appointed = "{}"
appointed_by = "owner""#,
        id, name, member_type, role, pubkey, appointed
    );

    content.push_str(&new_member);
    std::fs::write(config_path, content)?;

    Ok(())
}

/// Validate ID/slug format for security
pub fn validate_slug(slug: &str) -> Result<()> {
    if slug.trim().is_empty() {
        bail!("ID cannot be empty");
    }

    // Strict validation: only lowercase alphanumeric and hyphens
    let re = Regex::new(r"^[a-z0-9-]+$").unwrap();
    if !re.is_match(slug) {
        bail!("ID must consist of only lowercase alphanumeric characters and hyphens (got: '{}')", slug);
    }

    // Double check for path traversal patterns
    if slug.contains("..") || slug.contains('/') || slug.contains('\\') {
        bail!("Path traversal detected in ID");
    }

    Ok(())
}

/// Load owner keys from config
pub fn load_owner_keys(config: &Config) -> Result<(String, String)> {
    let owner = config.extra.owner.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Owner configuration not found"))?;

    let initialized = owner.initialized.unwrap_or(false);
    if !initialized {
        bail!("Owner authority not initialized. Run: cargo run -p xtask -- owner-init --name \"Your Name\"");
    }

    let primary_key = owner.primary_pubkey.clone()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Primary owner key not configured"))?;

    let backup_key = owner.backup_pubkey.clone()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Backup owner key not configured"))?;

    Ok((primary_key, backup_key))
}

/// Check if this is the initial board setup (no active members yet)
pub fn is_initial_board_setup(config: &Config) -> bool {
    config.extra.editorial_board
        .as_ref()
        .and_then(|b| b.members.as_ref())
        .map(|members| members.iter().filter(|m| m.active).count() == 0)
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_slug_valid() {
        assert!(validate_slug("test-author").is_ok());
        assert!(validate_slug("board-1").is_ok());
        assert!(validate_slug("alice123").is_ok());
    }

    #[test]
    fn test_validate_slug_invalid() {
        assert!(validate_slug("").is_err());
        assert!(validate_slug("../etc").is_err());
        assert!(validate_slug("Test-Author").is_err()); // uppercase
        assert!(validate_slug("test_author").is_err()); // underscore
        assert!(validate_slug("test author").is_err()); // space
    }
}
