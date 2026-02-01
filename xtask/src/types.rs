//! Shared types and enums for the newsroom CLI
//!
//! This module contains all the data structures used across the xtask modules.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// TYPE-SAFE ENUMS
// ============================================================================



// ============================================================================
// ARTICLE FRONTMATTER TYPES
// ============================================================================

/// Article frontmatter structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FrontMatter {
    pub title: String,
    pub date: toml::Value,
    #[serde(default)]
    pub extra: ExtraConfig,
    #[serde(flatten)]
    pub other: BTreeMap<String, toml::Value>,
}

/// Extra configuration in article frontmatter
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ExtraConfig {
    pub author: Option<String>,
    pub image: Option<String>,
    // integrity removed (legacy)
    #[serde(rename = "author_signature")]
    pub author_signature: Option<AuthorSignature>,
    #[serde(rename = "editorial_approval")]
    pub editorial_approval: Option<EditorialApproval>,
    #[serde(rename = "editorial_signatures")]
    pub editorial_signatures: Option<Vec<EditorialSignature>>,
    #[serde(flatten)]
    pub other: BTreeMap<String, toml::Value>,
}

/// Author signature data
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthorSignature {
    /// Pubkey-derived ID (first 12 chars of SHA256(pubkey))
    pub author_id: String,
    /// Display alias (user-chosen name)
    pub name: String,
    pub email: Option<String>,
    pub pubkey: String,
    pub signature: String,
    /// Whether identity is verified via social media (post pubkey publicly)
    #[serde(default)]
    pub verified: bool,
}

/// Editorial approval configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EditorialApproval {
    pub required: usize,
    pub status: String, // Will migrate to ApprovalStatus in future
}

/// Editorial signature from a board member
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EditorialSignature {
    pub board_member: String,
    pub signature: String,
    pub timestamp: String,
    pub decision: String, // Will migrate to ReviewDecision in future
}

// ============================================================================
// SITE CONFIGURATION TYPES
// ============================================================================

/// Site configuration from config.toml
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub base_url: String,
    pub title: Option<String>,
    #[serde(default)]
    pub extra: SiteExtra,
    #[serde(flatten)]
    pub other: BTreeMap<String, toml::Value>,
}

/// Extra site configuration
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct SiteExtra {
    pub public_key: Option<String>,
    // site_integrity, site_signature, site_randomart removed (legacy)
    pub editorial_board: Option<EditorialBoardConfig>,
    pub owner: Option<OwnerConfig>,
    #[serde(flatten)]
    pub other: BTreeMap<String, toml::Value>,
}

/// Editorial board configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EditorialBoardConfig {
    pub members: Option<Vec<BoardMemberConfig>>,
    pub threshold: Option<usize>,
    pub last_modified: Option<String>,
    pub manifest_hash: Option<String>,
    // legacy_pubkey removed
}

/// Board member configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BoardMemberConfig {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub member_type: Option<String>,
    pub role: String,
    pub active: bool,
    pub pubkey: String,
    pub appointed: Option<String>,
    pub appointed_by: Option<String>,
}

/// Owner configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OwnerConfig {
    pub name: Option<String>,
    pub primary_pubkey: Option<String>,
    pub backup_pubkey: Option<String>,
    pub initialized: Option<bool>,
}
