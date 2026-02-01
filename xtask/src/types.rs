//! Shared types and enums for the newsroom CLI
//!
//! This module contains all the data structures used across the xtask modules.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// TYPE-SAFE ENUMS
// ============================================================================

/// Approval status for articles
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

impl Default for ApprovalStatus {
    fn default() -> Self {
        Self::Pending
    }
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Rejected => write!(f, "rejected"),
        }
    }
}

/// Editorial review decision
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReviewDecision {
    Approve,
    Reject,
}

impl std::fmt::Display for ReviewDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approve => write!(f, "approve"),
            Self::Reject => write!(f, "reject"),
        }
    }
}

/// Type of board member
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemberType {
    Human,
    AiAgent,
}

impl Default for MemberType {
    fn default() -> Self {
        Self::Human
    }
}

impl std::fmt::Display for MemberType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Human => write!(f, "human"),
            Self::AiAgent => write!(f, "ai_agent"),
        }
    }
}

impl std::str::FromStr for MemberType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "human" => Ok(Self::Human),
            "ai_agent" => Ok(Self::AiAgent),
            _ => anyhow::bail!("Member type must be 'human' or 'ai_agent'"),
        }
    }
}

// ============================================================================
// ARTICLE FRONTMATTER TYPES
// ============================================================================

/// Article frontmatter structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FrontMatter {
    pub title: String,
    pub date: String,
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
    pub integrity: Option<String>,
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
    pub site_integrity: Option<String>,
    pub site_signature: Option<String>,
    pub site_randomart: Option<String>,
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
    pub legacy_pubkey: Option<String>,
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
