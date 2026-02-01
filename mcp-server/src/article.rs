//! Article file operations for MCP signing server
//!
//! This module provides reading and writing of article files,
//! compatible with the xtask frontmatter format.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

/// Custom deserializer that accepts both TOML date (2026-01-31) and string ("2026-01-31")
fn deserialize_date<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = toml::Value::deserialize(deserializer)?;
    match value {
        toml::Value::String(s) => Ok(s),
        toml::Value::Datetime(dt) => Ok(dt.to_string()),
        other => Err(serde::de::Error::custom(format!(
            "expected date string or datetime, got {:?}",
            other
        ))),
    }
}

/// Article frontmatter structure (matches xtask/src/types.rs)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FrontMatter {
    pub title: String,
    #[serde(deserialize_with = "deserialize_date")]
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
    /// Endorsements from humans vouching for this content
    #[serde(rename = "endorsements")]
    pub endorsements: Option<Vec<EndorsementSignature>>,
    /// Authorship claim - human claiming Bot-signed content
    #[serde(rename = "authorship_claim")]
    pub authorship_claim: Option<AuthorshipClaim>,
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
    pub status: String,
}

/// Editorial signature from a board member
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EditorialSignature {
    pub board_member: String,
    pub signature: String,
    pub timestamp: String,
    pub decision: String,
}

/// Endorsement signature - Human vouches for Bot-authored content
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EndorsementSignature {
    /// Endorser's pubkey-derived ID
    pub endorser_id: String,
    /// Display name
    pub name: String,
    /// Ed25519 public key (hex)
    pub pubkey: String,
    /// Signature over SHA256(body + author_signature.signature)
    pub signature: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
}

/// Authorship claim - Human claims authorship of Bot-signed content
/// Requires mutual consent: Bot grants permission, Human claims
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthorshipClaim {
    /// Original bot author ID
    pub original_author_id: String,
    /// Original bot's public key (hex)
    pub original_pubkey: String,
    /// Human claiming authorship
    pub claimed_by_id: String,
    /// Human's display name
    pub claimed_by_name: String,
    /// Human's public key (hex)
    pub claimed_by_pubkey: String,
    /// Bot's consent: Sign_Bot("I authorize {human_pubkey} to claim article {hash}")
    pub bot_consent_signature: String,
    /// Human's claim: Sign_Human(bot_consent_signature)
    pub claim_signature: String,
    /// ISO 8601 timestamp
    pub timestamp: String,
}

/// Parsed article data
pub struct ParsedArticle {
    pub frontmatter: FrontMatter,
    pub body: String,
}

/// Parse a markdown file with TOML frontmatter
pub fn parse_article(path: &Path) -> Result<ParsedArticle> {
    let mut file = std::fs::File::open(path)
        .context(format!("Failed to open article: {}", path.display()))?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;

    parse_article_content(&text)
}

/// Parse article content string
pub fn parse_article_content(text: &str) -> Result<ParsedArticle> {
    let parts: Vec<&str> = text.splitn(3, "+++").collect();
    if parts.len() < 3 {
        bail!("Article does not have valid TOML frontmatter (missing +++ delimiters)");
    }

    let frontmatter_str = parts[1];
    let body = parts[2].to_string();

    let frontmatter: FrontMatter = toml::from_str(frontmatter_str)
        .context("Failed to parse TOML frontmatter")?;

    Ok(ParsedArticle { frontmatter, body })
}

/// Write article with updated frontmatter
pub fn write_article(path: &Path, frontmatter: &FrontMatter, body: &str) -> Result<()> {
    let frontmatter_str = toml::to_string(frontmatter)
        .context("Failed to serialize frontmatter")?;
    let content = format!("+++\n{}+++{}", frontmatter_str, body);
    std::fs::write(path, content)
        .context(format!("Failed to write article: {}", path.display()))?;
    Ok(())
}

/// Load site config to get threshold
pub fn load_threshold(base_path: &Path) -> Result<usize> {
    let config_path = base_path.join("config.toml");
    let content = std::fs::read_to_string(&config_path)
        .context("Failed to read config.toml")?;

    // Simple TOML parsing for threshold
    #[derive(Deserialize)]
    struct Config {
        extra: Option<ConfigExtra>,
    }
    #[derive(Deserialize)]
    struct ConfigExtra {
        editorial_board: Option<EditorialBoard>,
    }
    #[derive(Deserialize)]
    struct EditorialBoard {
        threshold: Option<usize>,
    }

    let config: Config = toml::from_str(&content)?;
    Ok(config.extra
        .and_then(|e| e.editorial_board)
        .and_then(|b| b.threshold)
        .unwrap_or(3))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_article_content() {
        let content = r#"+++
title = "Test Article"
date = "2026-01-31"
[extra]
author = "Test Author"
+++

This is the article body.
"#;
        let parsed = parse_article_content(content).unwrap();
        assert_eq!(parsed.frontmatter.title, "Test Article");
        assert_eq!(parsed.frontmatter.date, "2026-01-31");
        assert!(parsed.body.contains("article body"));
    }

    #[test]
    fn test_parse_toml_date_format() {
        // Test TOML native date format (without quotes)
        let content = r#"+++
title = "Test Article"
date = 2026-01-31
[extra]
author = "Test Author"
+++

Body content.
"#;
        let parsed = parse_article_content(content).unwrap();
        assert_eq!(parsed.frontmatter.title, "Test Article");
        assert_eq!(parsed.frontmatter.date, "2026-01-31");
    }
}
