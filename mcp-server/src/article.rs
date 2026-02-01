//! Article file operations for MCP signing server
//!
//! This module provides reading and writing of article files,
//! compatible with the xtask frontmatter format.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

/// Article frontmatter structure (matches xtask/src/types.rs)
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
    pub name: String,
    pub email: Option<String>,
    pub pubkey: String,
    pub signature: String,
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
        assert!(parsed.body.contains("article body"));
    }
}
