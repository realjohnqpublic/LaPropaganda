//! Content management and integrity verification
//!
//! This module handles:
//! - Article parsing (frontmatter + body)
//! - Hash calculation
//! - Content verification
//! - Draft creation

use anyhow::{bail, Context, Result};
use chrono::Local;
// Re-export calculate_hash from core for use by other modules
pub use la_propaganda_core::calculate_hash;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::config::validate_slug;
use crate::types::FrontMatter;

/// Parse a markdown file with TOML frontmatter
pub fn parse_file(path: &Path) -> Result<(String, FrontMatter, String)> {
    let mut file = std::fs::File::open(path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;

    // Simplistic frontmatter split
    let parts: Vec<&str> = text.splitn(3, "+++").collect();
    if parts.len() < 3 {
        bail!("File {:?} does not appear to have valid TOML frontmatter", path);
    }

    let frontmatter_str = parts[1];
    let body = parts[2].to_string();

    let frontmatter: FrontMatter = toml::from_str(frontmatter_str)
        .context(format!("Failed to parse TOML frontmatter in {:?}", path))?;

    Ok((text, frontmatter, body))
}

// calculate_hash is now imported from la_propaganda_core

/// Get all content files (markdown articles)
pub fn get_content_files() -> Vec<PathBuf> {
    WalkDir::new("content/news")
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "md"))
        .filter(|e| e.file_name() != "_index.md") // Skip index files
        .map(|e| e.path().to_owned())
        .collect()
}











/// Create a new article draft
pub fn draft(title: String) -> Result<()> {
    // Sanitize title for filename
    let slug = title
        .to_lowercase()
        .replace(|c: char| !c.is_alphanumeric() && c != '-', "-")
        .replace("--", "-");
    let slug = slug.trim_matches('-');

    validate_slug(slug).context("Generated slug failed validation")?;

    let now = Local::now();
    let year = now.format("%Y").to_string();
    let month = now.format("%m").to_string();

    // Create directory structure content/news/YYYY/MM/
    let year_dir = Path::new("content/news").join(&year);
    let month_dir = year_dir.join(&month);

    std::fs::create_dir_all(&month_dir).context("Failed to create directory structure")?;

    // Ensure transparent index files exist
    let year_index = year_dir.join("_index.md");
    if !year_index.exists() {
        std::fs::write(&year_index, "+++\ntransparent = true\n+++")?;
    }
    let month_index = month_dir.join("_index.md");
    if !month_index.exists() {
        std::fs::write(&month_index, "+++\ntransparent = true\n+++")?;
    }

    let filename = month_dir.join(format!("{}.md", slug));

    if filename.exists() {
        bail!("A story with this slug already exists: {:?}", filename);
    }

    let date_str = now.format("%Y-%m-%d").to_string();

    let content = format!(r#"+++
title = "{}"
date = {}
[extra]
author = "Staff Reporter"
# image = "https://example.com/image.jpg"
+++

(Dateline: {}) - Start writing your story here...
"#, title, date_str, now.format("%B %d, %Y"));

    let mut file = std::fs::File::create(&filename).context("Failed to create file")?;
    file.write_all(content.as_bytes()).context("Failed to write content")?;

    // Automatically update the global site hash - REMOVED (Legacy)
    // hash_content(false)?;

    println!("Draft created at: {:?}", filename);
    Ok(())
}
