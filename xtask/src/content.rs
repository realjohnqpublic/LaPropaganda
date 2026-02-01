//! Content management and integrity verification
//!
//! This module handles:
//! - Article parsing (frontmatter + body)
//! - Hash calculation
//! - Content verification
//! - Draft creation

use anyhow::{bail, Context, Result};
use chrono::Local;
use console::style;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::config::{update_site_integrity, validate_slug};
use crate::signing::sign_global_hash;
use crate::timestamp::try_create_opentimestamp;
use crate::types::{Config, FrontMatter};

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

/// Calculate SHA-256 hash of article body
pub fn calculate_hash(body: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(body.trim().as_bytes()); // Trim to avoid whitespace issues
    hasher.finalize().to_vec()
}

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

/// Drunken Bishop Algorithm (OpenSSH style Randomart)
pub fn drunken_bishop(hash: &[u8]) -> String {
    let mut board = [[0u8; 20]; 9]; // Widened to 20 to fit text
    let mut x = 9; // Center start (approx)
    let mut y = 4;

    for &byte in hash {
        for i in 0..4 {
            let shift = i * 2;
            let val = (byte >> shift) & 0x03;

            // Move
            let dx = if (val & 0x01) != 0 { 1 } else { -1 };
            let dy = if (val & 0x02) != 0 { 1 } else { -1 };

            x = (x as i32 + dx).max(0).min(19) as usize; // Clamp to 0..19
            y = (y as i32 + dy).max(0).min(8) as usize;

            if board[y][x] < 14 {
                board[y][x] += 1;
            }
        }
    }

    // Symbols
    let symbols = " .o+=*BOX@%&^#@";
    let mut art = String::new();
    art.push_str("+-----[ Magic ]------+\n");

    for (r, row) in board.iter().enumerate() {
        art.push('|');
        for (c, &val) in row.iter().enumerate() {
            if r == 4 && c == 9 {
                art.push('S');
            } else if r == y && c == x {
                art.push('E');
            } else {
                art.push(symbols.chars().nth(val as usize).unwrap_or(' '));
            }
        }
        art.push_str("|\n");
    }
    art.push_str("+-----[ SHA256 ]-----+");
    art
}

/// Hash a single file (update its integrity field)
fn hash_single_file(path: &Path) -> Result<()> {
    let (_, mut frontmatter, body) = parse_file(path)?;
    let hash_bytes = calculate_hash(&body);
    let hash_hex = hex::encode(&hash_bytes);

    // Update hash in frontmatter
    frontmatter.extra.integrity = Some(hash_hex);

    // Re-serialize
    let new_frontmatter_str = toml::to_string(&frontmatter)?;
    let new_content = format!("+++{}+++{}", new_frontmatter_str, body);

    std::fs::write(path, new_content)?;

    Ok(())
}

/// Calculate global hash of all content files
pub fn calculate_global_hash() -> Result<(String, String)> {
    let mut files = get_content_files();
    files.sort(); // Deterministic order is CRITICAL

    let mut global_hasher = Sha256::new();

    println!("Hashing {} articles for global integrity...", files.len());

    for path in files {
        let mut file = std::fs::File::open(&path)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;

        global_hasher.update(&content);
        global_hasher.update(b"|:|"); // Separator
    }

    let hash_bytes = global_hasher.finalize().to_vec();
    let hash_hex = hex::encode(&hash_bytes);
    let randomart = drunken_bishop(&hash_bytes);

    Ok((hash_hex, randomart))
}

/// Update cryptographic hashes for all articles and sign globally
pub fn hash_content(skip_sign: bool) -> Result<()> {
    // Safety Force: Prevent accidental unsigned deployments
    if skip_sign {
        let proof_mode = std::env::var("LAPROPAGANDA_PROOF_MODE").unwrap_or_default();
        if proof_mode != "1" {
            bail!("SAFETY ERROR: --skip-sign is only allowed in Proof Mode.\nSet LAPROPAGANDA_PROOF_MODE=1 environment variable to confirm you are debugging/verifying hashes only.");
        }
        println!("{}", style("RUNNING IN PROOF MODE (Signatures Skipped)").yellow().bold());
    }

    let files = get_content_files();
    println!("Step 1: Signing {} individual articles...", files.len());

    for path in files {
        hash_single_file(&path).context(format!("Failed to hash {:?}", path))?;
    }

    println!("Step 2: Calculating Global Site Edition Hash...");
    let (hash_hex, randomart) = calculate_global_hash()?;

    println!("Step 3: Signing content with editorial board key...");
    let signature = if skip_sign {
        println!("{}", style("SKIPPING SIGNATURE (Proof Mode)").yellow().bold());
        "UNSIGNED_PROOF_MODE".to_string()
    } else {
        sign_global_hash(&hash_hex)?
    };

    // Use proper TOML updates
    let config_path = Path::new("config.toml");
    update_site_integrity(config_path, &hash_hex, &signature, &randomart)?;

    println!("{}", style("Content signed by editorial board").green().bold());
    let disp_sig = if signature.len() > 32 { &signature[..32] } else { &signature };
    println!("Signature: {}...", disp_sig);
    println!("{}", style("Hybrid Integrity System Updated (Local + Global).").green());

    // Create OpenTimestamp proof for global site hash
    println!();
    let ots_path = Path::new(".editorial_board/site_integrity.ots");
    try_create_opentimestamp(&hash_hex, ots_path);

    Ok(())
}

/// Verify content integrity (detect tampering)
pub fn verify_content() -> Result<()> {
    let files = get_content_files();
    let mut errors = 0;

    println!("Step 1: Verifying {} individual articles...", files.len());

    for path in files {
        let (_, frontmatter, body) = parse_file(&path)?;
        let calculated_hash_bytes = calculate_hash(&body);
        let calculated_hash = hex::encode(&calculated_hash_bytes);

        if let Some(stored_hash) = &frontmatter.extra.integrity {
            if stored_hash != &calculated_hash {
                eprintln!("{}", style(format!("TAMPERED: {:?} (Local Hash mismatch)", path)).red().bold());
                errors += 1;
            }
        } else {
            eprintln!("{}", style(format!("WARNING: {:?} has no integrity hash", path)).yellow());
            errors += 1;
        }
    }

    println!("Step 2: Verifying Global Site Edition Hash...");
    let (calculated_hash, _) = calculate_global_hash()?;
    let config_path = Path::new("config.toml");
    let config_str = std::fs::read_to_string(config_path)?;

    let config: Config = toml::from_str(&config_str)
        .context("Failed to parse config.toml")?;

    match &config.extra.site_integrity {
        Some(stored_hash) => {
            if stored_hash != &calculated_hash {
                eprintln!("{}", style("TAMPERED: Global Site Hash Mismatch!").red().bold());
                eprintln!("{}", style("Verify failed: Site edition signature invalid.").red());
                errors += 1;
            }
        }
        None => {
            bail!("Could not find site_integrity in config.toml");
        }
    }

    if errors > 0 {
        bail!("Verification failed: {} integrity issues found.", errors);
    }

    println!("{}", style("Hybrid System Verified: All articles and Site Edition are authentic.").green());
    Ok(())
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

    // Automatically update the global site hash
    hash_content(false)?;

    println!("Draft created at: {:?}", filename);
    Ok(())
}
