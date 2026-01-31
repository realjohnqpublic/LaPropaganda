use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::process::{Command, Stdio};
use std::path::{Path, PathBuf};
use chrono::Local;
use std::io::{Read, Write};
use walkdir::WalkDir;
use sha2::{Sha256, Digest};
use regex::Regex;
use console::style;
use ed25519_dalek::{SigningKey, Signature, Signer, VerifyingKey, Verifier};
use rand::rngs::OsRng;

#[derive(Parser)]
#[command(name = "newsroom")]
#[command(about = "Newsroom workflow tools for La Propaganda", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Draft a new breaking story (creates a new .md file)
    Draft {
        /// The headline of the story
        title: String,
    },
    /// Proofread the latest edition (serves the site locally)
    Proofread,
    /// Send the edition to the presses (builds the static site)
    Print,
    /// Update cryptographic integrity hashes for all articles
    Hash {
        /// Skip signing the global hash (for layout proofing only)
        #[arg(long)]
        skip_sign: bool,
    },
    /// Verify content integrity (detect tampering)
    Verify,
    /// CI check (Verify + Print)
    Ci,
    /// Generate Ed25519 keypair for editorial board signing
    GenerateKey,
    /// Verify cryptographic signature authenticity
    VerifySignature,
    /// Generate Ed25519 keypair for an author
    AuthorKeygen {
        /// Author's full name
        name: String,
        /// Author ID (slug format, e.g., alice-smith)
        id: String,
        /// Email address (optional)
        #[arg(short, long)]
        email: Option<String>,
    },
    /// Sign article as author
    AuthorSign {
        /// Path to article markdown file
        article: PathBuf,
    },
    /// Verify author signature on article
    VerifyAuthor {
        /// Path to article markdown file
        article: PathBuf,
    },
    /// Generate Ed25519 keypair for editorial board member
    BoardKeygen {
        /// Board member's full name
        name: String,
        /// Board member ID (slug format, e.g., bob-editor)
        id: String,
        /// Role/title
        #[arg(short, long)]
        role: String,
    },
    /// Review article as editorial board member
    EditorialReview {
        /// Path to article markdown file
        article: PathBuf,
        /// Approve the article
        #[arg(long, conflicts_with = "reject")]
        approve: bool,
        /// Reject the article
        #[arg(long, conflicts_with = "approve")]
        reject: bool,
    },
    /// List editorial board members
    BoardList,
    /// Verify all signatures on an article
    VerifyArticle {
        /// Path to article markdown file
        article: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Draft { title } => draft(title),
        Commands::Proofread => run_zola("serve"),
        Commands::Print => run_zola("build"),
        Commands::Hash { skip_sign } => hash_content(skip_sign),
        Commands::Verify => verify_content(),
        Commands::Ci => {
            verify_content()?;
            run_zola("build")
        }
        Commands::GenerateKey => generate_key(),
        Commands::VerifySignature => verify_signature(),
        Commands::AuthorKeygen { name, id, email } => author_keygen(name, id, email),
        Commands::AuthorSign { article } => author_sign(&article),
        Commands::VerifyAuthor { article } => verify_author(&article),
        Commands::BoardKeygen { name, id, role } => board_keygen(name, id, role),
        Commands::EditorialReview { article, approve, reject } => {
            editorial_review(&article, approve, reject)
        }
        Commands::BoardList => board_list(),
        Commands::VerifyArticle { article } => verify_article(&article),
    }
}

fn draft(title: String) -> Result<()> {
    // Sanitize title for filename
    let slug = title
        .to_lowercase()
        .replace(|c: char| !c.is_alphanumeric() && c != '-', "-")
        .replace("--", "-");
    
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

    let filename = month_dir.join(format!("{}.md", slug.trim_matches('-')));
    
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

fn run_zola(cmd: &str) -> Result<()> {
    println!("Running Zola {}...", cmd);
    
    if Command::new("zola").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_err() {
        eprintln!("Error: 'zola' is not found in your PATH.");
        bail!("Zola executable missing");
    }

    let status = Command::new("zola")
        .arg(cmd)
        .status()
        .context(format!("Failed to run zola {}", cmd))?;

    if !status.success() {
        bail!("Zola command failed");
    }
    
    Ok(())
}

fn get_content_files() -> Vec<PathBuf> {
    WalkDir::new("content/news")
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "md"))
        .filter(|e| e.file_name() != "_index.md") // Skip index files
        .map(|e| e.path().to_owned())
        .collect()
}

fn parse_file(path: &Path) -> Result<(String, String, String)> {
    let mut file = std::fs::File::open(path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;

    // simplistic frontmatter split
    let parts: Vec<&str> = text.splitn(3, "+++").collect();
    if parts.len() < 3 {
        // Might be just frontmatter or empty?
        bail!("File {:?} does not appear to have valid TOML frontmatter", path);
    }

    let frontmatter = parts[1].to_string();
    let body = parts[2].to_string();
    
    Ok((text, frontmatter, body))
}

fn calculate_hash(body: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(body.trim().as_bytes()); // Trim to avoid whitespace issues
    hasher.finalize().to_vec()
}

// Drunken Bishop Algorithm (OpenSSH style Randomart)
fn drunken_bishop(hash: &[u8]) -> String {
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

fn hash_single_file(path: &Path) -> Result<()> {
    let (_, frontmatter, body) = parse_file(path)?;
    let hash_bytes = calculate_hash(&body);
    let hash_hex = hex::encode(&hash_bytes);
    // Randomart is no longer needed for individual files per user request
    // let randomart = drunken_bishop(&hash_bytes);
    
    // Check if integrity field exists
    let hash_re = Regex::new(r#"(?m)^integrity\s*=\s*".*"$"#).unwrap();
    let mut new_frontmatter = if hash_re.is_match(&frontmatter) {
        hash_re.replace(&frontmatter, format!(r#"integrity = "{}""#, hash_hex)).to_string()
    } else {
        format!("{}\nintegrity = \"{}\"", frontmatter.trim_end(), hash_hex)
    };
    
    // User requested NO Randomart in individual files (Headline only)
    // We strictly remove any existing randomart block if present to clean up.
    let art_re = Regex::new(r#"(?ms)^randomart\s*=\s*""".*?"""\n?"#).unwrap();
    if art_re.is_match(&new_frontmatter) {
        new_frontmatter = art_re.replace(&new_frontmatter, "").to_string();
    }
    
    let new_content = format!("+++{}+++{}", new_frontmatter, body);
    std::fs::write(path, new_content)?;
    
    Ok(())
}

fn calculate_global_hash() -> Result<(String, String)> {
    let mut files = get_content_files();
    files.sort(); // Deterministic order is CRITICAL
    
    let mut global_hasher = Sha256::new();
    
    // Hashing body only, or body + frontmatter? 
    // If we include frontmatter, we include the per-file integrity hash, which creates a Merkle-like chain.
    // Let's include the whole file content to be safest (since we just updated them).
    
    println!("Hashing {} articles for global integrity...", files.len());
    
    for path in files {
        let mut file = std::fs::File::open(path)?;
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

fn hash_content(skip_sign: bool) -> Result<()> {
    let files = get_content_files();
    println!("Step 1: Signing {} individual articles...", files.len());

    for path in files {
        hash_single_file(&path).context(format!("Failed to hash {:?}", path))?;
    }

    println!("Step 2: Calculating Global Site Edition Hash...");
    let (hash_hex, randomart) = calculate_global_hash()?;

    println!("Step 3: Signing content with editorial board key...");
    let signature = if skip_sign {
        println!("{}", style("⚠️  SKIPPING SIGNATURE (Proof Mode)").yellow().bold());
        "UNSIGNED_PROOF_MODE".to_string()
    } else {
        sign_global_hash(&hash_hex)?
    };

    let config_path = Path::new("config.toml");
    let mut config = std::fs::read_to_string(config_path)?;

    // Update site_integrity
    let hash_re = Regex::new(r#"(?m)^site_integrity\s*=\s*".*"$"#).unwrap();
    config = if hash_re.is_match(&config) {
        hash_re.replace(&config, format!(r#"site_integrity = "{}""#, hash_hex)).to_string()
    } else {
        println!("{}", style("WARNING: site_integrity field not found in config.toml").yellow());
        config
    };

    // Update site_signature
    let sig_re = Regex::new(r#"(?m)^site_signature\s*=\s*".*"$"#).unwrap();
    if sig_re.is_match(&config) {
        config = sig_re.replace(&config, format!(r#"site_signature = "{}""#, signature)).to_string();
    } else {
        // Add site_signature field after public_key in [extra] section
        let pk_re = Regex::new(r#"(?m)^public_key\s*=\s*".*"$"#).unwrap();
        if pk_re.is_match(&config) {
            config = pk_re.replace(&config, |caps: &regex::Captures| {
                format!("{}\nsite_signature = \"{}\"", &caps[0], signature)
            }).to_string();
        } else {
            println!("{}", style("WARNING: site_signature and public_key fields not found in config.toml").yellow());
        }
    }

    // Update site_randomart
    let art_re = Regex::new(r#"(?ms)^site_randomart\s*=\s*""".*?"""$"#).unwrap();
    let art_block = format!(r#"site_randomart = """
{}
""""#, randomart);

    config = if art_re.is_match(&config) {
        art_re.replace(&config, art_block).to_string()
    } else {
        println!("{}", style("WARNING: site_randomart field not found in config.toml").yellow());
        config
    };

    std::fs::write(config_path, config)?;
    println!("{}", style("✅ Content signed by editorial board").green().bold());
    let disp_sig = if signature.len() > 32 { &signature[..32] } else { &signature };
    println!("📋 Signature: {}...", disp_sig);
    println!("{}", style("Hybrid Integrity System Updated (Local + Global).").green());

    // Create OpenTimestamp proof for global site hash
    println!();
    let ots_path = Path::new(".editorial_board/site_integrity.ots");
    try_create_opentimestamp(&hash_hex, &ots_path);

    Ok(())
}

fn verify_content() -> Result<()> {
    let files = get_content_files();
    let mut errors = 0;

    println!("Step 1: Verifying {} individual articles...", files.len());

    for path in files {
        let (_, frontmatter, body) = parse_file(&path)?;
        let calculated_hash_bytes = calculate_hash(&body);
        let calculated_hash = hex::encode(&calculated_hash_bytes);

        let re = Regex::new(r#"(?m)^integrity\s*=\s*"(.*)"$"#).unwrap();
        if let Some(caps) = re.captures(&frontmatter) {
            let stored_hash = &caps[1];
            if stored_hash != calculated_hash {
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
    let config = std::fs::read_to_string(config_path)?;

    let re = Regex::new(r#"(?m)^site_integrity\s*=\s*"(.*)"$"#).unwrap();
    if let Some(caps) = re.captures(&config) {
        let stored_hash = &caps[1];
        if stored_hash != calculated_hash {
             eprintln!("{}", style("TAMPERED: Global Site Hash Mismatch!").red().bold());
             eprintln!("{}", style("Verify failed: Site edition signature invalid.").red());
             errors += 1;
        }
    } else {
        bail!("Could not find site_integrity in config.toml");
    }

    if errors > 0 {
        bail!("Verification failed: {} integrity issues found.", errors);
    }

    println!("{}", style("Hybrid System Verified: All articles and Site Edition are authentic.").green());
    Ok(())
}

// ============================================================================
// CRYPTOGRAPHIC SIGNING FUNCTIONS
// ============================================================================

fn generate_key() -> Result<()> {
    println!("{}", style("🔑 Generating Ed25519 keypair...").cyan().bold());

    // Create .editorial_board directory if it doesn't exist
    let key_dir = Path::new(".editorial_board");
    std::fs::create_dir_all(key_dir).context("Failed to create .editorial_board directory")?;

    // Generate keypair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Encode keys as hex
    let private_key_hex = hex::encode(signing_key.to_bytes());
    let public_key_hex = hex::encode(verifying_key.to_bytes());

    // Save private key to file
    let private_key_path = key_dir.join("private_key.secret");
    std::fs::write(&private_key_path, &private_key_hex)
        .context("Failed to write private key")?;

    // Update config.toml with public key
    let config_path = Path::new("config.toml");
    let mut config = std::fs::read_to_string(config_path)
        .context("Failed to read config.toml")?;

    // Add public_key to [extra] section
    let public_key_re = Regex::new(r#"(?m)^public_key\s*=\s*".*"$"#).unwrap();
    if public_key_re.is_match(&config) {
        // Update existing
        config = public_key_re.replace(&config, format!(r#"public_key = "{}""#, public_key_hex)).to_string();
    } else {
        // Add new field after [extra] section
        let extra_re = Regex::new(r"(?m)^\[extra\]\s*$").unwrap();
        if extra_re.is_match(&config) {
            config = extra_re.replace(&config, format!("[extra]\npublic_key = \"{}\"", public_key_hex)).to_string();
        } else {
            // No [extra] section, add it
            config.push_str(&format!("\n[extra]\npublic_key = \"{}\"\n", public_key_hex));
        }
    }

    std::fs::write(config_path, config)
        .context("Failed to update config.toml")?;

    println!("{}", style("✅ Keypair generated successfully!").green().bold());
    println!();
    println!("{}", style("📁 Private key saved to:").yellow());
    println!("   {}", style(private_key_path.display()).cyan());
    println!("   {}", style("⚠️  KEEP THIS SECRET! Never commit to git.").red().bold());
    println!();
    println!("{}", style("🔑 Public key added to config.toml:").yellow());
    println!("   {}...", style(&public_key_hex[..32]).cyan());
    println!();
    println!("{}", style("Next steps:").yellow().bold());
    println!("1. Add private key to GitHub Secrets:");
    println!("   {}", style("gh secret set EDITORIAL_BOARD_PRIVATE_KEY < .editorial_board/private_key.secret").cyan());
    println!("2. Commit public key:");
    println!("   {}", style("git add config.toml && git commit -m 'feat: Add public key for signature verification'").cyan());

    Ok(())
}

fn load_private_key() -> Result<SigningKey> {
    // Try loading from environment variable first (CI)
    if let Ok(key_hex) = std::env::var("EDITORIAL_BOARD_PRIVATE_KEY") {
        let key_bytes = hex::decode(key_hex.trim())
            .context("Failed to decode private key from environment variable")?;
        let key_array: [u8; 32] = key_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Private key must be 32 bytes"))?;
        return Ok(SigningKey::from_bytes(&key_array));
    }

    // Try loading from file (local dev)
    let key_path = Path::new(".editorial_board/private_key.secret");
    if key_path.exists() {
        let key_hex = std::fs::read_to_string(key_path)
            .context("Failed to read private key file")?;
        let key_bytes = hex::decode(key_hex.trim())
            .context("Failed to decode private key from file")?;
        let key_array: [u8; 32] = key_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Private key must be 32 bytes"))?;
        return Ok(SigningKey::from_bytes(&key_array));
    }

    bail!("No signing key found. Run: cargo run -p xtask -- generate-key")
}

fn sign_global_hash(hash_hex: &str) -> Result<String> {
    let signing_key = load_private_key()?;

    // Sign the hash hex string
    let signature = signing_key.sign(hash_hex.as_bytes());

    // Return signature as hex
    Ok(hex::encode(signature.to_bytes()))
}

fn verify_signature() -> Result<()> {
    println!("{}", style("🔐 Verifying cryptographic signature...").cyan().bold());

    // Step 1: Calculate current global hash
    let (calculated_hash, _) = calculate_global_hash()?;

    // Step 2: Load config.toml
    let config_path = Path::new("config.toml");
    let config = std::fs::read_to_string(config_path)
        .context("Failed to read config.toml")?;

    // Step 3: Extract public key
    let public_key_re = Regex::new(r#"(?m)^public_key\s*=\s*"(.*)"$"#).unwrap();
    let public_key_hex = public_key_re.captures(&config)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str())
        .ok_or_else(|| anyhow::anyhow!("No public_key found in config.toml. Run: cargo run -p xtask -- generate-key"))?;

    // Step 4: Extract signature
    let signature_re = Regex::new(r#"(?m)^site_signature\s*=\s*"(.*)"$"#).unwrap();
    let signature_hex = signature_re.captures(&config)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str())
        .ok_or_else(|| anyhow::anyhow!("No site_signature found in config.toml. Run: cargo run -p xtask -- hash"))?;

    // Step 5: Decode keys and signature
    let public_key_bytes = hex::decode(public_key_hex)
        .context("Failed to decode public key")?;
    let public_key_array: [u8; 32] = public_key_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array)
        .context("Invalid public key")?;

    let signature_bytes = hex::decode(signature_hex)
        .context("Failed to decode signature")?;
    let signature_array: [u8; 64] = signature_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&signature_array);

    // Step 6: Verify signature
    verifying_key.verify(calculated_hash.as_bytes(), &signature)
        .context("Signature verification failed - content has been tampered or signed with different key")?;

    println!("{}", style("✅ Signature VALID - Content signed by editorial board").green().bold());
    println!();
    println!("{}", style("🔑 Public key:").yellow());
    println!("   {}...", style(&public_key_hex[..32]).cyan());
    println!();
    println!("{}", style("📋 Site hash:").yellow());
    println!("   {}...", style(&calculated_hash[..32]).cyan());
    println!();
    println!("{}", style("✅ Content authenticity verified!").green().bold());

    Ok(())
}

// ============================================================================
// MULTI-SIGNATURE SYSTEM: AUTHOR SIGNING
// ============================================================================

fn author_keygen(name: String, id: String, email: Option<String>) -> Result<()> {
    println!("{}", style(format!("🔑 Generating Ed25519 keypair for author: {}", name)).cyan().bold());

    // Validate ID format (slug)
    if !id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        bail!("Author ID must be in slug format (lowercase, alphanumeric, hyphens only)");
    }

    // Create .authors/<id> directory
    let key_dir = Path::new(".authors").join(&id);
    if key_dir.exists() {
        bail!("Author {} already exists at {:?}", id, key_dir);
    }
    std::fs::create_dir_all(&key_dir).context("Failed to create author key directory")?;

    // Generate keypair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Encode keys as hex
    let private_key_hex = hex::encode(signing_key.to_bytes());
    let public_key_hex = hex::encode(verifying_key.to_bytes());

    // Save private key to file
    let private_key_path = key_dir.join("private_key.secret");
    std::fs::write(&private_key_path, &private_key_hex)
        .context("Failed to write private key")?;

    // Save author metadata
    let metadata = format!(
        "# Author: {}\n# ID: {}\n# Email: {}\n# Public Key: {}\n# Generated: {}\n",
        name,
        id,
        email.as_deref().unwrap_or("N/A"),
        public_key_hex,
        Local::now().format("%Y-%m-%d %H:%M:%S")
    );
    let metadata_path = key_dir.join("author.info");
    std::fs::write(&metadata_path, &metadata)
        .context("Failed to write author metadata")?;

    println!("{}", style("✅ Author keypair generated successfully!").green().bold());
    println!();
    println!("{}", style("📁 Private key saved to:").yellow());
    println!("   {}", style(private_key_path.display()).cyan());
    println!("   {}", style("⚠️  KEEP THIS SECRET! Never commit to git.").red().bold());
    println!();
    println!("{}", style("🔑 Public key:").yellow());
    println!("   {}", style(&public_key_hex).cyan());
    println!();
    println!("{}", style("Next steps:").yellow().bold());
    println!("1. Use this public key when signing articles");
    println!("2. Sign articles with:");
    println!("   {}", style(format!("cargo run -p xtask -- author-sign <article.md>")).cyan());

    Ok(())
}

fn load_author_private_key(author_id: &str) -> Result<SigningKey> {
    let key_path = Path::new(".authors").join(author_id).join("private_key.secret");
    if !key_path.exists() {
        bail!(
            "Author key not found for '{}'. Generate with: cargo run -p xtask -- author-keygen --name \"Name\" --id {}",
            author_id,
            author_id
        );
    }

    let key_hex = std::fs::read_to_string(&key_path)
        .context("Failed to read author private key")?;
    let key_bytes = hex::decode(key_hex.trim())
        .context("Failed to decode author private key")?;
    let key_array: [u8; 32] = key_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Author private key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&key_array))
}

fn author_sign(article_path: &Path) -> Result<()> {
    println!("{}", style(format!("✍️  Signing article: {}", article_path.display())).cyan().bold());

    // Parse article
    let (_full_text, frontmatter, body) = parse_file(article_path)?;

    // Check if already has author signature
    let author_sig_re = Regex::new(r"(?m)^\[author\]")?;
    if author_sig_re.is_match(&frontmatter) {
        bail!("Article already has author signature. Remove [author] section first to re-sign.");
    }

    // Prompt for author ID
    println!();
    println!("{}", style("Enter author ID (from .authors/ directory):").yellow());
    print!("> ");
    std::io::stdout().flush()?;

    let mut author_id = String::new();
    std::io::stdin().read_line(&mut author_id)?;
    let author_id = author_id.trim();

    if author_id.is_empty() {
        bail!("Author ID cannot be empty");
    }

    // Load author metadata
    let author_info_path = Path::new(".authors").join(author_id).join("author.info");
    let author_info = std::fs::read_to_string(&author_info_path)
        .context("Failed to read author metadata. Run author-keygen first.")?;

    // Extract name and email from metadata
    let name_re = Regex::new(r"# Author: (.+)")?;
    let email_re = Regex::new(r"# Email: (.+)")?;
    let pubkey_re = Regex::new(r"# Public Key: (.+)")?;

    let author_name = name_re.captures(&author_info)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .unwrap_or("Unknown");
    let author_email = email_re.captures(&author_info)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .filter(|s| *s != "N/A");
    let author_pubkey = pubkey_re.captures(&author_info)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .ok_or_else(|| anyhow::anyhow!("Could not find public key in author metadata"))?;

    // Calculate article hash
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    // Load author private key and sign
    let signing_key = load_author_private_key(author_id)?;
    let signature = signing_key.sign(hash_hex.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    println!("{}", style(format!("✅ Signed as: {}", author_name)).green());

    // Update frontmatter with author section
    let mut new_frontmatter = frontmatter.clone();

    // Add [author] section after date field
    let author_section = format!(
        "\n[author]\nname = \"{}\"\n{}pubkey = \"{}\"\nsignature = \"{}\"",
        author_name,
        author_email.map(|e| format!("email = \"{}\"\n", e)).unwrap_or_default(),
        author_pubkey,
        signature_hex
    );

    // Find where to insert (after date field)
    let date_re = Regex::new(r"(?m)^date\s*=\s*.+$")?;
    if date_re.is_match(&new_frontmatter) {
        new_frontmatter = date_re.replace(&new_frontmatter, |caps: &regex::Captures| {
            format!("{}{}", &caps[0], author_section)
        }).to_string();
    } else {
        // Fallback: add after title
        let title_re = Regex::new(r"(?m)^title\s*=\s*.+$")?;
        if title_re.is_match(&new_frontmatter) {
            new_frontmatter = title_re.replace(&new_frontmatter, |caps: &regex::Captures| {
                format!("{}{}", &caps[0], author_section)
            }).to_string();
        } else {
            // Last resort: add at end of frontmatter
            new_frontmatter.push_str(&author_section);
        }
    }

    // Add editorial approval section (status: pending)
    let approval_section = "\n\n[editorial_approval]\nrequired = 3\nstatus = \"pending\"";
    new_frontmatter.push_str(approval_section);

    // Write updated article
    let new_content = format!("+++{}+++{}", new_frontmatter, body);
    std::fs::write(article_path, new_content)?;

    println!("{}", style("✅ Article signed successfully!").green().bold());
    println!();
    println!("{}", style("📋 Article hash:").yellow());
    println!("   {}...", style(&hash_hex[..32]).cyan());
    println!("{}", style("✍️  Author signature:").yellow());
    println!("   {}...", style(&signature_hex[..32]).cyan());
    println!();
    println!("{}", style("Next steps:").yellow().bold());
    println!("1. Submit article for editorial review");
    println!("2. Editorial board members review with:");
    println!("   {}", style("cargo run -p xtask -- editorial-review <article.md> --approve").cyan());

    Ok(())
}

fn verify_author(article_path: &Path) -> Result<()> {
    println!("{}", style(format!("🔍 Verifying author signature: {}", article_path.display())).cyan().bold());

    let (_, frontmatter, body) = parse_file(article_path)?;

    // Extract author section
    let author_pubkey_re = Regex::new(r#"(?m)^pubkey\s*=\s*"(.+)"$"#)?;
    let author_sig_re = Regex::new(r#"(?m)^signature\s*=\s*"(.+)"$"#)?;

    let author_pubkey = author_pubkey_re.captures(&frontmatter)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .ok_or_else(|| anyhow::anyhow!("No author public key found in article"))?;

    let author_signature = author_sig_re.captures(&frontmatter)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .ok_or_else(|| anyhow::anyhow!("No author signature found in article"))?;

    // Calculate article hash
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    // Verify signature
    let pubkey_bytes = hex::decode(author_pubkey)
        .context("Failed to decode author public key")?;
    let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Author public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
        .context("Invalid author public key")?;

    let sig_bytes = hex::decode(author_signature)
        .context("Failed to decode author signature")?;
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Author signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key.verify(hash_hex.as_bytes(), &signature)
        .context("Author signature verification failed - article has been modified")?;

    println!("{}", style("✅ Author signature VALID").green().bold());
    println!();
    println!("{}", style("🔑 Author public key:").yellow());
    println!("   {}...", style(&author_pubkey[..32]).cyan());
    println!();
    println!("{}", style("📋 Article hash:").yellow());
    println!("   {}...", style(&hash_hex[..32]).cyan());

    Ok(())
}

// ============================================================================
// MULTI-SIGNATURE SYSTEM: EDITORIAL BOARD
// ============================================================================

fn board_keygen(name: String, id: String, role: String) -> Result<()> {
    println!("{}", style(format!("🔑 Generating Ed25519 keypair for board member: {}", name)).cyan().bold());

    // Validate ID format
    if !id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        bail!("Board member ID must be in slug format (lowercase, alphanumeric, hyphens only)");
    }

    // Create .editorial_board/board/<id> directory
    let key_dir = Path::new(".editorial_board/board").join(&id);
    if key_dir.exists() {
        bail!("Board member {} already exists at {:?}", id, key_dir);
    }
    std::fs::create_dir_all(&key_dir).context("Failed to create board member key directory")?;

    // Generate keypair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Encode keys as hex
    let private_key_hex = hex::encode(signing_key.to_bytes());
    let public_key_hex = hex::encode(verifying_key.to_bytes());

    // Save private key
    let private_key_path = key_dir.join("private_key.secret");
    std::fs::write(&private_key_path, &private_key_hex)
        .context("Failed to write private key")?;

    // Save metadata
    let metadata = format!(
        "# Board Member: {}\n# ID: {}\n# Role: {}\n# Public Key: {}\n# Generated: {}\n",
        name,
        id,
        role,
        public_key_hex,
        Local::now().format("%Y-%m-%d %H:%M:%S")
    );
    let metadata_path = key_dir.join("member.info");
    std::fs::write(&metadata_path, &metadata)
        .context("Failed to write member metadata")?;

    println!("{}", style("✅ Board member keypair generated successfully!").green().bold());
    println!();
    println!("{}", style("📁 Private key saved to:").yellow());
    println!("   {}", style(private_key_path.display()).cyan());
    println!("   {}", style("⚠️  KEEP THIS SECRET! Never commit to git.").red().bold());
    println!();
    println!("{}", style("🔑 Public key:").yellow());
    println!("   {}", style(&public_key_hex).cyan());
    println!();
    println!("{}", style("Next steps:").yellow().bold());
    println!("1. Add this member to config.toml [extra] section:");
    println!();
    println!("   [[extra.editorial_board.members]]");
    println!("   id = \"{}\"", id);
    println!("   name = \"{}\"", name);
    println!("   role = \"{}\"", role);
    println!("   pubkey = \"{}\"", public_key_hex);
    println!("   active = true");
    println!("   joined = \"{}\"", Local::now().format("%Y-%m-%d"));

    Ok(())
}

fn load_board_member_private_key(member_id: &str) -> Result<SigningKey> {
    let key_path = Path::new(".editorial_board/board").join(member_id).join("private_key.secret");
    if !key_path.exists() {
        bail!(
            "Board member key not found for '{}'. Generate with: cargo run -p xtask -- board-keygen --name \"Name\" --id {} --role \"Role\"",
            member_id,
            member_id
        );
    }

    let key_hex = std::fs::read_to_string(&key_path)
        .context("Failed to read board member private key")?;
    let key_bytes = hex::decode(key_hex.trim())
        .context("Failed to decode board member private key")?;
    let key_array: [u8; 32] = key_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Board member private key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&key_array))
}

fn editorial_review(article_path: &Path, approve: bool, reject: bool) -> Result<()> {
    if !approve && !reject {
        bail!("Must specify either --approve or --reject");
    }

    let decision = if approve { "approve" } else { "reject" };
    println!("{}", style(format!("📋 Editorial review: {} - {}", article_path.display(), decision)).cyan().bold());

    // Parse article
    let (_, frontmatter, body) = parse_file(article_path)?;

    // Verify author signature first
    println!("{}", style("Step 1: Verifying author signature...").yellow());
    verify_author(article_path)?;

    // Prompt for board member ID
    println!();
    println!("{}", style("Enter board member ID (from .editorial_board/board/ directory):").yellow());
    print!("> ");
    std::io::stdout().flush()?;

    let mut member_id = String::new();
    std::io::stdin().read_line(&mut member_id)?;
    let member_id = member_id.trim();

    if member_id.is_empty() {
        bail!("Board member ID cannot be empty");
    }

    // Load board member metadata
    let member_info_path = Path::new(".editorial_board/board").join(member_id).join("member.info");
    let member_info = std::fs::read_to_string(&member_info_path)
        .context("Failed to read board member metadata. Run board-keygen first.")?;

    let name_re = Regex::new(r"# Board Member: (.+)")?;
    let pubkey_re = Regex::new(r"# Public Key: (.+)")?;

    let member_name = name_re.captures(&member_info)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .unwrap_or("Unknown");
    let _member_pubkey = pubkey_re.captures(&member_info)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .ok_or_else(|| anyhow::anyhow!("Could not find public key in member metadata"))?;

    // Extract author signature
    let author_sig_re = Regex::new(r#"(?m)^signature\s*=\s*"(.+)"$"#)?;
    let author_signature = author_sig_re.captures(&frontmatter)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .ok_or_else(|| anyhow::anyhow!("No author signature found"))?;

    // Calculate article hash
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    // Create review hash: SHA-256(article_hash + author_signature)
    let review_data = format!("{}{}", hash_hex, author_signature);
    let mut hasher = Sha256::new();
    hasher.update(review_data.as_bytes());
    let review_hash = hasher.finalize();
    let review_hash_hex = hex::encode(&review_hash);

    // Sign review hash
    let signing_key = load_board_member_private_key(member_id)?;
    let signature = signing_key.sign(review_hash_hex.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    println!("{}", style(format!("Step 2: Signing {} decision as: {}", decision, member_name)).yellow());

    // Update frontmatter with editorial signature
    let mut new_frontmatter = frontmatter.clone();

    // Add editorial signature entry
    let timestamp = Local::now().to_rfc3339();
    let sig_entry = format!(
        "\n[[editorial_signatures]]\nboard_member = \"{}\"\nsignature = \"{}\"\ntimestamp = \"{}\"\ndecision = \"{}\"",
        member_id,
        signature_hex,
        timestamp,
        decision
    );

    // Find [editorial_approval] section and add signature after it
    let approval_re = Regex::new(r"(?m)^\[editorial_approval\]")?;
    if approval_re.is_match(&new_frontmatter) {
        // Check if there are already signatures
        let has_sigs = Regex::new(r"(?m)^\[\[editorial_signatures\]\]")?.is_match(&new_frontmatter);

        if has_sigs {
            // Add after last signature entry
            // Find the last occurrence of [[editorial_signatures]]
            let last_sig_re = Regex::new(r"(?ms)(\[\[editorial_signatures\]\][^\[]*)")?;
            let matches: Vec<_> = last_sig_re.find_iter(&new_frontmatter).collect();
            if let Some(last_match) = matches.last() {
                let insert_pos = last_match.end();
                new_frontmatter.insert_str(insert_pos, &sig_entry);
            }
        } else {
            // Add after [editorial_approval] section
            let status_re = Regex::new(r#"(?m)^status\s*=\s*".*"$"#)?;
            if status_re.is_match(&new_frontmatter) {
                new_frontmatter = status_re.replace(&new_frontmatter, |caps: &regex::Captures| {
                    format!("{}{}", &caps[0], sig_entry)
                }).to_string();
            }
        }
    } else {
        bail!("No [editorial_approval] section found. Article must be signed by author first.");
    }

    // Count signatures and update status if threshold reached
    let sig_count_re = Regex::new(r"(?m)^\[\[editorial_signatures\]\]")?;
    let sig_count = sig_count_re.find_iter(&new_frontmatter).count() + 1; // +1 for the one we're adding

    // Extract threshold from config.toml or frontmatter
    let threshold_re = Regex::new(r#"(?m)^required\s*=\s*(\d+)$"#)?;
    let threshold = threshold_re.captures(&new_frontmatter)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<usize>().ok())
        .unwrap_or(3);

    println!("{}", style(format!("Step 3: Checking threshold ({}/{} signatures)", sig_count, threshold)).yellow());

    // Update status if threshold reached
    if sig_count >= threshold {
        let status_re = Regex::new(r#"(?m)^status\s*=\s*".*"$"#)?;
        new_frontmatter = status_re.replace(&new_frontmatter, r#"status = "approved""#).to_string();
        println!("{}", style("✅ Threshold reached! Article approved for publication.").green().bold());

        // Create OpenTimestamp proof of approval
        println!();
        let ots_path = article_path.with_extension("md.ots");
        try_create_opentimestamp(&hash_hex, &ots_path);
    } else {
        println!("{}", style(format!("⏳ {} more signature(s) needed", threshold - sig_count)).yellow());
    }

    // Write updated article
    let new_content = format!("+++{}+++{}", new_frontmatter, body);
    std::fs::write(article_path, new_content)?;

    println!("{}", style(format!("✅ Editorial {} recorded successfully!", decision)).green().bold());
    println!();
    println!("{}", style("📋 Review hash:").yellow());
    println!("   {}...", style(&review_hash_hex[..32]).cyan());
    println!("{}", style(format!("✍️  {} signature:", member_name)).yellow());
    println!("   {}...", style(&signature_hex[..32]).cyan());

    Ok(())
}

fn board_list() -> Result<()> {
    println!("{}", style("📋 Editorial Board Members").cyan().bold());
    println!();

    // Check if config.toml has board members
    let config_path = Path::new("config.toml");
    let config = std::fs::read_to_string(config_path)
        .context("Failed to read config.toml")?;

    let member_re = Regex::new(r#"(?m)^\[\[extra\.editorial_board\.members\]\]"#)?;
    if !member_re.is_match(&config) {
        println!("{}", style("No board members found in config.toml").yellow());
        println!();
        println!("Add members with:");
        println!("  {}", style("cargo run -p xtask -- board-keygen --name \"Name\" --id member-id --role \"Role\"").cyan());
        return Ok(());
    }

    // Parse board members from config.toml (simple approach)
    let id_re = Regex::new(r#"(?m)^id\s*=\s*"(.+)"$"#)?;
    let name_re = Regex::new(r#"(?m)^name\s*=\s*"(.+)"$"#)?;
    let role_re = Regex::new(r#"(?m)^role\s*=\s*"(.+)"$"#)?;
    let active_re = Regex::new(r#"(?m)^active\s*=\s*(true|false)$"#)?;

    println!("| ID | Name | Role | Status |");
    println!("|---|---|---|---|");

    // This is a simplified parser - in production would use proper TOML parsing
    for section in config.split("[[extra.editorial_board.members]]").skip(1) {
        let id = id_re.captures(section).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("?");
        let name = name_re.captures(section).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("?");
        let role = role_re.captures(section).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("?");
        let active = active_re.captures(section).and_then(|c| c.get(1)).map(|m| m.as_str() == "true").unwrap_or(false);

        let status = if active { "✅ Active" } else { "❌ Inactive" };
        println!("| {} | {} | {} | {} |", id, name, role, status);
    }

    Ok(())
}

fn verify_article(article_path: &Path) -> Result<()> {
    println!("{}", style(format!("🔐 Verifying all signatures: {}", article_path.display())).cyan().bold());

    // Step 1: Verify author signature
    println!();
    println!("{}", style("Step 1: Verifying author signature...").yellow());
    verify_author(article_path)?;

    // Step 2: Verify editorial signatures
    println!();
    println!("{}", style("Step 2: Verifying editorial signatures...").yellow());

    let (_, frontmatter, body) = parse_file(article_path)?;

    // Extract author signature
    let author_sig_re = Regex::new(r#"(?m)^signature\s*=\s*"(.+)"$"#)?;
    let author_signature = author_sig_re.captures(&frontmatter)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .ok_or_else(|| anyhow::anyhow!("No author signature found"))?;

    // Calculate article hash
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    // Create review hash
    let review_data = format!("{}{}", hash_hex, author_signature);
    let mut hasher = Sha256::new();
    hasher.update(review_data.as_bytes());
    let review_hash = hasher.finalize();
    let review_hash_hex = hex::encode(&review_hash);

    // Load config.toml for board member public keys
    let config_path = Path::new("config.toml");
    let config = std::fs::read_to_string(config_path)
        .context("Failed to read config.toml")?;

    // Extract threshold
    let threshold_re = Regex::new(r#"(?m)^required\s*=\s*(\d+)$"#)?;
    let threshold = threshold_re.captures(&frontmatter)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<usize>().ok())
        .unwrap_or(3);

    // Find all editorial signatures in frontmatter
    let sig_sections: Vec<&str> = frontmatter
        .split("[[editorial_signatures]]")
        .skip(1)
        .collect();

    if sig_sections.is_empty() {
        println!("{}", style("⚠️  No editorial signatures found").yellow());
        println!("   Article needs editorial review.");
        return Ok(());
    }

    let member_id_re = Regex::new(r#"(?m)^board_member\s*=\s*"(.+)"$"#)?;
    let sig_re = Regex::new(r#"(?m)^signature\s*=\s*"(.+)"$"#)?;
    let decision_re = Regex::new(r#"(?m)^decision\s*=\s*"(.+)"$"#)?;

    let mut valid_signatures = 0;

    for (i, section) in sig_sections.iter().enumerate() {
        let member_id = member_id_re.captures(section)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .ok_or_else(|| anyhow::anyhow!("Signature {} missing board_member", i + 1))?;

        let signature_hex = sig_re.captures(section)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .ok_or_else(|| anyhow::anyhow!("Signature {} missing signature", i + 1))?;

        let decision = decision_re.captures(section)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .unwrap_or("approve");

        // Find board member public key in config.toml
        // Match the entire [[extra.editorial_board.members]] section for this member
        let member_section_pattern = format!(
            r#"(?ms)\[\[extra\.editorial_board\.members\]\]\s*\nid\s*=\s*"{}"\s*\n(?:[^\[]|\[[^\[])*"#,
            regex::escape(member_id)
        );
        let member_section_re = Regex::new(&member_section_pattern)?;
        let member_section = member_section_re.find(&config)
            .ok_or_else(|| anyhow::anyhow!("Board member '{}' not found in config.toml", member_id))?;

        let pubkey_re = Regex::new(r#"(?m)^pubkey\s*=\s*"(.+)"$"#)?;
        let active_re = Regex::new(r#"(?m)^active\s*=\s*(true|false)$"#)?;

        let member_pubkey = pubkey_re.captures(member_section.as_str())
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .ok_or_else(|| anyhow::anyhow!("Board member '{}' has no public key", member_id))?;

        let is_active = active_re.captures(member_section.as_str())
            .and_then(|c| c.get(1))
            .map(|m| m.as_str() == "true")
            .unwrap_or(false);

        if !is_active {
            println!("   ⚠️  Signature {}: {} (INACTIVE - skipped)", i + 1, member_id);
            continue;
        }

        // Verify signature
        let pubkey_bytes = hex::decode(member_pubkey)
            .context("Failed to decode board member public key")?;
        let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Board member public key must be 32 bytes"))?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_array)
            .context("Invalid board member public key")?;

        let sig_bytes = hex::decode(signature_hex)
            .context("Failed to decode editorial signature")?;
        let sig_array: [u8; 64] = sig_bytes.try_into()
            .map_err(|_| anyhow::anyhow!("Editorial signature must be 64 bytes"))?;
        let signature = Signature::from_bytes(&sig_array);

        match verifying_key.verify(review_hash_hex.as_bytes(), &signature) {
            Ok(_) => {
                println!("   ✅ Signature {}: {} ({})", i + 1, member_id, decision);
                if decision == "approve" {
                    valid_signatures += 1;
                }
            }
            Err(_) => {
                println!("   ❌ Signature {}: {} (INVALID)", i + 1, member_id);
            }
        }
    }

    println!();
    println!("{}", style(format!("📊 Summary: {}/{} valid approval signatures", valid_signatures, threshold)).yellow());

    if valid_signatures >= threshold {
        println!("{}", style("✅ Article meets publication threshold!").green().bold());
    } else {
        println!("{}", style(format!("⏳ Article needs {} more approval(s)", threshold - valid_signatures)).yellow());
    }

    Ok(())
}

// ============================================================================
// OPENTIMESTAMPS INTEGRATION
// ============================================================================

/// Submit a hash to OpenTimestamps calendar servers and create .ots file
fn create_opentimestamp(hash_hex: &str, output_path: &Path) -> Result<()> {
    println!("{}", style("⏱️  Creating OpenTimestamp proof...").cyan());
    
    // Decode the hash
    let hash_bytes = hex::decode(hash_hex)
        .context("Failed to decode hash for timestamping")?;
    
    // Submit to OpenTimestamps calendar server
    let client = reqwest::blocking::Client::new();
    let calendar_url = "https://a.pool.opentimestamps.org/digest";
    
    let response = client
        .post(calendar_url)
        .header("Content-Type", "application/octet-stream")
        .body(hash_bytes.clone())
        .send()
        .context("Failed to submit to OpenTimestamps calendar")?;
    
    if !response.status().is_success() {
        bail!("OpenTimestamps calendar returned error: {}", response.status());
    }
    
    let ots_data = response.bytes()
        .context("Failed to read OpenTimestamps response")?;
    
    // Write .ots file
    std::fs::write(output_path, ots_data)
        .context("Failed to write .ots file")?;
    
    println!("{}", style(format!("✅ Timestamp proof created: {}", output_path.display())).green());
    println!("{}", style("   This proof can be verified against the Bitcoin blockchain").dim());
    
    Ok(())
}

/// Attempt to create OpenTimestamp with graceful fallback
fn try_create_opentimestamp(hash_hex: &str, output_path: &Path) {
    match create_opentimestamp(hash_hex, output_path) {
        Ok(_) => {}
        Err(e) => {
            println!("{}", style(format!("⚠️  OpenTimestamp failed (non-critical): {}", e)).yellow());
            println!("{}", style("   Article is still valid without timestamp. You can timestamp manually later.").dim());
        }
    }
}
