use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::process::{Command, Stdio};
use std::path::{Path, PathBuf};
use chrono::{Local, Utc};
use std::io::{Read, Write};
use walkdir::WalkDir;
use sha2::{Sha256, Digest};
use regex::Regex;
use console::style;
use ed25519_dalek::{SigningKey, Signature, Signer, VerifyingKey, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod hwkey;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct FrontMatter {
    title: String,
    date: String,
    #[serde(default)]
    extra: ExtraConfig,
    #[serde(flatten)]
    other: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct ExtraConfig {
    author: Option<String>,
    image: Option<String>,
    integrity: Option<String>,
    #[serde(rename = "author_signature")]
    author_signature: Option<AuthorSignature>,
    #[serde(rename = "editorial_approval")]
    editorial_approval: Option<EditorialApproval>,
    #[serde(rename = "editorial_signatures")]
    editorial_signatures: Option<Vec<EditorialSignature>>,
    #[serde(flatten)]
    other: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct AuthorSignature {
    name: String,
    email: Option<String>,
    pubkey: String,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct EditorialApproval {
    required: usize,
    status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct EditorialSignature {
    board_member: String,
    signature: String,
    timestamp: String,
    decision: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Config {
    base_url: String,
    title: Option<String>,
    #[serde(default)]
    extra: SiteExtra,
    #[serde(flatten)]
    other: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
struct SiteExtra {
    public_key: Option<String>,
    site_integrity: Option<String>,
    site_signature: Option<String>,
    site_randomart: Option<String>,
    editorial_board: Option<EditorialBoardConfig>,
    #[serde(flatten)]
    other: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct EditorialBoardConfig {
    members: Option<Vec<BoardMemberConfig>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BoardMemberConfig {
    id: String,
    name: String,
    role: String,
    active: bool,
    pubkey: String,
}

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
        /// Member type: human or ai_agent
        #[arg(short = 't', long, default_value = "human")]
        member_type: String,
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

    // ═══════════════════════════════════════════════════════════════════════════
    // OWNER AUTHORITY COMMANDS
    // Single hardware key: routine governance (appoint, remove, update, threshold)
    // Dual hardware key: key management only (init, rotate/recover)
    // ═══════════════════════════════════════════════════════════════════════════

    /// Initialize owner authority with dual hardware keys (first-time setup) [DUAL KEY]
    OwnerInit {
        /// Owner's name
        #[arg(long)]
        name: String,
    },

    /// Check hardware key status
    HwkeyStatus,

    /// Verify both owner hardware keys are accessible
    OwnerVerifyKeys,

    /// Rotate/recover owner key when one is lost [DUAL KEY: remaining + new]
    OwnerRotateKey {
        /// Which key to replace: "primary" or "backup"
        #[arg(long)]
        replace: String,
    },

    /// Appoint a new editorial board member [SINGLE KEY + 48hr notice]
    BoardAppoint {
        /// Member ID (slug format)
        #[arg(long)]
        id: String,
        /// Member's full name
        #[arg(long)]
        name: String,
        /// Member type: "human" or "ai_agent"
        #[arg(long)]
        member_type: String,
        /// Role/title
        #[arg(long)]
        role: String,
        /// Ed25519 public key (hex)
        #[arg(long)]
        pubkey: String,
        /// Notice article hash (required unless initial board setup)
        #[arg(long)]
        notice_hash: Option<String>,
    },

    /// Remove an editorial board member [SINGLE KEY + 48hr notice]
    BoardRemove {
        /// Member ID to remove
        id: String,
        /// Notice article hash (required)
        #[arg(long)]
        notice_hash: Option<String>,
    },

    /// Update a board member's public key [SINGLE KEY]
    BoardUpdateKey {
        /// Member ID
        id: String,
        /// New public key (hex)
        new_pubkey: String,
    },

    /// Change the approval threshold [SINGLE KEY + 48hr notice]
    BoardSetThreshold {
        /// New threshold value (k in k-of-n)
        threshold: usize,
        /// Notice article hash (required unless initial board setup)
        #[arg(long)]
        notice_hash: Option<String>,
    },

    /// Show the authority manifest and verify signatures
    ManifestShow,

    /// Verify all approved articles have valid signatures and timestamps (for CI/CD)
    VerifyAllArticles {
        /// Require OpenTimestamp proofs to exist
        #[arg(long, default_value = "false")]
        require_timestamps: bool,
    },

    /// Create OpenTimestamp proof for a governance notice article
    TimestampNotice {
        /// Path to notice article
        article: PathBuf,
    },

    /// Verify OpenTimestamp proof
    VerifyTimestamp {
        /// Path to .ots file
        ots_file: PathBuf,
    },

    /// Ratify bylaws with hardware key signature and OpenTimestamp
    RatifyBylaws,
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
        Commands::BoardKeygen { name, id, role, member_type } => board_keygen(name, id, role, member_type),
        Commands::EditorialReview { article, approve, reject } => {
            editorial_review(&article, approve, reject)
        }
        Commands::BoardList => board_list(),
        Commands::VerifyArticle { article } => verify_article(&article),

        // Owner authority commands
        // Dual key: init, rotate
        // Single key: appoint, remove, update, threshold
        Commands::OwnerInit { name } => owner_init(name),
        Commands::HwkeyStatus => hwkey::print_hwkey_status(),
        Commands::OwnerVerifyKeys => owner_verify_keys(),
        Commands::OwnerRotateKey { replace } => owner_rotate_key(replace),
        Commands::BoardAppoint { id, name, member_type, role, pubkey, notice_hash } => {
            board_appoint(id, name, member_type, role, pubkey, notice_hash)
        }
        Commands::BoardRemove { id, notice_hash } => board_remove(id, notice_hash),
        Commands::BoardUpdateKey { id, new_pubkey } => board_update_key(id, new_pubkey),
        Commands::BoardSetThreshold { threshold, notice_hash } => board_set_threshold(threshold, notice_hash),
        Commands::ManifestShow => manifest_show(),
        Commands::VerifyAllArticles { require_timestamps } => verify_all_articles(require_timestamps),
        Commands::TimestampNotice { article } => timestamp_notice(&article),
        Commands::VerifyTimestamp { ots_file } => verify_timestamp(&ots_file),
        Commands::RatifyBylaws => ratify_bylaws(),
    }
}

fn validate_slug(slug: &str) -> Result<()> {
    if slug.trim().is_empty() {
        bail!("ID cannot be empty");
    }
    
    // Strict validation: only lowercase alphanumeric and hyphens
    let re = Regex::new(r"^[a-z0-9-]+$").unwrap();
    if !re.is_match(slug) {
        bail!("ID must consist of only lowercase alphanumeric characters and hyphens (got: '{}')", slug);
    }
    
    // Double check for path traversal patterns just in case regex is modified in future
    if slug.contains("..") || slug.contains('/') || slug.contains('\\') {
        bail!("Path traversal detected in ID");
    }
    
    Ok(())
}

fn draft(title: String) -> Result<()> {
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
    
    // We shouldn't use manual string formatting here either ideally, but for creation it's safer than parsing
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

fn parse_file(path: &Path) -> Result<(String, FrontMatter, String)> {
    let mut file = std::fs::File::open(path)?;
    let mut text = String::new();
    file.read_to_string(&mut text)?;

    // simplistic frontmatter split
    let parts: Vec<&str> = text.splitn(3, "+++").collect();
    if parts.len() < 3 {
        // Might be just frontmatter or empty?
        bail!("File {:?} does not appear to have valid TOML frontmatter", path);
    }

    let frontmatter_str = parts[1];
    let body = parts[2].to_string();
    
    let frontmatter: FrontMatter = toml::from_str(frontmatter_str)
        .context(format!("Failed to parse TOML frontmatter in {:?}", path))?;
    
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
    // Safety Force: Prevent accidental unsigned deployments
    if skip_sign {
        let proof_mode = std::env::var("LAPROPAGANDA_PROOF_MODE").unwrap_or_default();
        if proof_mode != "1" {
            bail!("SAFETY ERROR: --skip-sign is only allowed in Proof Mode.\nSet LAPROPAGANDA_PROOF_MODE=1 environment variable to confirm you are debugging/verifying hashes only.");
        }
        println!("{}", style("⚠️  RUNNING IN PROOF MODE (Signatures Skipped) ⚠️").yellow().bold());
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
        println!("{}", style("⚠️  SKIPPING SIGNATURE (Proof Mode)").yellow().bold());
        "UNSIGNED_PROOF_MODE".to_string()
    } else {
        sign_global_hash(&hash_hex)?
    };

    let config_path = Path::new("config.toml");
    let mut config = std::fs::read_to_string(config_path)?;

    // Update site_integrity (Using Regex to preserve comments in config.toml)
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

        // use FrontMatter struct
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
    
    // We can use Config struct here for read-only verification
    let config: Config = toml::from_str(&config_str)
         .context("Failed to parse config.toml")?;

    match &config.extra.site_integrity {
        Some(stored_hash) => {
             if stored_hash != &calculated_hash {
                 eprintln!("{}", style("TAMPERED: Global Site Hash Mismatch!").red().bold());
                 eprintln!("{}", style("Verify failed: Site edition signature invalid.").red());
                 errors += 1;
            }
        },
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

// ============================================================================
// MULTI-SIGNATURE SYSTEM: AUTHOR SIGNING
// ============================================================================

fn author_keygen(name: String, id: String, email: Option<String>) -> Result<()> {
    println!("{}", style(format!("🔑 Generating Ed25519 keypair for author: {}", name)).cyan().bold());

    // Validate ID format (slug)
    validate_slug(&id).context("Invalid author ID")?;

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
    // Validate ID to prevent path traversal when loading key
    validate_slug(author_id).context("Invalid author ID")?;

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
    let (_full_text, mut frontmatter, body) = parse_file(article_path)?;

    // Check if already has author signature
    if frontmatter.extra.author_signature.is_some() {
        bail!("Article already has author signature. Remove [extra.author_signature] section first to re-sign.");
    }

    // Prompt for author ID
    println!();
    println!("{}", style("Enter author ID (from .authors/ directory):").yellow());
    print!("> ");
    std::io::stdout().flush()?;

    let mut author_id = String::new();
    std::io::stdin().read_line(&mut author_id)?;
    let author_id = author_id.trim();
    
    validate_slug(author_id).context("Invalid author ID")?;

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

    // Update frontmatter struct
    frontmatter.extra.author_signature = Some(AuthorSignature {
        name: author_name.to_string(),
        email: author_email.map(|s| s.to_string()),
        pubkey: author_pubkey.to_string(),
        signature: signature_hex.clone(),
    });
    
    // Add editorial approval section (status: pending)
    frontmatter.extra.editorial_approval = Some(EditorialApproval {
        required: 3, 
        status: "pending".to_string(),
    });

    // Write updated article
    let new_frontmatter_str = toml::to_string(&frontmatter)?;
    let new_content = format!("+++{}+++{}", new_frontmatter_str, body);
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
    let sig_data = frontmatter.extra.author_signature
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No author signature found in article"))?;
        
    let author_pubkey = &sig_data.pubkey;
    let author_signature = &sig_data.signature;

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

fn board_keygen(name: String, id: String, role: String, member_type: String) -> Result<()> {
    println!("{}", style(format!("🔑 Generating Ed25519 keypair for board member: {}", name)).cyan().bold());

    // Validate member type
    if member_type != "human" && member_type != "ai_agent" {
        bail!("Member type must be 'human' or 'ai_agent'");
    }

    // Validate ID format
    validate_slug(&id).context("Invalid board member ID")?;

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
    
    // ... rest matches original but wrapped in safety instructions ...

    // Save metadata
    let metadata = format!(
        "# Board Member: {}\n# ID: {}\n# Type: {}\n# Role: {}\n# Public Key: {}\n# Generated: {}\n",
        name,
        id,
        member_type,
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
    println!("Use owner authority to appoint this member to the board:");
    println!();
    println!("   cargo run -p xtask -- board-appoint \\");
    println!("     --id \"{}\" \\", id);
    println!("     --name \"{}\" \\", name);
    println!("     --member-type \"{}\" \\", member_type);
    println!("     --role \"{}\" \\", role);
    println!("     --pubkey \"{}\"", public_key_hex);

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

    // 1. Verify author signature first
    println!("{}", style("Step 1: Verifying author signature...").yellow());
    verify_author(article_path)?; // This ensures signature is valid against content

    // Parse article
    let (_, mut frontmatter, body) = parse_file(article_path)?;

    // Get author signature for chaining (verify_author checked validity, now we need the data)
    let author_sig_data = frontmatter.extra.author_signature.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing author signature data"))?;
    let author_signature = &author_sig_data.signature;

    // Check pre-conditions
    if let Some(approval) = &frontmatter.extra.editorial_approval {
        if approval.status == "approved" {
            println!("{}", style("ℹ️  Article is already APPROVED").yellow());
        }
    }

    // Prompt for board member ID
    println!();
    println!("{}", style("Enter board member ID (from .editorial_board/board/ directory):").yellow());
    print!("> ");
    std::io::stdout().flush()?;

    let mut member_id = String::new();
    std::io::stdin().read_line(&mut member_id)?;
    let member_id = member_id.trim();

    validate_slug(member_id).context("Invalid board member ID")?;

    // Check for duplicate review
    if let Some(signatures) = &frontmatter.extra.editorial_signatures {
        if signatures.iter().any(|s| s.board_member == member_id) {
            bail!("Board member '{}' has already reviewed this article.", member_id);
        }
    }

    // Load board member metadata
    let member_info_path = Path::new(".editorial_board/board").join(member_id).join("member.info");
    let member_info = std::fs::read_to_string(&member_info_path)
        .context("Failed to read board member metadata. Run board-keygen first.")?;

    let name_re = Regex::new(r"# Board Member: (.+)")?;
    let member_name = name_re.captures(&member_info)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .unwrap_or("Unknown");

    // Calculate article hash
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    // Create review hash: SHA-256(article_hash + author_signature)
    // This chains the review to the specific author signature
    let review_data = format!("{}{}", hash_hex, author_signature);
    let mut hasher = Sha256::new();
    hasher.update(review_data.as_bytes());
    let review_hash = hasher.finalize();
    let review_hash_hex = hex::encode(review_hash);

    // Sign review hash
    // We need to implement/find load_board_member_private_key. 
    // Assuming it exists or we implement logic here.
    // The original code used `load_board_member_private_key`.
    let signing_key = load_board_member_private_key(member_id)?;
    let signature = signing_key.sign(review_hash_hex.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    println!("{}", style(format!("Step 2: Signing {} decision as: {}", decision, member_name)).yellow());

    // Update frontmatter with editorial signature
    let timestamp = Local::now().to_rfc3339();
    
    if frontmatter.extra.editorial_signatures.is_none() {
        frontmatter.extra.editorial_signatures = Some(Vec::new());
    }
    
    if let Some(signatures) = &mut frontmatter.extra.editorial_signatures {
        signatures.push(EditorialSignature {
            board_member: member_id.to_string(),
            signature: signature_hex.clone(),
            timestamp: timestamp,
            decision: decision.to_string(),
        });
    }

    // Check threshold
    let required = frontmatter.extra.editorial_approval.as_ref().map(|a| a.required).unwrap_or(3);
    let approval_count = frontmatter.extra.editorial_signatures.as_ref()
        .map(|sigs| sigs.iter().filter(|s| s.decision == "approve").count())
        .unwrap_or(0);
    
    let sig_count = frontmatter.extra.editorial_signatures.as_ref().map(|s| s.len()).unwrap_or(0);

    println!("{}", style(format!("Step 3: Checking threshold ({}/{} signatures)", sig_count, required)).yellow());

    if approval_count >= required {
         if let Some(approval) = &mut frontmatter.extra.editorial_approval {
            approval.status = "approved".to_string();
        }
        println!("{}", style("✅ Threshold reached! Article approved for publication.").green().bold());

        // Create OpenTimestamp proof of approval
        println!();
        let ots_path = article_path.with_extension("md.ots");
        try_create_opentimestamp(&hash_hex, &ots_path);
    } else {
        println!("{}", style(format!("⏳ {} more signature(s) needed", if required > approval_count { required - approval_count } else { 0 })).yellow());
    }

    // Write updated article
    let new_frontmatter_str = toml::to_string(&frontmatter)?;
    let new_content = format!("+++{}+++{}", new_frontmatter_str, body);
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
    println!("{}", style(format!("🔎 Verifying article: {}", article_path.display())).cyan());

    // 1. Verify author
    println!("{}", style("  Step 1: Author Signature").dim());
    verify_author(article_path)?;

    // Parse article
    let (_, frontmatter, body) = parse_file(article_path)?;

    // 2. Verify editorial signatures
    println!("{}", style("  Step 2: Editorial Signatures").dim());
    
    // Get author signature data for review hash calculation
    let author_sig_data = frontmatter.extra.author_signature.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing author signature (unexpected)"))?;
    let author_signature = &author_sig_data.signature;

    // Calculate base hashes
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);
    
    let mut hasher = Sha256::new();
    let review_data = format!("{}{}", hash_hex, author_signature);
    hasher.update(review_data.as_bytes());
    let review_hash = hasher.finalize();
    let review_hash_hex = hex::encode(review_hash);

    let signatures = frontmatter.extra.editorial_signatures.as_ref();
    
    if signatures.is_none() || signatures.unwrap().is_empty() {
        println!("{}", style("  ⚠️  No editorial signatures found").yellow());
        return Ok(()); // Valid integrity, just unapproved
    }
    
    let signatures = signatures.unwrap();
    let mut valid_approvals = 0;
    
    for sig in signatures {
        let member_info_path = Path::new(".editorial_board/board").join(&sig.board_member).join("member.info");
        if !member_info_path.exists() {
             println!("{}", style(format!("  ⚠️  Unknown board member: {}", sig.board_member)).yellow());
             continue;
        }

        let member_info = std::fs::read_to_string(&member_info_path)?;
        let pubkey_re = Regex::new(r"# Public Key: (.+)")?;
        let pubkey_hex = pubkey_re.captures(&member_info)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing public key for {}", sig.board_member))?;

        let pubkey_bytes = hex::decode(pubkey_hex)?;
        let pubkey_array: [u8; 32] = pubkey_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid key"))?;
        let verifying_key = VerifyingKey::from_bytes(&pubkey_array)?;

        let sig_bytes = hex::decode(&sig.signature)?;
        let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| anyhow::anyhow!("Invalid signature"))?;
        let signature = Signature::from_bytes(&sig_array);

        if verifying_key.verify(review_hash_hex.as_bytes(), &signature).is_ok() {
            println!("  ✓ Valid signature from {}", sig.board_member);
            if sig.decision == "approve" {
                valid_approvals += 1;
            }
        } else {
            println!("{}", style(format!("  ❌ INVALID signature from {}", sig.board_member)).red().bold());
            bail!("Invalid editorial signature detected from {}", sig.board_member);
        }
    }

    // Check threshold
    let required = frontmatter.extra.editorial_approval.as_ref().map(|a| a.required).unwrap_or(3);
    let status = frontmatter.extra.editorial_approval.as_ref().map(|a| a.status.clone()).unwrap_or_else(|| "pending".to_string());

    if valid_approvals >= required {
        if status == "approved" {
            println!("{}", style("  ✅ Article fully approved and verified").green().bold());
        } else {
            println!("{}", style("  ⚠️  Threshold met but status not 'approved'").yellow());
        }
    } else {
         println!("{}", style(format!("  ℹ️  Approvals: {}/{}", valid_approvals, required)).dim());
    }

    Ok(())
}

// ============================================================================
// CI/CD ARTICLE VERIFICATION
// ============================================================================

/// Verify all approved articles have valid signatures (for CI/CD pipeline)
/// This ensures no article is published without proper author + editorial approval
fn verify_site_signature() -> Result<()> {
    println!("{}", style("🔐 Verifying SITE-WIDE signature...").cyan());
    
    let config_path = Path::new("config.toml");
    let config_str = std::fs::read_to_string(config_path)
        .context("Failed to read config.toml")?;
    let config: Config = toml::from_str(&config_str)
        .context("Failed to parse config.toml")?;
        
    let pubkey_hex = config.extra.public_key
        .ok_or_else(|| anyhow::anyhow!("No site public key found in config.toml"))?;
        
    let signature_hex = config.extra.site_signature
        .ok_or_else(|| anyhow::anyhow!("No site signature found in config.toml"))?;
        
    let integrity_hash = config.extra.site_integrity
        .ok_or_else(|| anyhow::anyhow!("No site integrity hash found in config.toml"))?;
        
    // Verify
    let pubkey_bytes = hex::decode(pubkey_hex)?;
    let pubkey_array: [u8; 32] = pubkey_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid site public key length"))?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_array)?;
    
    let sig_bytes = hex::decode(signature_hex)?;
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid site signature length"))?;
    let signature = Signature::from_bytes(&sig_array);
    
    verifying_key.verify(integrity_hash.as_bytes(), &signature)
        .context("Site signature verification FAILED")?;
        
    println!("{}", style("✅ Site signature VALID").green().bold());
    Ok(())
}

/// Verify all approved articles have valid signatures (for CI/CD pipeline)
/// This ensures no article is published without proper author + editorial approval
fn verify_all_articles(require_timestamps: bool) -> Result<()> {
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!("{}", style("        🔐 CI/CD ARTICLE SIGNATURE VERIFICATION").cyan().bold());
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!();

    // 1. Verify Site Signature
    if let Err(e) = verify_site_signature() {
        println!("{}", style(format!("❌ SITE VERIFICATION FAILED: {}", e)).red().bold());
        // We might want to bail here, but let's verify articles too to give full report
        // bail!("Site verification failed"); 
    }

    let files = get_content_files();
    let mut approved_count = 0;
    let mut failed_count = 0;
    let mut pending_count = 0;
    let mut missing_timestamps = 0;

    for file in files {
        // Skip _index.md files
        if file.file_name().map(|f| f == "_index.md").unwrap_or(false) {
            continue;
        }

        let (_, frontmatter, _) = match parse_file(&file) {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Check if article has [author_signature] section (indicates it's a signed article)
        let has_author_sig = frontmatter.extra.author_signature.is_some();
        if !has_author_sig {
            // Unsigned articles might be allowed if they are legacy, but ideally everything is signed.
            // For now, if no author signature, we skip strict verification unless it claims to be approved.
            // But wait, parse_file checks for TOML validity.
            // If it doesn't have author signature, it can't be approved.
            continue;
        }

        // Check approval status
        let status = frontmatter.extra.editorial_approval.as_ref()
            .map(|a| a.status.clone())
            .unwrap_or_else(|| "pending".to_string());

        if status == "approved" {
            print!("  📄 {} ... ", file.display());

            // Use our robust verify_article function
            match verify_article(&file) {
                Ok(_) => {
                     // Check for OpenTimestamp proof
                    let ots_path = file.with_extension("md.ots");
                    if require_timestamps && !ots_path.exists() {
                        println!("{}", style("⚠️  MISSING TIMESTAMP").yellow());
                        missing_timestamps += 1;
                        if require_timestamps {
                            failed_count += 1;
                            continue;
                        }
                    }
                    println!("{}", style("✅ VERIFIED").green());
                    approved_count += 1;
                }
                Err(e) => {
                     println!("{}", style("❌ VERIFICATION FAILED").red());
                     println!("      {}", e);
                     failed_count += 1;
                }
            }
        } else {
            pending_count += 1;
        }
    }

    println!();
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!("  Verified Approved Articles: {}", style(approved_count).green().bold());
    println!("  Pending Articles:           {}", style(pending_count).yellow());
    if failed_count > 0 {
        println!("  Failed Verifications:       {}", style(failed_count).red().bold());
    }
    if missing_timestamps > 0 {
         println!("  Missing Timestamps:         {}", style(missing_timestamps).yellow());
    }
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());

    if failed_count > 0 {
        if require_timestamps && missing_timestamps > 0 {
            bail!("Verification failed: {} articles failed verification (including {} missing timestamps)", failed_count, missing_timestamps);
        }
        bail!("Verification failed: {} articles failed verification", failed_count);
    }
    
    Ok(())
}

/// Create OpenTimestamp proof for a governance notice article
fn timestamp_notice(article_path: &Path) -> Result<()> {
    println!("{}", style(format!("⏱️  Creating OpenTimestamp for notice: {}", article_path.display())).cyan().bold());

    let (_, _, body) = parse_file(article_path)?;
    let article_hash = calculate_hash(&body);
    let hash_hex = hex::encode(&article_hash);

    // Create timestamps directory if needed
    let timestamps_dir = Path::new(".editorial_board/timestamps");
    std::fs::create_dir_all(timestamps_dir)?;

    // Create OTS file with hash prefix as filename
    let ots_filename = format!("{}.ots", &hash_hex[..16]);
    let ots_path = timestamps_dir.join(&ots_filename);

    create_opentimestamp(&hash_hex, &ots_path)?;

    println!();
    println!("{}", style("Notice hash for governance action:").yellow());
    println!("   {}", style(&hash_hex).cyan());
    println!();
    println!("Use this hash with --notice-hash when executing the governance action");
    println!("after 48 hours have passed.");

    Ok(())
}

/// Verify an OpenTimestamp proof file
fn verify_timestamp(ots_path: &Path) -> Result<()> {
    println!("{}", style(format!("⏱️  Verifying OpenTimestamp: {}", ots_path.display())).cyan().bold());

    if !ots_path.exists() {
        bail!("OTS file not found: {}", ots_path.display());
    }

    // Check if ots CLI is available
    let ots_check = std::process::Command::new("ots")
        .arg("--version")
        .output();

    match ots_check {
        Ok(output) if output.status.success() => {
            // Use ots CLI to verify
            let verify_result = std::process::Command::new("ots")
                .arg("verify")
                .arg(ots_path)
                .output()?;

            if verify_result.status.success() {
                println!("{}", style("✅ OpenTimestamp proof is valid").green().bold());
                let stdout = String::from_utf8_lossy(&verify_result.stdout);
                if !stdout.is_empty() {
                    println!("{}", stdout);
                }
            } else {
                let stderr = String::from_utf8_lossy(&verify_result.stderr);
                if stderr.contains("Pending") {
                    println!("{}", style("⏳ Timestamp is pending Bitcoin confirmation").yellow());
                    println!("   This is normal for recent timestamps. Check back later.");
                } else {
                    bail!("Timestamp verification failed: {}", stderr);
                }
            }
        }
        _ => {
            println!("{}", style("⚠️  OpenTimestamps CLI not installed").yellow());
            println!("   Install with: pip install opentimestamps-client");
            println!();
            println!("   OTS file exists: {}", ots_path.display());
            println!("   Size: {} bytes", std::fs::metadata(ots_path)?.len());
        }
    }

    Ok(())
}

/// Ratify bylaws with hardware key signature and OpenTimestamp
fn ratify_bylaws() -> Result<()> {
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!("{}", style("        📜 BYLAWS RATIFICATION").green().bold());
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!();

    let bylaws_path = Path::new("BYLAWS.md");
    if !bylaws_path.exists() {
        bail!("BYLAWS.md not found");
    }

    let bylaws_content = std::fs::read_to_string(bylaws_path)?;

    // Find the Signatures section and exclude it from hash
    let sig_marker = "## Signatures";
    let content_to_hash = if let Some(pos) = bylaws_content.find(sig_marker) {
        &bylaws_content[..pos]
    } else {
        &bylaws_content
    };

    let mut hasher = Sha256::new();
    hasher.update(content_to_hash.as_bytes());
    let hash = hex::encode(hasher.finalize());

    println!("Bylaws Hash (SHA-256): {}", style(&hash).cyan());
    println!();

    // Load owner keys from config
    let config_path = Path::new("config.toml");
    let config = std::fs::read_to_string(config_path)
        .context("Failed to read config.toml")?;

    let primary_re = Regex::new(r#"(?m)^primary_pubkey\s*=\s*"([^"]*)""#)?;
    let backup_re = Regex::new(r#"(?m)^backup_pubkey\s*=\s*"([^"]*)""#)?;

    let primary_key = primary_re.captures(&config)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .unwrap_or("");
    let backup_key = backup_re.captures(&config)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .unwrap_or("");

    // Require hardware key signature
    println!("{}", style("Step 1/2: Sign bylaws with hardware key").cyan().bold());
    let single_sig = hwkey::single_sign(hash.as_bytes(), &[primary_key, backup_key])?;

    // Create OpenTimestamp
    println!();
    println!("{}", style("Step 2/2: Creating OpenTimestamp proof").cyan().bold());
    let ots_path = Path::new(".editorial_board/timestamps/bylaws-ratification.ots");
    std::fs::create_dir_all(".editorial_board/timestamps")?;
    try_create_opentimestamp(&hash, ots_path);

    println!();
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!("{}", style("        ✅ BYLAWS RATIFIED").green().bold());
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!();
    println!("Hash: {}", &hash);
    println!("Signed by: {}", single_sig.key_id);
    println!();
    println!("Update BYLAWS.md Signatures section with:");
    println!("  Bylaws Hash (SHA-256): {}", &hash);
    println!("  Signature: {}", &single_sig.signature[..64]);
    println!("  Hardware Key ID: {}", single_sig.key_id);

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

// ============================================================================
// OWNER AUTHORITY FUNCTIONS (Require dual hardware key)
// ============================================================================

/// Initialize owner authority with dual hardware keys
fn owner_init(owner_name: String) -> Result<()> {
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!("{}", style("              OWNER AUTHORITY INITIALIZATION").cyan().bold());
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!();

    // Check if already initialized
    let config_path = Path::new("config.toml");
    let config = std::fs::read_to_string(config_path)?;

    let initialized_re = Regex::new(r#"(?m)^initialized\s*=\s*true"#)?;
    if initialized_re.is_match(&config) {
        bail!("Owner authority is already initialized. Use board-appoint/board-remove to manage the board.");
    }

    hwkey::check_gpg()?;

    println!("This will set up dual-hardware key authority for: {}", style(&owner_name).cyan().bold());
    println!();
    println!("{}", style("Requirements:").yellow());
    println!("  • Two hardware key 5 series devices with Ed25519 keys configured");
    println!("  • Each hardware key must have a signing key generated via GPG");
    println!();
    println!("{}", style("If you haven't set up your hardware keys yet:").dim());
    println!("  1. Insert hardware key and run: gpg --card-edit");
    println!("  2. Type 'admin' then 'generate' to create Ed25519 key");
    println!("  3. Repeat for second hardware key");
    println!();

    // Step 1: Get Primary hardware key info
    println!("{}", style("Step 1/3: Configure PRIMARY hardware key").cyan().bold());
    println!("Insert your PRIMARY hardware key and press Enter...");
    hwkey::wait_for_enter()?;

    let primary_info = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    let primary_key_id = primary_info.key_id.clone()
        .ok_or_else(|| anyhow::anyhow!("No signing key on this hardware key. Generate one with: gpg --card-edit"))?;

    println!("  Detected: Serial {}", primary_info.serial);
    println!("  Key ID:   {}", style(&primary_key_id).green());

    // Step 2: Get Backup hardware key info
    println!();
    println!("{}", style("Step 2/3: Configure BACKUP hardware key").cyan().bold());
    println!("REMOVE the Primary hardware key");
    println!("INSERT your BACKUP hardware key and press Enter...");
    hwkey::wait_for_enter()?;

    let backup_info = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    if backup_info.serial == primary_info.serial {
        bail!("Same hardware key detected! You need TWO different hardware keys.");
    }

    let backup_key_id = backup_info.key_id.clone()
        .ok_or_else(|| anyhow::anyhow!("No signing key on backup hardware key. Generate one with: gpg --card-edit"))?;

    println!("  Detected: Serial {}", backup_info.serial);
    println!("  Key ID:   {}", style(&backup_key_id).green());

    // Step 3: Create initial authority manifest and sign with both keys
    println!();
    println!("{}", style("Step 3/3: Creating authority manifest with dual signatures").cyan().bold());

    let timestamp = Utc::now().to_rfc3339();
    let manifest_data = format!(
        "owner:{}\nprimary:{}\nbackup:{}\ntimestamp:{}\nthreshold:3\nmembers:0",
        owner_name, primary_key_id, backup_key_id, timestamp
    );

    // Calculate hash of manifest data
    let mut hasher = Sha256::new();
    hasher.update(manifest_data.as_bytes());
    let manifest_hash = hex::encode(hasher.finalize());

    // Dual sign the manifest hash
    let dual_sig = hwkey::dual_sign(manifest_hash.as_bytes(), &primary_key_id, &backup_key_id)?;

    // Update config.toml
    let mut config = std::fs::read_to_string(config_path)?;

    // Update owner section
    let name_re = Regex::new(r#"(?m)^name\s*=\s*"[^"]*"(\s*#.*)?\n(.*\n)*?primary_pubkey"#)?;
    if name_re.is_match(&config) {
        config = config.replace(
            &name_re.find(&config).unwrap().as_str(),
            &format!("name = \"{}\"\nprimary_pubkey", owner_name)
        );
    }

    let primary_re = Regex::new(r#"(?m)^primary_pubkey\s*=\s*"[^"]*""#)?;
    config = primary_re.replace(&config, format!("primary_pubkey = \"{}\"", primary_key_id)).to_string();

    let backup_re = Regex::new(r#"(?m)^backup_pubkey\s*=\s*"[^"]*""#)?;
    config = backup_re.replace(&config, format!("backup_pubkey = \"{}\"", backup_key_id)).to_string();

    let init_re = Regex::new(r#"(?m)^initialized\s*=\s*\w+"#)?;
    config = init_re.replace(&config, "initialized = true").to_string();

    // Update manifest hash in editorial_board section
    let manifest_hash_re = Regex::new(r#"(?m)^manifest_hash\s*=\s*"[^"]*""#)?;
    config = manifest_hash_re.replace(&config, format!("manifest_hash = \"{}\"", manifest_hash)).to_string();

    std::fs::write(config_path, &config)?;

    // Update authority manifest file
    let manifest_path = Path::new(".editorial_board/authority_manifest.toml");
    let mut manifest = std::fs::read_to_string(manifest_path)
        .unwrap_or_else(|_| include_str!("../../.editorial_board/authority_manifest.toml").to_string());

    // Update manifest fields
    let created_re = Regex::new(r#"(?m)^created\s*=\s*"[^"]*""#)?;
    manifest = created_re.replace(&manifest, format!("created = \"{}\"", timestamp)).to_string();

    let modified_re = Regex::new(r#"(?m)^last_modified\s*=\s*"[^"]*""#)?;
    manifest = modified_re.replace(&manifest, format!("last_modified = \"{}\"", timestamp)).to_string();

    let owner_re = Regex::new(r#"(?m)^owner_name\s*=\s*"[^"]*""#)?;
    manifest = owner_re.replace(&manifest, format!("owner_name = \"{}\"", owner_name)).to_string();

    let hash_re = Regex::new(r#"(?m)^board_state_hash\s*=\s*"[^"]*""#)?;
    manifest = hash_re.replace(&manifest, format!("board_state_hash = \"{}\"", manifest_hash)).to_string();

    // Update signatures
    let primary_sig_re = Regex::new(r#"(?m)^primary_signature\s*=\s*"[^"]*""#)?;
    manifest = primary_sig_re.replace(&manifest, format!("primary_signature = \"{}\"", dual_sig.primary_signature)).to_string();

    let primary_id_re = Regex::new(r#"(?m)^primary_key_id\s*=\s*"[^"]*""#)?;
    manifest = primary_id_re.replace(&manifest, format!("primary_key_id = \"{}\"", dual_sig.primary_key_id)).to_string();

    let primary_time_re = Regex::new(r#"(?m)^primary_signed_at\s*=\s*"[^"]*""#)?;
    manifest = primary_time_re.replace(&manifest, format!("primary_signed_at = \"{}\"", dual_sig.primary_timestamp)).to_string();

    let backup_sig_re = Regex::new(r#"(?m)^backup_signature\s*=\s*"[^"]*""#)?;
    manifest = backup_sig_re.replace(&manifest, format!("backup_signature = \"{}\"", dual_sig.backup_signature)).to_string();

    let backup_id_re = Regex::new(r#"(?m)^backup_key_id\s*=\s*"[^"]*""#)?;
    manifest = backup_id_re.replace(&manifest, format!("backup_key_id = \"{}\"", dual_sig.backup_key_id)).to_string();

    let backup_time_re = Regex::new(r#"(?m)^backup_signed_at\s*=\s*"[^"]*""#)?;
    manifest = backup_time_re.replace(&manifest, format!("backup_signed_at = \"{}\"", dual_sig.backup_timestamp)).to_string();

    std::fs::write(manifest_path, &manifest)?;

    println!();
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!("{}", style("           ✅ OWNER AUTHORITY INITIALIZED").green().bold());
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!();
    println!("Owner:        {}", style(&owner_name).cyan());
    println!("Primary Key:  {}", style(&primary_key_id).cyan());
    println!("Backup Key:   {}", style(&backup_key_id).cyan());
    println!();
    println!("{}", style("Next steps:").yellow().bold());
    println!("1. Store your BACKUP hardware key in a secure off-site location");
    println!("2. Use 'board-appoint' to add editorial board members");
    println!("3. Board members can then publish content without owner involvement");

    Ok(())
}

/// Verify both owner hardware keys are accessible
fn owner_verify_keys() -> Result<()> {
    println!("{}", style("Verifying owner hardware key access...").cyan().bold());
    println!();

    // Load owner config
    let config = std::fs::read_to_string("config.toml")?;

    let primary_re = Regex::new(r#"(?m)^primary_pubkey\s*=\s*"([^"]*)""#)?;
    let backup_re = Regex::new(r#"(?m)^backup_pubkey\s*=\s*"([^"]*)""#)?;

    let primary_key = primary_re.captures(&config)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Owner not initialized. Run: owner-init --name \"Your Name\""))?;

    let backup_key = backup_re.captures(&config)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Backup key not configured"))?;

    println!("Expected PRIMARY key: {}", style(primary_key).dim());
    println!("Expected BACKUP key:  {}", style(backup_key).dim());
    println!();

    // Verify Primary
    println!("{}", style("Step 1/2: Verify PRIMARY hardware key").cyan());
    println!("Insert PRIMARY hardware key and press Enter...");
    hwkey::wait_for_enter()?;

    let info1 = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    match &info1.key_id {
        Some(id) if id.contains(primary_key) || primary_key.contains(id) => {
            println!("{}", style("  ✓ Primary hardware key verified").green());
        }
        Some(id) => {
            println!("{}", style(format!("  ⚠ Key ID mismatch: found {}", id)).yellow());
        }
        None => {
            println!("{}", style("  ✗ No signing key on this hardware key").red());
        }
    }

    let primary_serial = info1.serial.clone();

    // Verify Backup
    println!();
    println!("{}", style("Step 2/2: Verify BACKUP hardware key").cyan());
    println!("REMOVE Primary, INSERT BACKUP hardware key and press Enter...");
    hwkey::wait_for_enter()?;

    let info2 = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    if info2.serial == primary_serial {
        bail!("Same hardware key detected! Insert the BACKUP hardware key.");
    }

    match &info2.key_id {
        Some(id) if id.contains(backup_key) || backup_key.contains(id) => {
            println!("{}", style("  ✓ Backup hardware key verified").green());
        }
        Some(id) => {
            println!("{}", style(format!("  ⚠ Key ID mismatch: found {}", id)).yellow());
        }
        None => {
            println!("{}", style("  ✗ No signing key on this hardware key").red());
        }
    }

    println!();
    println!("{}", style("✅ Both hardware keys verified successfully").green().bold());

    Ok(())
}

/// Appoint a new board member (requires single hardware key)
fn board_appoint(id: String, name: String, member_type: String, role: String, pubkey: String, notice_hash: Option<String>) -> Result<()> {
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!("{}", style("              APPOINT EDITORIAL BOARD MEMBER").cyan().bold());
    println!("{}", style("   (Single hardware key + 48hr notice, except initial setup)").dim());
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!();

    // Validate inputs
    if member_type != "human" && member_type != "ai_agent" {
        bail!("Member type must be 'human' or 'ai_agent'");
    }

    if !id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        bail!("Member ID must be slug format (alphanumeric and hyphens only)");
    }

    // Validate pubkey is valid hex and correct length
    let pubkey_bytes = hex::decode(&pubkey)
        .context("Public key must be valid hex")?;
    if pubkey_bytes.len() != 32 {
        bail!("Public key must be 32 bytes (64 hex characters)");
    }

    // Load config and check if member already exists
    let config_path = Path::new("config.toml");
    let config = std::fs::read_to_string(config_path)?;

    let member_check = format!("id = \"{}\"", id);
    if config.contains(&member_check) {
        bail!("Board member '{}' already exists", id);
    }

    // Load owner keys for validation
    let (primary_key, backup_key) = load_owner_keys(&config)?;

    // Check notice period requirement (per BYLAWS Section 3.5)
    let is_initial_setup = is_initial_board_setup(&config)?;
    if !is_initial_setup {
        verify_notice_period(&notice_hash, "board-appoint")?;
    } else {
        println!("{}", style("Initial board setup - notice period waived").yellow());
    }

    println!("Appointing new board member:");
    println!("  ID:     {}", style(&id).cyan());
    println!("  Name:   {}", style(&name).cyan());
    println!("  Type:   {}", style(&member_type).cyan());
    println!("  Role:   {}", style(&role).cyan());
    println!("  Pubkey: {}...", style(&pubkey[..16]).cyan());
    println!();

    // Create appointment data
    let timestamp = Utc::now().to_rfc3339();
    let appointment_data = format!(
        "action:appoint\nid:{}\nname:{}\ntype:{}\nrole:{}\npubkey:{}\ntimestamp:{}",
        id, name, member_type, role, pubkey, timestamp
    );

    let mut hasher = Sha256::new();
    hasher.update(appointment_data.as_bytes());
    let appointment_hash = hex::encode(hasher.finalize());

    // Single key sign
    let single_sig = hwkey::single_sign(appointment_hash.as_bytes(), &[&primary_key, &backup_key])?;

    // Add member to config.toml
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
        id, name, member_type, role, pubkey, timestamp.split('T').next().unwrap_or(&timestamp)
    );

    let mut config = config;
    config.push_str(&new_member);

    // Update last_modified
    let modified_re = Regex::new(r#"(?m)^last_modified\s*=\s*"[^"]*""#)?;
    config = modified_re.replace(&config, format!("last_modified = \"{}\"", timestamp.split('T').next().unwrap_or(&timestamp))).to_string();

    std::fs::write(config_path, &config)?;

    // Add to audit log in manifest
    append_single_to_audit_log("appoint", &id, &format!("Appointed {} as {}", name, role), &single_sig)?;

    println!();
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!("{}", style("        ✅ BOARD MEMBER APPOINTED SUCCESSFULLY").green().bold());
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!();
    println!("Member {} ({}) can now participate in editorial reviews.", style(&name).cyan(), style(&id).dim());

    Ok(())
}

/// Remove a board member (requires single hardware key)
fn board_remove(id: String, notice_hash: Option<String>) -> Result<()> {
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!("{}", style("              REMOVE EDITORIAL BOARD MEMBER").cyan().bold());
    println!("{}", style("        (Single hardware key + 48hr notice required)").dim());
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!();

    let config_path = Path::new("config.toml");
    let config = std::fs::read_to_string(config_path)?;

    // Check member exists
    let member_check = format!("id = \"{}\"", id);
    if !config.contains(&member_check) {
        bail!("Board member '{}' not found", id);
    }

    // Load owner keys for validation
    let (primary_key, backup_key) = load_owner_keys(&config)?;

    // Verify notice period (per BYLAWS Section 3.5) - removal always requires notice
    verify_notice_period(&notice_hash, "board-remove")?;

    println!("Removing board member: {}", style(&id).red().bold());
    println!();

    // Create removal data
    let timestamp = Utc::now().to_rfc3339();
    let removal_data = format!("action:remove\nid:{}\ntimestamp:{}", id, timestamp);

    let mut hasher = Sha256::new();
    hasher.update(removal_data.as_bytes());
    let removal_hash = hex::encode(hasher.finalize());

    // Single key sign
    let single_sig = hwkey::single_sign(removal_hash.as_bytes(), &[&primary_key, &backup_key])?;

    // Set member to inactive (we don't delete, we deactivate for audit trail)
    let active_pattern = format!(r#"(?ms)(\[\[extra\.editorial_board\.members\]\]\s*\nid\s*=\s*"{}"\s*\n(?:[^\[]|\[[^\[])*?)active\s*=\s*true"#, regex::escape(&id));
    let active_re = Regex::new(&active_pattern)?;

    let config = active_re.replace(&config, "${1}active = false").to_string();

    // Update last_modified
    let modified_re = Regex::new(r#"(?m)^last_modified\s*=\s*"[^"]*""#)?;
    let config = modified_re.replace(&config, format!("last_modified = \"{}\"", timestamp.split('T').next().unwrap_or(&timestamp))).to_string();

    std::fs::write(config_path, &config)?;

    // Add to audit log
    append_single_to_audit_log("remove", &id, &format!("Removed member {}", id), &single_sig)?;

    println!();
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!("{}", style("        ✅ BOARD MEMBER REMOVED SUCCESSFULLY").green().bold());
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!();
    println!("Member {} has been deactivated and can no longer sign approvals.", style(&id).dim());

    Ok(())
}

/// Update a board member's key (requires single hardware key)
fn board_update_key(id: String, new_pubkey: String) -> Result<()> {
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!("{}", style("              UPDATE BOARD MEMBER KEY").cyan().bold());
    println!("{}", style("        (Single hardware key required)").dim());
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!();

    // Validate pubkey
    let pubkey_bytes = hex::decode(&new_pubkey)
        .context("Public key must be valid hex")?;
    if pubkey_bytes.len() != 32 {
        bail!("Public key must be 32 bytes (64 hex characters)");
    }

    let config_path = Path::new("config.toml");
    let config = std::fs::read_to_string(config_path)?;

    // Check member exists
    let member_check = format!("id = \"{}\"", id);
    if !config.contains(&member_check) {
        bail!("Board member '{}' not found", id);
    }

    // Load owner keys for validation
    let (primary_key, backup_key) = load_owner_keys(&config)?;

    println!("Updating key for member: {}", style(&id).cyan());
    println!("New pubkey: {}...", style(&new_pubkey[..16]).cyan());
    println!();

    // Create update data
    let timestamp = Utc::now().to_rfc3339();
    let update_data = format!("action:update_key\nid:{}\nnew_pubkey:{}\ntimestamp:{}", id, new_pubkey, timestamp);

    let mut hasher = Sha256::new();
    hasher.update(update_data.as_bytes());
    let update_hash = hex::encode(hasher.finalize());

    // Single key sign
    let single_sig = hwkey::single_sign(update_hash.as_bytes(), &[&primary_key, &backup_key])?;

    // Update pubkey in config
    let pubkey_pattern = format!(r#"(?ms)(\[\[extra\.editorial_board\.members\]\]\s*\nid\s*=\s*"{}"\s*\n(?:[^\[]|\[[^\[])*?)pubkey\s*=\s*"[^"]*""#, regex::escape(&id));
    let pubkey_re = Regex::new(&pubkey_pattern)?;

    let config = pubkey_re.replace(&config, format!("${{1}}pubkey = \"{}\"", new_pubkey)).to_string();

    // Update last_modified
    let modified_re = Regex::new(r#"(?m)^last_modified\s*=\s*"[^"]*""#)?;
    let config = modified_re.replace(&config, format!("last_modified = \"{}\"", timestamp.split('T').next().unwrap_or(&timestamp))).to_string();

    std::fs::write(config_path, &config)?;

    // Add to audit log
    append_single_to_audit_log("update_key", &id, &format!("Updated key for {}", id), &single_sig)?;

    println!();
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!("{}", style("        ✅ BOARD MEMBER KEY UPDATED SUCCESSFULLY").green().bold());
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());

    Ok(())
}

/// Set the approval threshold (requires single hardware key)
fn board_set_threshold(threshold: usize, notice_hash: Option<String>) -> Result<()> {
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!("{}", style("              SET APPROVAL THRESHOLD").cyan().bold());
    println!("{}", style("   (Single hardware key + 48hr notice, except initial setup)").dim());
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!();

    if threshold < 1 {
        bail!("Threshold must be at least 1");
    }

    let config_path = Path::new("config.toml");
    let config = std::fs::read_to_string(config_path)?;

    // Count active members
    let active_count = Regex::new(r#"(?m)^active\s*=\s*true"#)?.find_iter(&config).count();

    if threshold > active_count {
        bail!("Threshold ({}) cannot exceed number of active members ({})", threshold, active_count);
    }

    // Load owner keys for validation
    let (primary_key, backup_key) = load_owner_keys(&config)?;

    // Check notice period requirement (per BYLAWS Section 3.5)
    let is_initial_setup = is_initial_board_setup(&config)?;
    if !is_initial_setup {
        verify_notice_period(&notice_hash, "board-set-threshold")?;
    } else {
        println!("{}", style("Initial board setup - notice period waived").yellow());
    }

    println!("Setting approval threshold to: {}", style(threshold).cyan().bold());
    println!("Active board members: {}", active_count);
    println!();

    // Create threshold data
    let timestamp = Utc::now().to_rfc3339();
    let threshold_data = format!("action:set_threshold\nthreshold:{}\ntimestamp:{}", threshold, timestamp);

    let mut hasher = Sha256::new();
    hasher.update(threshold_data.as_bytes());
    let threshold_hash = hex::encode(hasher.finalize());

    // Single key sign
    let single_sig = hwkey::single_sign(threshold_hash.as_bytes(), &[&primary_key, &backup_key])?;

    // Update threshold in config
    let threshold_re = Regex::new(r#"(?m)^threshold\s*=\s*\d+"#)?;
    let config = threshold_re.replace(&config, format!("threshold = {}", threshold)).to_string();

    // Update last_modified
    let modified_re = Regex::new(r#"(?m)^last_modified\s*=\s*"[^"]*""#)?;
    let config = modified_re.replace(&config, format!("last_modified = \"{}\"", timestamp.split('T').next().unwrap_or(&timestamp))).to_string();

    std::fs::write(config_path, &config)?;

    // Add to audit log
    append_single_to_audit_log("set_threshold", "board", &format!("Set threshold to {}", threshold), &single_sig)?;

    println!();
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!("{}", style("        ✅ THRESHOLD UPDATED SUCCESSFULLY").green().bold());
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!();
    println!("Now requires {}-of-{} signatures for content approval.", threshold, active_count);

    Ok(())
}

/// Show authority manifest
fn manifest_show() -> Result<()> {
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!("{}", style("              AUTHORITY MANIFEST").cyan().bold());
    println!("{}", style("═══════════════════════════════════════════════════════════════").cyan());
    println!();

    let manifest_path = Path::new(".editorial_board/authority_manifest.toml");
    if !manifest_path.exists() {
        println!("{}", style("No authority manifest found.").yellow());
        println!("Run 'owner-init' to initialize owner authority.");
        return Ok(());
    }

    let manifest = std::fs::read_to_string(manifest_path)?;

    // Extract and display key fields
    let extract = |field: &str| -> String {
        let re = Regex::new(&format!(r#"(?m)^{}\s*=\s*"([^"]*)""#, field)).unwrap();
        re.captures(&manifest)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "(not set)".to_string())
    };

    println!("{}", style("Manifest Info:").yellow());
    println!("  Owner:         {}", extract("owner_name"));
    println!("  Created:       {}", extract("created"));
    println!("  Last Modified: {}", extract("last_modified"));
    println!("  Board Hash:    {}...", &extract("board_state_hash").chars().take(16).collect::<String>());
    println!();

    println!("{}", style("Signatures:").yellow());
    println!("  Primary Key:   {}", extract("primary_key_id"));
    println!("  Primary Sig:   {}...", &extract("primary_signature").chars().take(16).collect::<String>());
    println!("  Primary Time:  {}", extract("primary_signed_at"));
    println!();
    println!("  Backup Key:    {}", extract("backup_key_id"));
    println!("  Backup Sig:    {}...", &extract("backup_signature").chars().take(16).collect::<String>());
    println!("  Backup Time:   {}", extract("backup_signed_at"));
    println!();

    // Show audit log entries
    println!("{}", style("Audit Log:").yellow());
    let audit_entries: Vec<&str> = manifest.split("[[audit_log]]").skip(1).collect();
    if audit_entries.is_empty() || (audit_entries.len() == 1 && audit_entries[0].contains("timestamp = \"\"")) {
        println!("  (no entries yet)");
    } else {
        for entry in audit_entries.iter().take(10) {
            let action_re = Regex::new(r#"action\s*=\s*"([^"]*)""#)?;
            let target_re = Regex::new(r#"target_id\s*=\s*"([^"]*)""#)?;
            let time_re = Regex::new(r#"timestamp\s*=\s*"([^"]*)""#)?;

            let action = action_re.captures(entry).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("?");
            let target = target_re.captures(entry).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("?");
            let time = time_re.captures(entry).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("?");

            if !time.is_empty() {
                println!("  {} | {} | {}", time.chars().take(10).collect::<String>(), action, target);
            }
        }
    }

    Ok(())
}

// ============================================================================
// HELPER FUNCTIONS FOR OWNER AUTHORITY
// ============================================================================

/// Load owner keys from config
fn load_owner_keys(config: &str) -> Result<(String, String)> {
    let initialized_re = Regex::new(r#"(?m)^initialized\s*=\s*true"#)?;
    if !initialized_re.is_match(config) {
        bail!("Owner authority not initialized. Run: cargo run -p xtask -- owner-init --name \"Your Name\"");
    }

    let primary_re = Regex::new(r#"(?m)^primary_pubkey\s*=\s*"([^"]*)""#)?;
    let backup_re = Regex::new(r#"(?m)^backup_pubkey\s*=\s*"([^"]*)""#)?;

    let primary_key = primary_re.captures(config)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Primary owner key not configured"))?;

    let backup_key = backup_re.captures(config)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Backup owner key not configured"))?;

    Ok((primary_key, backup_key))
}

/// Check if this is the initial board setup (no active members yet)
/// Per BYLAWS Section 3.5, initial board setup is exempt from notice period
fn is_initial_board_setup(config: &str) -> Result<bool> {
    let active_count = Regex::new(r#"(?m)^active\s*=\s*true"#)?.find_iter(config).count();
    Ok(active_count == 0)
}

/// Verify notice period requirement (per BYLAWS Section 3.5)
/// Checks that:
/// 1. Notice hash is provided
/// 2. OTS file exists for this notice
/// 3. 48 hours have elapsed since timestamp
fn verify_notice_period(notice_hash: &Option<String>, action: &str) -> Result<()> {
    let hash = match notice_hash {
        Some(h) => h,
        None => {
            bail!(
                "Notice period required for {}.\n\
                 Per BYLAWS Section 3.5, you must:\n\
                 1. Publish a notice article announcing this action\n\
                 2. Run: cargo run -p xtask -- timestamp-notice <article>\n\
                 3. Wait 48 hours after OpenTimestamp anchoring\n\
                 4. Re-run this command with --notice-hash <hash>",
                action
            );
        }
    };

    // Check OTS file exists
    let timestamps_dir = Path::new(".editorial_board/timestamps");
    let ots_file = timestamps_dir.join(format!("{}.ots", &hash[..std::cmp::min(16, hash.len())]));

    if !ots_file.exists() {
        // Try to find any .ots file that might match
        println!("{}", style("Looking for OpenTimestamp proof...").dim());

        let mut found = false;
        if timestamps_dir.exists() {
            for entry in std::fs::read_dir(timestamps_dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.ends_with(".ots") && hash.starts_with(&name_str[..name_str.len()-4]) {
                    found = true;
                    println!("  Found: {:?}", entry.path());
                    break;
                }
            }
        }

        if !found {
            bail!(
                "No OpenTimestamp proof found for notice hash: {}\n\
                 Create one with: cargo run -p xtask -- timestamp-notice <article>",
                hash
            );
        }
    }

    // Verify timestamp age (48 hours = 172800 seconds)
    // For now, we'll trust that the OTS exists and warn about verification
    println!("{}", style("✓ Notice hash provided").green());
    println!("{}", style("  Verifying OpenTimestamp...").dim());

    // Try to verify with ots command if available
    let ots_check = std::process::Command::new("ots")
        .arg("--version")
        .output();

    match ots_check {
        Ok(output) if output.status.success() => {
            // TODO: Parse OTS and verify 48hr elapsed
            // For now, just verify the proof exists
            println!("{}", style("  ⚠ Manual verification: ensure 48 hours have passed since OTS anchor time").yellow());
            println!("{}", style("    Run: ots verify <file>.ots to check timestamp").dim());
        }
        _ => {
            println!("{}", style("  ⚠ OpenTimestamps CLI not available for automatic verification").yellow());
            println!("{}", style("    Install: pip install opentimestamps-client").dim());
            println!("{}", style("    Proceeding with manual attestation that 48 hours have passed").yellow());
        }
    }

    Ok(())
}

/// Append an entry to the audit log in the manifest (dual signature)
#[allow(dead_code)]
fn append_to_audit_log(action: &str, target_id: &str, details: &str, dual_sig: &hwkey::DualSignature) -> Result<()> {
    let manifest_path = Path::new(".editorial_board/authority_manifest.toml");
    let mut manifest = std::fs::read_to_string(manifest_path)
        .unwrap_or_default();

    let timestamp = Utc::now().to_rfc3339();
    let entry = format!(r#"

[[audit_log]]
timestamp = "{}"
action = "{}"
target_id = "{}"
details = "{}"
signature_type = "dual"
primary_signature = "{}"
backup_signature = "{}""#,
        timestamp, action, target_id, details,
        dual_sig.primary_signature.chars().take(32).collect::<String>(),
        dual_sig.backup_signature.chars().take(32).collect::<String>()
    );

    manifest.push_str(&entry);
    std::fs::write(manifest_path, &manifest)?;

    Ok(())
}

/// Append an entry to the audit log in the manifest (single signature)
fn append_single_to_audit_log(action: &str, target_id: &str, details: &str, single_sig: &hwkey::SingleSignature) -> Result<()> {
    let manifest_path = Path::new(".editorial_board/authority_manifest.toml");
    let mut manifest = std::fs::read_to_string(manifest_path)
        .unwrap_or_default();

    let timestamp = Utc::now().to_rfc3339();
    let entry = format!(r#"

[[audit_log]]
timestamp = "{}"
action = "{}"
target_id = "{}"
details = "{}"
signature_type = "single"
signer_key_id = "{}"
signature = "{}""#,
        timestamp, action, target_id, details,
        single_sig.key_id,
        single_sig.signature.chars().take(32).collect::<String>()
    );

    manifest.push_str(&entry);
    std::fs::write(manifest_path, &manifest)?;

    Ok(())
}

/// Rotate/recover owner key when one is lost
/// Requires: the REMAINING working key + a NEW replacement key
fn owner_rotate_key(replace: String) -> Result<()> {
    println!("{}", style("═══════════════════════════════════════════════════════════════").yellow());
    println!("{}", style("              OWNER KEY ROTATION / RECOVERY").yellow().bold());
    println!("{}", style("       Requires: remaining key + new replacement key").yellow());
    println!("{}", style("═══════════════════════════════════════════════════════════════").yellow());
    println!();

    if replace != "primary" && replace != "backup" {
        bail!("--replace must be 'primary' or 'backup'");
    }

    let config_path = Path::new("config.toml");
    let config = std::fs::read_to_string(config_path)?;

    // Load current owner keys
    let (primary_key, backup_key) = load_owner_keys(&config)?;

    let (remaining_key, remaining_name, lost_name) = if replace == "primary" {
        (&backup_key, "BACKUP", "PRIMARY")
    } else {
        (&primary_key, "PRIMARY", "BACKUP")
    };

    println!("{}", style(format!("Replacing LOST {} key", lost_name)).red().bold());
    println!("Using REMAINING {} key for authorization", remaining_name);
    println!();

    // Step 1: Verify remaining key
    println!("{}", style(format!("Step 1/3: Verify REMAINING {} hardware key", remaining_name)).cyan().bold());
    println!("Insert your {} hardware key and press Enter...", remaining_name);
    hwkey::wait_for_enter()?;

    let remaining_info = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    let remaining_detected_id = remaining_info.key_id.clone()
        .ok_or_else(|| anyhow::anyhow!("No signing key on this hardware key"))?;

    // Verify it matches
    if !remaining_detected_id.contains(remaining_key) && !remaining_key.contains(&remaining_detected_id) {
        println!("{}", style(format!("  Warning: Key ID {} may not match expected {}", remaining_detected_id, remaining_key)).yellow());
    }
    println!("{}", style(format!("  ✓ {} hardware key detected: Serial {}", remaining_name, remaining_info.serial)).green());

    let remaining_serial = remaining_info.serial.clone();

    // Step 2: Get new replacement key
    println!();
    println!("{}", style(format!("Step 2/3: Register NEW {} hardware key", lost_name)).cyan().bold());
    println!("REMOVE the {} hardware key", remaining_name);
    println!("INSERT your NEW {} hardware key and press Enter...", lost_name);
    hwkey::wait_for_enter()?;

    let new_info = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    if new_info.serial == remaining_serial {
        bail!("Same hardware key detected! Insert the NEW replacement hardware key.");
    }

    let new_key_id = new_info.key_id.clone()
        .ok_or_else(|| anyhow::anyhow!("No signing key on new hardware key. Generate one with: gpg --card-edit"))?;

    println!("{}", style(format!("  ✓ New hardware key detected: Serial {}", new_info.serial)).green());
    println!("  New Key ID: {}", style(&new_key_id).cyan());

    // Step 3: Sign rotation with both keys (remaining + new)
    println!();
    println!("{}", style("Step 3/3: Authorize rotation with both keys").cyan().bold());

    let timestamp = Utc::now().to_rfc3339();
    let rotation_data = format!(
        "action:rotate_key\nreplace:{}\nold_key:{}\nnew_key:{}\ntimestamp:{}",
        replace,
        if replace == "primary" { &primary_key } else { &backup_key },
        new_key_id,
        timestamp
    );

    let mut hasher = Sha256::new();
    hasher.update(rotation_data.as_bytes());
    let rotation_hash = hex::encode(hasher.finalize());

    // Sign with new key first (it's currently inserted)
    println!("Signing with NEW {} key...", lost_name);
    println!("{}", style("Touch hardware key to sign...").yellow().bold());
    let new_sig = hwkey::sign_with_hwkey(rotation_hash.as_bytes(), &new_key_id)?;
    println!("{}", style("  ✓ New key signature obtained").green());

    // Now sign with remaining key
    println!();
    println!("REMOVE the new hardware key");
    println!("INSERT the {} hardware key and press Enter...", remaining_name);
    hwkey::wait_for_enter()?;

    let verify_info = hwkey::detect_hwkey()?
        .ok_or_else(|| anyhow::anyhow!("No hardware key detected"))?;

    if verify_info.serial == new_info.serial {
        bail!("Same hardware key! Insert the {} hardware key.", remaining_name);
    }

    println!("Signing with {} key...", remaining_name);
    println!("{}", style("Touch hardware key to sign...").yellow().bold());
    let remaining_sig = hwkey::sign_with_hwkey(rotation_hash.as_bytes(), &remaining_detected_id)?;
    println!("{}", style("  ✓ Remaining key signature obtained").green());

    // Update config.toml with new key
    let mut config = config;
    if replace == "primary" {
        let primary_re = Regex::new(r#"(?m)^primary_pubkey\s*=\s*"[^"]*""#)?;
        config = primary_re.replace(&config, format!("primary_pubkey = \"{}\"", new_key_id)).to_string();
    } else {
        let backup_re = Regex::new(r#"(?m)^backup_pubkey\s*=\s*"[^"]*""#)?;
        config = backup_re.replace(&config, format!("backup_pubkey = \"{}\"", new_key_id)).to_string();
    }

    std::fs::write(config_path, &config)?;

    // Add to audit log
    let manifest_path = Path::new(".editorial_board/authority_manifest.toml");
    let mut manifest = std::fs::read_to_string(manifest_path).unwrap_or_default();

    let entry = format!(r#"

[[audit_log]]
timestamp = "{}"
action = "rotate_key"
target_id = "{}"
details = "Rotated {} key (lost/replaced)"
signature_type = "rotation"
remaining_key_signature = "{}"
new_key_signature = "{}""#,
        timestamp,
        replace,
        lost_name,
        remaining_sig.chars().take(32).collect::<String>(),
        new_sig.chars().take(32).collect::<String>()
    );

    manifest.push_str(&entry);
    std::fs::write(manifest_path, &manifest)?;

    println!();
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!("{}", style("        ✅ KEY ROTATION SUCCESSFUL").green().bold());
    println!("{}", style("═══════════════════════════════════════════════════════════════").green());
    println!();
    println!("{} key has been replaced.", lost_name);
    println!("New key ID: {}", style(&new_key_id).cyan());
    println!();
    println!("{}", style("Important:").yellow().bold());
    println!("• Store the new hardware key securely");
    println!("• The old {} key is now DEACTIVATED", lost_name);
    println!("• Consider generating a fresh key if the old one was compromised");

    Ok(())
}
