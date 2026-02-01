//! La Propaganda Newsroom CLI
//!
//! This is the main entry point for the newsroom CLI tool.
//! It handles command-line parsing and dispatches to the appropriate modules.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::{Command, Stdio};

// Import library modules
mod types;
mod config;
mod author;
mod board;
mod content;
mod signing;
mod owner;
mod governance;
mod timestamp;
mod hwkey;
mod mcp;

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
        /// Import existing public key (hex) from hardware key instead of generating
        #[arg(long)]
        import_pubkey: Option<String>,
        /// Mark as human (uses hardware key for signing via GPG)
        #[arg(long)]
        hardware_key: bool,
    },
    /// Sign article as author
    AuthorSign {
        /// Path to article markdown file
        article: PathBuf,
        /// Author ID (skip interactive prompt)
        #[arg(long)]
        author_id: Option<String>,
    },
    /// Verify author signature on article
    VerifyAuthor {
        /// Path to article markdown file
        article: PathBuf,
    },
    /// Delegate signing authority to another device or bot
    AuthorDelegate {
        /// Primary author ID (must exist in .authors/)
        #[arg(long)]
        primary_id: String,
        /// Name for the delegate (e.g., "Work Laptop", "Claude Assistant")
        #[arg(long)]
        name: String,
        /// ID for the delegate (slug format, e.g., "laptop-work", "claude-assistant")
        #[arg(long)]
        id: String,
        /// Delegate type: "device" or "bot"
        #[arg(long, default_value = "bot")]
        delegate_type: String,
        /// Optional expiration (ISO 8601 date, e.g., 2026-01-31)
        #[arg(long)]
        expires: Option<String>,
    },
    /// List all delegated identities for an author
    AuthorListDelegates {
        /// Primary author ID
        id: String,
    },
    /// Revoke a delegation
    AuthorRevoke {
        /// Primary author ID
        #[arg(long)]
        primary_id: String,
        /// Delegate ID to revoke
        #[arg(long)]
        delegate_id: String,
    },

    // ═══════════════════════════════════════════════════════════════════════════
    // ENDORSEMENT AND CLAIM COMMANDS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Endorse an article as a human vouching for Bot-authored content
    Endorse {
        /// Path to article markdown file
        article: PathBuf,
        /// Endorser's author ID (must have registered key)
        #[arg(long)]
        endorser_id: String,
    },

    /// Grant consent for a human to claim authorship (Bot must run this)
    GrantClaimConsent {
        /// Path to article markdown file
        article: PathBuf,
        /// Bot's author ID (must be the original signer)
        #[arg(long)]
        bot_id: String,
        /// Human's public key (hex) who will claim authorship
        #[arg(long)]
        human_pubkey: String,
    },

    /// Claim authorship of a Bot-signed article (Human runs this)
    ClaimAuthorship {
        /// Path to article markdown file
        article: PathBuf,
        /// Human's author ID
        #[arg(long)]
        claimer_id: String,
        /// Bot's consent signature (from grant-claim-consent)
        #[arg(long)]
        consent_signature: String,
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
        /// Board member ID (skip interactive prompt)
        #[arg(long)]
        member_id: Option<String>,
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

    /// Approve a pending board member (generated via MCP generate_board_identity)
    /// Moves from .editorial_board/pending/<id>/ to .editorial_board/board/<id>/
    BoardApprove {
        /// Pending member ID to approve
        id: String,
    },

    /// List pending board member requests
    BoardPending,

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

    /// Validate config.toml structure
    ValidateConfig,

    // ═══════════════════════════════════════════════════════════════════════════
    // MCP SERVER MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════

    /// Start the MCP signing server (foreground)
    McpStart,

    /// Check MCP server status
    McpStatus,

    /// Install MCP server as system service (systemd on Linux, launchd on macOS)
    McpInstall,

    /// Uninstall MCP server system service
    McpUninstall,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // Content commands
        Commands::Draft { title } => content::draft(title),
        Commands::Proofread => run_zola("serve"),
        Commands::Print => run_zola("build"),
        // Legacy Hash command removed
        Commands::Hash { .. } => {
            anyhow::bail!("Legacy hashing is deprecated. Use 'author-sign' and 'editorial-review'.");
        }
        Commands::Verify => board::verify_all_articles(false), // Redirect to multi-sig verify
        Commands::Ci => {
            board::verify_all_articles(false)?;
            run_zola("build")
        }

        // Signing commands
        Commands::GenerateKey => signing::generate_key(),
        Commands::VerifySignature => {
             anyhow::bail!("Legacy site-wide signature verification is deprecated. Use 'verify-article'.");
        }

        // Author commands
        Commands::AuthorKeygen { name, id, email, import_pubkey, hardware_key } => {
            author::author_keygen(name, id, email, import_pubkey, hardware_key)
        }
        Commands::AuthorSign { article, author_id } => author::author_sign(&article, author_id),
        Commands::VerifyAuthor { article } => author::verify_author(&article),
        Commands::AuthorDelegate { primary_id, name, id, delegate_type, expires } => {
            author::author_delegate(primary_id, name, id, delegate_type, expires)
        }
        Commands::AuthorListDelegates { id } => author::author_list_delegates(&id),
        Commands::AuthorRevoke { primary_id, delegate_id } => {
            author::author_revoke(&primary_id, &delegate_id)
        }

        // Endorsement and claim commands
        Commands::Endorse { article, endorser_id } => {
            author::endorse_article(&article, &endorser_id)
        }
        Commands::GrantClaimConsent { article, bot_id, human_pubkey } => {
            author::grant_claim_consent(&article, &bot_id, &human_pubkey)
        }
        Commands::ClaimAuthorship { article, claimer_id, consent_signature } => {
            author::claim_authorship(&article, &claimer_id, &consent_signature)
        }

        // Board commands
        Commands::BoardKeygen { name, id, role, member_type } => {
            board::board_keygen(name, id, role, member_type)
        }
        Commands::EditorialReview { article, approve, reject, member_id } => {
            board::editorial_review(&article, approve, reject, member_id)
        }
        Commands::BoardList => board::board_list(),
        Commands::VerifyArticle { article } => board::verify_article(&article),
        Commands::VerifyAllArticles { require_timestamps } => {
            board::verify_all_articles(require_timestamps)
        }

        // Owner authority commands
        Commands::OwnerInit { name } => owner::owner_init(name),
        Commands::HwkeyStatus => hwkey::print_hwkey_status(),
        Commands::OwnerVerifyKeys => owner::owner_verify_keys(),
        Commands::OwnerRotateKey { replace } => owner::owner_rotate_key(replace),
        Commands::ManifestShow => owner::manifest_show(),

        // Governance commands
        Commands::BoardAppoint { id, name, member_type, role, pubkey, notice_hash } => {
            governance::board_appoint(id, name, member_type, role, pubkey, notice_hash)
        }
        Commands::BoardRemove { id, notice_hash } => governance::board_remove(id, notice_hash),
        Commands::BoardUpdateKey { id, new_pubkey } => governance::board_update_key(id, new_pubkey),
        Commands::BoardSetThreshold { threshold, notice_hash } => {
            governance::board_set_threshold(threshold, notice_hash)
        }
        Commands::BoardApprove { id } => governance::board_approve_pending(id),
        Commands::BoardPending => governance::board_list_pending(),
        Commands::RatifyBylaws => governance::ratify_bylaws(),

        // Timestamp commands
        Commands::TimestampNotice { article } => timestamp::timestamp_notice(&article),
        Commands::VerifyTimestamp { ots_file } => timestamp::verify_timestamp(&ots_file),

        // Config validation
        Commands::ValidateConfig => validate_config(),

        // MCP server management
        Commands::McpStart => mcp::mcp_start(),
        Commands::McpStatus => mcp::mcp_status(),
        Commands::McpInstall => mcp::mcp_install(),
        Commands::McpUninstall => mcp::mcp_uninstall(),
    }
}

/// Run Zola with the specified command
fn run_zola(cmd: &str) -> Result<()> {
    println!("Running Zola {}...", cmd);

    if Command::new("zola")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("Error: 'zola' is not found in your PATH.");
        anyhow::bail!("Zola executable missing");
    }

    let status = Command::new("zola")
        .arg(cmd)
        .status()
        .context(format!("Failed to run zola {}", cmd))?;

    if !status.success() {
        anyhow::bail!("Zola command failed");
    }

    Ok(())
}

/// Validate config.toml structure
fn validate_config() -> Result<()> {
    use console::style;
    use std::path::Path;

    println!("{}", style("Validating config.toml...").cyan().bold());

    let config_path = Path::new("config.toml");
    let config = config::load_config(config_path)?;

    // Check required fields
    println!("  base_url: {}", config.base_url);

    if config.extra.public_key.is_none() {
        println!("{}", style("  WARNING: public_key not set").yellow());
    }

    // Check editorial board
    if let Some(board) = &config.extra.editorial_board {
        let threshold = board.threshold.unwrap_or(3);
        let member_count = board.members.as_ref().map(|m| m.len()).unwrap_or(0);
        let active_count = board.members.as_ref()
            .map(|m| m.iter().filter(|x| x.active).count())
            .unwrap_or(0);

        println!("  Editorial board threshold: {}", threshold);
        println!("  Total members: {}", member_count);
        println!("  Active members: {}", active_count);

        if threshold > active_count && active_count > 0 {
            println!("{}", style(format!("  WARNING: Threshold ({}) > active members ({})", threshold, active_count)).yellow());
        }
    } else {
        println!("{}", style("  WARNING: No editorial_board configuration").yellow());
    }

    // Check owner
    if let Some(owner) = &config.extra.owner {
        let initialized = owner.initialized.unwrap_or(false);
        println!("  Owner initialized: {}", initialized);

        if !initialized {
            println!("{}", style("  NOTE: Run 'owner-init' to set up owner authority").dim());
        }
    }

    println!();
    println!("{}", style("Config validation complete").green().bold());

    Ok(())
}

use anyhow::Context;
