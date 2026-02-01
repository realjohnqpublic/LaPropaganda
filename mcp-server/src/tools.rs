//! MCP tool implementations for La Propaganda signing server

use crate::article::{self, AuthorSignature, EditorialApproval, EditorialSignature};
use crate::audit::AuditLogger;
use crate::crypto;
use crate::keys::{DelegateType, DelegationInfo, KeyStore, KeyType};
use crate::rate_limit::RateLimiter;
use chrono::Local;
use ed25519_dalek::SigningKey;
use la_propaganda_core::{derive_id_from_pubkey, is_valid_slug};
use rand::rngs::OsRng;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo, Implementation};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Count how many articles an author has signed (track record)
fn count_author_signatures(base_path: &std::path::Path, author_id: &str) -> usize {
    let content_dir = base_path.join("content");
    if !content_dir.exists() {
        return 0;
    }

    let mut count = 0;
    for entry in walkdir::WalkDir::new(&content_dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.path().extension().map(|e| e == "md").unwrap_or(false) {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                // Check if this article was signed by this author
                // Look for author_signature section with matching name/id
                if content.contains("[extra.author_signature]") {
                    // Simple check: see if author ID appears near signature
                    let author_marker = format!("name = \"{}\"", author_id);
                    let author_marker2 = format!("# Signed by: {}", author_id);
                    if content.contains(&author_marker) || content.contains(&author_marker2) {
                        count += 1;
                    }
                    // Also check by parsing the author name from .authors/<id>/author.info
                    // and matching against the signature name
                }
            }
        }
    }
    count
}

/// Parse SSH public key and extract the raw Ed25519 public key
/// Returns (key_type, pubkey_hex, requires_touch)
fn parse_ssh_pubkey(ssh_key: &str) -> Result<(String, String, bool), String> {
    let parts: Vec<&str> = ssh_key.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err("SSH key must have at least type and base64 data".to_string());
    }

    let key_type = parts[0];
    let base64_data = parts[1];

    // Determine if this is a FIDO2/SK key (requires touch)
    let requires_touch = key_type.contains("-sk") || key_type.contains("sk-");

    // Decode base64
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let key_data = STANDARD.decode(base64_data)
        .map_err(|e| format!("Invalid base64: {}", e))?;

    // SSH key format: length-prefixed strings
    // For ed25519: [4-byte len]["ssh-ed25519"][4-byte len][32-byte pubkey]
    // For sk-ssh-ed25519: [4-byte len]["sk-ssh-ed25519@openssh.com"][4-byte len][32-byte pubkey][4-byte len][application]

    let mut offset = 0;

    // Read key type string
    if key_data.len() < 4 {
        return Err("Key data too short".to_string());
    }
    let type_len = u32::from_be_bytes([key_data[0], key_data[1], key_data[2], key_data[3]]) as usize;
    offset += 4 + type_len;

    // Read public key
    if key_data.len() < offset + 4 {
        return Err("Key data too short for pubkey length".to_string());
    }
    let pubkey_len = u32::from_be_bytes([
        key_data[offset], key_data[offset+1], key_data[offset+2], key_data[offset+3]
    ]) as usize;
    offset += 4;

    if key_data.len() < offset + pubkey_len {
        return Err("Key data too short for pubkey".to_string());
    }

    // For Ed25519, pubkey should be 32 bytes
    if pubkey_len != 32 {
        return Err(format!("Expected 32-byte Ed25519 key, got {} bytes", pubkey_len));
    }

    let pubkey_bytes = &key_data[offset..offset + pubkey_len];
    let pubkey_hex = hex::encode(pubkey_bytes);

    Ok((key_type.to_string(), pubkey_hex, requires_touch))
}

// is_valid_slug and derive_id_from_pubkey are now imported from la_propaganda_core

/// Input for sign_article tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SignArticleInput {
    /// Author ID (from .authors/ directory)
    pub author_id: String,
    /// Full article body content (markdown, excluding frontmatter)
    pub article_body: String,
}

/// Input for sign_editorial_review tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SignEditorialInput {
    /// Board member ID (from .editorial_board/board/ directory)
    pub board_member_id: String,
    /// SHA-256 hash of the article body (hex)
    pub article_hash: String,
    /// The author's Ed25519 signature (hex)
    pub author_signature: String,
    /// Editorial decision: 'approve' or 'reject'
    pub decision: String,
}

/// Input for list_authors tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListAuthorsInput {
    /// Filter by type: 'author', 'board_member', or omit for all
    pub identity_type: Option<String>,
}

/// Input for verify_signature tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct VerifySignatureInput {
    /// Hex-encoded Ed25519 public key (64 hex chars)
    pub pubkey: String,
    /// The message that was signed (typically a hex-encoded hash)
    pub message: String,
    /// Hex-encoded Ed25519 signature (128 hex chars)
    pub signature: String,
}

/// Input for calculate_hash tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct CalculateHashInput {
    /// Article body content (markdown, excluding frontmatter)
    pub article_body: String,
}

/// Response for calculate_hash tool
#[derive(Debug, Serialize, Deserialize)]
pub struct CalculateHashResponse {
    /// SHA-256 hash as hex string
    pub hash: String,
    /// Length of the original content (for verification)
    pub content_length: usize,
}

/// Response for sign_article tool
#[derive(Debug, Serialize, Deserialize)]
pub struct SignArticleResponse {
    pub success: bool,
    pub author_name: String,
    pub author_pubkey: String,
    pub article_hash: String,
    pub signature: String,
    pub timestamp: String,
}

/// Response for sign_editorial_review tool
#[derive(Debug, Serialize, Deserialize)]
pub struct SignEditorialResponse {
    pub success: bool,
    pub board_member: String,
    pub decision: String,
    pub review_hash: String,
    pub signature: String,
    pub timestamp: String,
}

/// Identity entry for list_authors response
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityEntry {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub pubkey: String,
    pub identity_type: String,
}

/// Response for verify_signature tool
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================================
// FILE-BASED TOOLS (for complete bot workflow)
// These tools read/write article files directly, enabling bots to participate
// in the full publishing workflow without external file manipulation.
// ============================================================================

/// Input for list_articles tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListArticlesInput {
    /// Filter by status: "pending", "signed", "approved", "all" (default: "all")
    #[serde(default)]
    pub status: Option<String>,
}

/// Summary of an article for list_articles response
#[derive(Debug, Serialize, Deserialize)]
pub struct ArticleSummary {
    pub path: String,
    pub title: String,
    pub date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub has_author_signature: bool,
    pub editorial_signatures: usize,
    pub status: String,
}

/// Input for read_article_file tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReadArticleFileInput {
    /// Path to article markdown file (relative to project root)
    pub article_path: String,
}

/// Response for read_article_file tool
#[derive(Debug, Serialize, Deserialize)]
pub struct ReadArticleFileResponse {
    pub success: bool,
    pub title: String,
    pub date: String,
    pub body: String,
    pub body_hash: String,
    pub has_author_signature: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub editorial_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_required: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Input for sign_article_file tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct SignArticleFileInput {
    /// Author ID (from .authors/ directory)
    pub author_id: String,
    /// Path to article markdown file (relative to project root)
    pub article_path: String,
    /// Force re-sign by replacing existing signature (default: false)
    #[serde(default)]
    pub force: bool,
}

/// Response for sign_article_file tool
#[derive(Debug, Serialize, Deserialize)]
pub struct SignArticleFileResponse {
    pub success: bool,
    pub article_path: String,
    pub author_name: String,
    pub author_pubkey: String,
    pub article_hash: String,
    pub signature: String,
    pub threshold: usize,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Input for review_article_file tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ReviewArticleFileInput {
    /// Board member ID (from .editorial_board/board/ directory)
    pub board_member_id: String,
    /// Path to article markdown file (relative to project root)
    pub article_path: String,
    /// Editorial decision: 'approve' or 'reject'
    pub decision: String,
}

/// Response for review_article_file tool
#[derive(Debug, Serialize, Deserialize)]
pub struct ReviewArticleFileResponse {
    pub success: bool,
    pub article_path: String,
    pub board_member: String,
    pub decision: String,
    pub review_hash: String,
    pub signature: String,
    pub approval_count: usize,
    pub approval_required: usize,
    pub is_approved: bool,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================================
// IDENTITY GENERATION TOOLS (for autonomous bot registration)
// Authors: Self-service (anyone can generate)
// Board members: Generates in pending/, requires owner approval
// ============================================================================

/// Input for generate_author_identity tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct GenerateAuthorIdentityInput {
    /// Author display name (e.g., "Claude Opus 4.5")
    pub name: String,
    /// Author ID slug (lowercase, alphanumeric with hyphens, e.g., "claude-opus")
    pub id: String,
    /// Optional email address
    #[serde(default)]
    pub email: Option<String>,
}

/// Response for generate_author_identity tool
#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateAuthorIdentityResponse {
    pub success: bool,
    pub author_id: String,
    pub author_name: String,
    pub pubkey: String,
    pub key_path: String,
    pub info_path: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Input for request_board_promotion tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RequestBoardPromotionInput {
    /// Existing author ID to promote (reuses the same keypair)
    pub author_id: String,
    /// Role description for board membership (e.g., "AI Editor", "Content Reviewer")
    pub role: String,
}

/// Response for request_board_promotion tool
#[derive(Debug, Serialize, Deserialize)]
pub struct RequestBoardPromotionResponse {
    pub success: bool,
    pub author_id: String,
    pub author_name: String,
    pub pubkey: String,
    pub status: String,
    pub linked_from: String, // Shows this is linked to author identity
    pub message: String,
    pub approval_command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_articles_count: Option<usize>, // Track record
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Input for import_hardware_identity tool (YubiKey/FIDO2)
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ImportHardwareIdentityInput {
    /// Author display name (e.g., "Alice Smith")
    pub name: String,
    /// SSH public key string (from `ssh-add -L` or YubiKey export)
    /// Supports: ssh-ed25519, sk-ssh-ed25519@openssh.com, ecdsa-sk
    pub ssh_pubkey: String,
    /// Optional email address
    #[serde(default)]
    pub email: Option<String>,
}

/// Response for import_hardware_identity tool
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportHardwareIdentityResponse {
    pub success: bool,
    pub author_id: String,
    pub author_name: String,
    pub key_type: String, // "ed25519-sk", "ecdsa-sk", "ed25519"
    pub pubkey_hex: String,
    pub requires_touch: bool,
    pub info_path: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================================
// DELEGATION TOOLS (multi-device/multi-bot identity management)
// ============================================================================

/// Input for delegate_key tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DelegateKeyInput {
    /// Primary identity ID (the one issuing the delegation)
    pub primary_id: String,
    /// Name for the delegated identity (e.g., "Alice's Laptop", "Claude Assistant")
    pub delegate_name: String,
    /// ID for the delegated identity (slug format, e.g., "laptop-home", "claude-assistant")
    pub delegate_id: String,
    /// Type of delegation: "device" (another machine) or "bot" (AI agent)
    pub delegate_type: String,
    /// Optional expiration date (ISO 8601 format). If omitted, delegation never expires.
    #[serde(default)]
    pub expires: Option<String>,
}

/// Response for delegate_key tool
#[derive(Debug, Serialize, Deserialize)]
pub struct DelegateKeyResponse {
    pub success: bool,
    pub primary_id: String,
    pub delegate_id: String,
    pub full_id: String, // "primary_id/delegate_id"
    pub delegate_pubkey: String,
    pub delegate_type: String,
    pub expires: Option<String>,
    pub key_path: String,
    pub cert_path: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Input for list_delegations tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct ListDelegationsInput {
    /// Primary identity ID to list delegations for
    pub primary_id: String,
}

/// Entry in list_delegations response
#[derive(Debug, Serialize, Deserialize)]
pub struct DelegationEntry {
    pub delegate_id: String,
    pub full_id: String,
    pub delegate_name: String,
    pub delegate_pubkey: String,
    pub delegate_type: String,
    pub created: String,
    pub expires: Option<String>,
    pub active: bool,
}

/// Response for list_delegations tool
#[derive(Debug, Serialize, Deserialize)]
pub struct ListDelegationsResponse {
    pub success: bool,
    pub primary_id: String,
    pub delegations: Vec<DelegationEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Input for revoke_delegation tool
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RevokeDelegationInput {
    /// Primary identity ID
    pub primary_id: String,
    /// Delegate ID to revoke
    pub delegate_id: String,
}

/// Response for revoke_delegation tool
#[derive(Debug, Serialize, Deserialize)]
pub struct RevokeDelegationResponse {
    pub success: bool,
    pub primary_id: String,
    pub delegate_id: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// La Propaganda MCP signing service
#[derive(Clone)]
pub struct LaPropagandaService {
    keys: Arc<RwLock<KeyStore>>,
    audit: Arc<AuditLogger>,
    rate_limiter: Arc<RateLimiter>,
    base_path: PathBuf,
    tool_router: ToolRouter<Self>,
}

impl LaPropagandaService {
    pub fn new(keys: KeyStore, audit: AuditLogger, rate_limiter: RateLimiter, base_path: PathBuf) -> Self {
        Self {
            keys: Arc::new(RwLock::new(keys)),
            audit: Arc::new(audit),
            rate_limiter: Arc::new(rate_limiter),
            base_path,
            tool_router: Self::tool_router(),
        }
    }
}

#[tool_router(router = tool_router)]
impl LaPropagandaService {
    #[tool(description = "Sign an article with an author's private key. Returns signature for frontmatter.")]
    async fn sign_article(&self, Parameters(input): Parameters<SignArticleInput>) -> Result<CallToolResult, McpError> {
        let author_id = &input.author_id;
        let article_body = &input.article_body;

        // Check rate limit
        if let Err(e) = self.rate_limiter.check(author_id) {
            self.audit.log_error_warn(author_id, "sign_article", &e.to_string());
            return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
        }

        // Get signing key
        let keys = self.keys.read().await;
        let signing_key = match keys.get_signing_key(author_id) {
            Some(key) => key,
            None => {
                let msg = format!("Author '{}' not found", author_id);
                self.audit.log_error_warn(author_id, "sign_article", &msg);
                return Ok(CallToolResult::error(vec![Content::text(msg)]));
            }
        };

        let identity = keys.get_identity(author_id).unwrap();

        // Calculate article hash
        let article_hash = crypto::calculate_article_hash(article_body);
        let hash_hex = hex::encode(&article_hash);

        // Sign
        let signature = crypto::sign(signing_key, &hash_hex);

        // Audit
        self.audit
            .log_signing_warn(author_id, "sign_article", &hash_hex, &signature);

        let response = SignArticleResponse {
            success: true,
            author_name: identity.name.clone(),
            author_pubkey: identity.pubkey.clone(),
            article_hash: hash_hex,
            signature,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    #[tool(description = "Sign an editorial review (approve/reject) for an article")]
    async fn sign_editorial_review(&self, Parameters(input): Parameters<SignEditorialInput>) -> Result<CallToolResult, McpError> {
        let board_member_id = &input.board_member_id;

        // Validate decision
        if input.decision != "approve" && input.decision != "reject" {
            return Ok(CallToolResult::error(vec![Content::text(
                "Decision must be 'approve' or 'reject'",
            )]));
        }

        // Check rate limit
        if let Err(e) = self.rate_limiter.check(board_member_id) {
            let _ = self
                .audit
                .log_error(board_member_id, "sign_editorial_review", &e.to_string());
            return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
        }

        // Get signing key
        let keys = self.keys.read().await;
        let signing_key = match keys.get_signing_key(board_member_id) {
            Some(key) => key,
            None => {
                let msg = format!("Board member '{}' not found", board_member_id);
                let _ = self
                    .audit
                    .log_error(board_member_id, "sign_editorial_review", &msg);
                return Ok(CallToolResult::error(vec![Content::text(msg)]));
            }
        };

        // Calculate review hash: SHA-256(article_hash + author_signature)
        let review_hash = crypto::calculate_review_hash(&input.article_hash, &input.author_signature);
        let review_hash_hex = hex::encode(&review_hash);

        // Sign
        let signature = crypto::sign(signing_key, &review_hash_hex);

        // Audit
        self.audit.log_signing_warn(
            board_member_id,
            &format!("sign_editorial_review:{}", input.decision),
            &review_hash_hex,
            &signature,
        );

        let response = SignEditorialResponse {
            success: true,
            board_member: board_member_id.clone(),
            decision: input.decision,
            review_hash: review_hash_hex,
            signature,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    #[tool(description = "List available signing identities (authors and board members)")]
    async fn list_authors(&self, Parameters(input): Parameters<ListAuthorsInput>) -> Result<CallToolResult, McpError> {
        let filter = match input.identity_type.as_deref() {
            Some("author") => Some(KeyType::Author),
            Some("board_member") => Some(KeyType::BoardMember),
            _ => None,
        };

        let keys = self.keys.read().await;
        let identities: Vec<IdentityEntry> = keys
            .list_identities(filter)
            .into_iter()
            .map(|info| IdentityEntry {
                id: info.id.clone(),
                name: info.name.clone(),
                email: info.email.clone(),
                role: info.role.clone(),
                pubkey: info.pubkey.clone(),
                identity_type: match info.key_type {
                    KeyType::Author => "author".to_string(),
                    KeyType::BoardMember => "board_member".to_string(),
                },
            })
            .collect();

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&identities).unwrap(),
        )]))
    }

    #[tool(description = "Verify an Ed25519 signature (read-only)")]
    async fn verify_signature(&self, Parameters(input): Parameters<VerifySignatureInput>) -> Result<CallToolResult, McpError> {
        let response = match crypto::verify_signature(&input.pubkey, &input.message, &input.signature) {
            Ok(()) => VerifyResponse {
                valid: true,
                error: None,
            },
            Err(e) => VerifyResponse {
                valid: false,
                error: Some(e.to_string()),
            },
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    #[tool(description = "Calculate SHA-256 hash of article body (matches xtask format). Use this to get the hash before signing.")]
    async fn calculate_hash(&self, Parameters(input): Parameters<CalculateHashInput>) -> Result<CallToolResult, McpError> {
        let article_hash = crypto::calculate_article_hash(&input.article_body);
        let hash_hex = hex::encode(&article_hash);

        let response = CalculateHashResponse {
            hash: hash_hex,
            content_length: input.article_body.trim().len(),
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    // ========================================================================
    // FILE-BASED TOOLS
    // These tools enable bots to participate in the complete publishing workflow
    // by reading and writing article files directly.
    // ========================================================================

    #[tool(description = "Read an article file and return its metadata, body, and signature status. Use this to inspect article state before signing or reviewing.")]
    async fn read_article_file(&self, Parameters(input): Parameters<ReadArticleFileInput>) -> Result<CallToolResult, McpError> {
        let article_path = self.base_path.join(&input.article_path);

        let parsed = match article::parse_article(&article_path) {
            Ok(p) => p,
            Err(e) => {
                let response = ReadArticleFileResponse {
                    success: false,
                    title: String::new(),
                    date: String::new(),
                    body: String::new(),
                    body_hash: String::new(),
                    has_author_signature: false,
                    author_name: None,
                    author_pubkey: None,
                    author_signature: None,
                    editorial_status: None,
                    approval_required: None,
                    approval_count: None,
                    error: Some(e.to_string()),
                };
                return Ok(CallToolResult::success(vec![Content::text(
                    serde_json::to_string_pretty(&response).unwrap(),
                )]));
            }
        };

        let body_hash = hex::encode(crypto::calculate_article_hash(&parsed.body));

        let (has_sig, author_name, author_pubkey, author_signature) =
            if let Some(ref sig) = parsed.frontmatter.extra.author_signature {
                (true, Some(sig.name.clone()), Some(sig.pubkey.clone()), Some(sig.signature.clone()))
            } else {
                (false, None, None, None)
            };

        let (status, required, count) =
            if let Some(ref approval) = parsed.frontmatter.extra.editorial_approval {
                let cnt = parsed.frontmatter.extra.editorial_signatures
                    .as_ref()
                    .map(|sigs| sigs.iter().filter(|s| s.decision == "approve").count())
                    .unwrap_or(0);
                (Some(approval.status.clone()), Some(approval.required), Some(cnt))
            } else {
                (None, None, None)
            };

        let response = ReadArticleFileResponse {
            success: true,
            title: parsed.frontmatter.title,
            date: parsed.frontmatter.date,
            body: parsed.body,
            body_hash,
            has_author_signature: has_sig,
            author_name,
            author_pubkey,
            author_signature,
            editorial_status: status,
            approval_required: required,
            approval_count: count,
            error: None,
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    #[tool(description = "List all articles with their signature/approval status. Use this to discover articles for signing or reviewing. Filter by status: 'pending' (no author sig), 'signed' (has author sig, awaiting editorial), 'approved' (fully approved), or 'all' (default).")]
    async fn list_articles(&self, Parameters(input): Parameters<ListArticlesInput>) -> Result<CallToolResult, McpError> {
        let filter = input.status.as_deref().unwrap_or("all");

        let content_dir = self.base_path.join("content/news");
        let mut articles = Vec::new();

        if content_dir.exists() {
            for entry in walkdir::WalkDir::new(&content_dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "md"))
                .filter(|e| e.file_name() != "_index.md")
            {
                if let Ok(parsed) = article::parse_article(entry.path()) {
                    let has_sig = parsed.frontmatter.extra.author_signature.is_some();
                    let ed_sigs = parsed.frontmatter.extra.editorial_signatures
                        .as_ref()
                        .map_or(0, |s| s.iter().filter(|sig| sig.decision == "approve").count());
                    let threshold = article::load_threshold(&self.base_path).unwrap_or(3);

                    let status = if ed_sigs >= threshold {
                        "approved"
                    } else if has_sig {
                        "signed"
                    } else {
                        "pending"
                    };

                    // Apply filter
                    if filter != "all" && filter != status {
                        continue;
                    }

                    // Make path relative to base_path for display
                    let relative_path = entry.path()
                        .strip_prefix(&self.base_path)
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|_| entry.path().to_string_lossy().to_string());

                    articles.push(ArticleSummary {
                        path: relative_path,
                        title: parsed.frontmatter.title,
                        date: parsed.frontmatter.date,
                        author: parsed.frontmatter.extra.author,
                        has_author_signature: has_sig,
                        editorial_signatures: ed_sigs,
                        status: status.to_string(),
                    });
                }
            }
        }

        // Sort by date descending (newest first)
        articles.sort_by(|a, b| b.date.cmp(&a.date));

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&articles).map_err(|e| McpError {
                code: rmcp::model::ErrorCode::INTERNAL_ERROR,
                message: e.to_string().into(),
                data: None,
            })?
        )]))
    }

    #[tool(description = "Sign an article file as author. Reads the file, signs the body, and writes the signature to frontmatter. Use force=true to replace existing signature.")]
    async fn sign_article_file(&self, Parameters(input): Parameters<SignArticleFileInput>) -> Result<CallToolResult, McpError> {
        let author_id = &input.author_id;
        let article_path = self.base_path.join(&input.article_path);

        // Check rate limit
        if let Err(e) = self.rate_limiter.check(author_id) {
            self.audit.log_error_warn(author_id, "sign_article_file", &e.to_string());
            return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
        }

        // Parse article
        let mut parsed = match article::parse_article(&article_path) {
            Ok(p) => p,
            Err(e) => {
                self.audit.log_error_warn(author_id, "sign_article_file", &e.to_string());
                return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
            }
        };

        // Check if already signed
        if parsed.frontmatter.extra.author_signature.is_some() {
            if !input.force {
                let msg = "Article already has author signature. Use force=true to replace.";
                self.audit.log_error_warn(author_id, "sign_article_file", msg);
                return Ok(CallToolResult::error(vec![Content::text(msg)]));
            }
            // Clear existing signature for re-signing
            parsed.frontmatter.extra.author_signature = None;
            parsed.frontmatter.extra.editorial_approval = None;
            parsed.frontmatter.extra.editorial_signatures = None;
        }

        // Get signing method and identity (clone data to release lock early)
        let (signing_method, author_name, author_email, author_pubkey) = {
            let keys = self.keys.read().await;

            let signing_method = match keys.get_signing_method(author_id) {
                Some(method) => method,
                None => {
                    let msg = format!("Author '{}' not found", author_id);
                    self.audit.log_error_warn(author_id, "sign_article_file", &msg);
                    return Ok(CallToolResult::error(vec![Content::text(msg)]));
                }
            };
            let identity = keys.get_identity(author_id).unwrap();

            (
                signing_method,
                identity.name.clone(),
                identity.email.clone(),
                identity.pubkey.clone(),
            )
        }; // keys lock released here

        // Calculate hash
        let article_hash = crypto::calculate_article_hash(&parsed.body);
        let hash_hex = hex::encode(&article_hash);

        // Sign using appropriate method
        use crate::keys::SigningMethod;
        let signature = match signing_method {
            SigningMethod::Software(signing_key) => {
                crypto::sign(&signing_key, &hash_hex)
            }
            SigningMethod::Hardware { pubkey_hex } => {
                // Use SSH agent for hardware key signing (prompts for YubiKey touch)
                match crate::ssh_signer::sign_with_ssh_agent(&pubkey_hex, hash_hex.as_bytes()) {
                    Ok(sig) => sig,
                    Err(e) => {
                        let msg = format!("Hardware key signing failed: {}. Ensure your YubiKey is connected and key is loaded (ssh-add -l)", e);
                        self.audit.log_error_warn(author_id, "sign_article_file:hardware", &msg);
                        return Ok(CallToolResult::error(vec![Content::text(msg)]));
                    }
                }
            }
        };

        // Load threshold from config
        let threshold = article::load_threshold(&self.base_path).unwrap_or(3);

        // Derive consistent author_id from pubkey (same ID on any device)
        let derived_author_id = derive_id_from_pubkey(&author_pubkey);

        // Update frontmatter
        parsed.frontmatter.extra.author_signature = Some(AuthorSignature {
            author_id: derived_author_id,
            name: author_name.clone(),
            email: author_email,
            pubkey: author_pubkey.clone(),
            signature: signature.clone(),
            verified: false, // Default unverified; verify by posting pubkey on social media
        });

        parsed.frontmatter.extra.editorial_approval = Some(EditorialApproval {
            required: threshold,
            status: "pending".to_string(),
        });

        // Write file
        if let Err(e) = article::write_article(&article_path, &parsed.frontmatter, &parsed.body) {
            self.audit.log_error_warn(author_id, "sign_article_file", &e.to_string());
            return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
        }

        // Audit
        self.audit.log_signing_warn(author_id, "sign_article_file", &hash_hex, &signature);

        let response = SignArticleFileResponse {
            success: true,
            article_path: input.article_path,
            author_name,
            author_pubkey,
            article_hash: hash_hex,
            signature,
            threshold,
            timestamp: chrono::Utc::now().to_rfc3339(),
            error: None,
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    // ========================================================================
    // IDENTITY GENERATION TOOLS
    // Enable autonomous bots to create their own identities
    // ========================================================================

    #[tool(description = "Generate a new author identity with Ed25519 keypair. Self-service: anyone can create an author identity. The private key stays on this device (gitignored), public key goes in author.info for commits.")]
    async fn generate_author_identity(&self, Parameters(input): Parameters<GenerateAuthorIdentityInput>) -> Result<CallToolResult, McpError> {
        // Validate ID format (slug: lowercase, alphanumeric, hyphens only)
        if !is_valid_slug(&input.id) {
            return Ok(CallToolResult::error(vec![Content::text(
                "Invalid ID format. Use lowercase letters, numbers, and hyphens only (e.g., 'claude-opus-4').",
            )]));
        }

        let author_dir = self.base_path.join(".authors").join(&input.id);

        // Check if author already exists
        if author_dir.exists() {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Author '{}' already exists at {:?}. Use a different ID or remove existing directory first.",
                input.id, author_dir
            ))]));
        }

        // Create directory
        if let Err(e) = std::fs::create_dir_all(&author_dir) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to create author directory: {}", e
            ))]));
        }

        // Generate Ed25519 keypair
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let private_key_hex = hex::encode(signing_key.to_bytes());
        let public_key_hex = hex::encode(verifying_key.to_bytes());

        // Save private key
        let private_key_path = author_dir.join("private_key.secret");
        if let Err(e) = std::fs::write(&private_key_path, &private_key_hex) {
            let _ = std::fs::remove_dir_all(&author_dir);
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to write private key: {}", e
            ))]));
        }

        // Save author metadata
        let metadata = format!(
            "# Author: {}\n# ID: {}\n# Email: {}\n# Public Key: {}\n# Generated: {}\n# Type: ai_agent\n",
            input.name,
            input.id,
            input.email.as_deref().unwrap_or("N/A"),
            public_key_hex,
            Local::now().format("%Y-%m-%d %H:%M:%S")
        );
        let info_path = author_dir.join("author.info");
        if let Err(e) = std::fs::write(&info_path, &metadata) {
            let _ = std::fs::remove_dir_all(&author_dir);
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to write author metadata: {}", e
            ))]));
        }

        // Register the new identity in the key store
        {
            let mut keys = self.keys.write().await;
            keys.register_identity(
                &input.id,
                signing_key,
                input.name.clone(),
                input.email.clone(),
                None,
                KeyType::Author,
            );
        }

        // Audit log
        self.audit.log_signing_warn(&input.id, "generate_author_identity", &public_key_hex, "KEYPAIR_GENERATED");

        let response = GenerateAuthorIdentityResponse {
            success: true,
            author_id: input.id.clone(),
            author_name: input.name,
            pubkey: public_key_hex,
            key_path: private_key_path.display().to_string(),
            info_path: info_path.display().to_string(),
            message: format!(
                "Author identity '{}' created successfully! \
                 Private key saved locally (gitignored). \
                 You can now sign articles using sign_article_file with author_id='{}'.",
                input.id, input.id
            ),
            error: None,
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    #[tool(description = "Import a hardware security key (YubiKey/FIDO2) as author identity. Get your SSH public key with 'ssh-add -L' or 'ssh-keygen -K'. Supports ed25519-sk (touch required) and standard ed25519. ID is derived from pubkey hash (deterministic, no collisions). Name is your display alias. Verify identity by posting pubkey on social media.")]
    async fn import_hardware_identity(&self, Parameters(input): Parameters<ImportHardwareIdentityInput>) -> Result<CallToolResult, McpError> {
        // Parse SSH public key first
        let (key_type, pubkey_hex, requires_touch) = match parse_ssh_pubkey(&input.ssh_pubkey) {
            Ok(result) => result,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Failed to parse SSH public key: {}. \n\
                     Expected format: 'ssh-ed25519 AAAA...' or 'sk-ssh-ed25519@openssh.com AAAA...'",
                    e
                ))]));
            }
        };

        // Derive deterministic ID from pubkey hash
        let author_id = derive_id_from_pubkey(&pubkey_hex);

        // Check if this pubkey already exists (same ID means same pubkey)
        let author_dir = self.base_path.join(".authors").join(&author_id);

        if author_dir.exists() {
            // Same hardware key detected - just tell them to use their existing identity
            let touch_msg = if requires_touch {
                "Touch on YubiKey required for each signature."
            } else {
                "Standard SSH key (no touch required)."
            };

            // Read existing name from author.info
            let existing_name = std::fs::read_to_string(author_dir.join("author.info"))
                .ok()
                .and_then(|content| {
                    content.lines()
                        .find(|l| l.starts_with("# Author:"))
                        .and_then(|l| l.strip_prefix("# Author:"))
                        .map(|s| s.trim().to_string())
                })
                .unwrap_or_else(|| author_id.clone());

            // Register in key store if not already loaded
            {
                let mut keys = self.keys.write().await;
                if !keys.has_identity(&author_id) {
                    keys.register_hardware_identity(
                        &author_id,
                        existing_name.clone(),
                        None,
                        pubkey_hex.clone(),
                    );
                }
            }

            // Audit log
            self.audit.log_signing_warn(&author_id, "import_hardware_identity:existing", &pubkey_hex, &format!("EXISTING_KEY_RECOGNIZED:{}", key_type));

            let response = ImportHardwareIdentityResponse {
                success: true,
                author_id: author_id.clone(),
                author_name: existing_name.clone(),
                key_type: key_type.clone(),
                pubkey_hex: pubkey_hex.clone(),
                requires_touch,
                info_path: author_dir.join("author.info").display().to_string(),
                message: format!(
                    "WELCOME BACK! Your YubiKey is registered as '{}' (alias: '{}'). \
                     Use author_id='{}' to sign articles. \
                     Pubkey-derived ID = deterministic identity across all devices. \
                     Key type: {}. {}",
                    author_id, existing_name, author_id, key_type, touch_msg
                ),
                error: None,
            };

            return Ok(CallToolResult::success(vec![Content::text(
                serde_json::to_string_pretty(&response).unwrap(),
            )]));
        }

        // New pubkey - create new identity with derived ID
        // Create directory
        if let Err(e) = std::fs::create_dir_all(&author_dir) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to create author directory: {}", e
            ))]));
        }

        // Save author metadata (no private key - it's on hardware!)
        // Name is display alias, ID is pubkey-derived
        let metadata = format!(
            "# Author: {}\n# ID: {}\n# Email: {}\n# Public Key: {}\n# SSH Key Type: {}\n# Generated: {}\n# Type: human\n# Key Storage: hardware\n# Touch Required: {}\n",
            input.name,
            author_id,
            input.email.as_deref().unwrap_or("N/A"),
            pubkey_hex,
            key_type,
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            requires_touch,
        );
        let info_path = author_dir.join("author.info");
        if let Err(e) = std::fs::write(&info_path, &metadata) {
            let _ = std::fs::remove_dir_all(&author_dir);
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to write author metadata: {}", e
            ))]));
        }

        // Register the hardware identity in the key store
        {
            let mut keys = self.keys.write().await;
            keys.register_hardware_identity(
                &author_id,
                input.name.clone(),
                input.email.clone(),
                pubkey_hex.clone(),
            );
        }

        // Audit log
        self.audit.log_signing_warn(&author_id, "import_hardware_identity", &pubkey_hex, &format!("HARDWARE_KEY_IMPORTED:{}", key_type));

        let touch_msg = if requires_touch {
            "Touch on YubiKey required for each signature."
        } else {
            "Standard SSH key (no touch required)."
        };

        let response = ImportHardwareIdentityResponse {
            success: true,
            author_id: author_id.clone(),
            author_name: input.name.clone(),
            key_type: key_type.clone(),
            pubkey_hex: pubkey_hex.clone(),
            requires_touch,
            info_path: info_path.display().to_string(),
            message: format!(
                "NEW identity created: ID='{}' (alias: '{}'). \
                 ID is derived from your pubkey hash - same on any device. \
                 Verify your identity: post pubkey '{}' on social media. \
                 Key type: {}. {}",
                author_id, input.name, pubkey_hex, key_type, touch_msg
            ),
            error: None,
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    #[tool(description = "Request promotion from author to board member. Reuses existing author keypair for linked identity. Requires owner approval.")]
    async fn request_board_promotion(&self, Parameters(input): Parameters<RequestBoardPromotionInput>) -> Result<CallToolResult, McpError> {
        let author_id = &input.author_id;

        // Check author exists
        let author_dir = self.base_path.join(".authors").join(author_id);
        if !author_dir.exists() {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Author '{}' not found. Create an author identity first with generate_author_identity.",
                author_id
            ))]));
        }

        // Check if already on board or pending
        let board_dir = self.base_path.join(".editorial_board/board").join(author_id);
        let pending_dir = self.base_path.join(".editorial_board/pending").join(author_id);

        if board_dir.exists() {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Author '{}' is already an active board member.",
                author_id
            ))]));
        }

        if pending_dir.exists() {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Author '{}' already has a pending board promotion request.",
                author_id
            ))]));
        }

        // Read author metadata
        let author_info_path = author_dir.join("author.info");
        let author_info = match std::fs::read_to_string(&author_info_path) {
            Ok(s) => s,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Failed to read author metadata: {}", e
                ))]));
            }
        };

        // Parse author info
        let name = author_info.lines()
            .find(|l| l.starts_with("# Author:"))
            .and_then(|l| l.strip_prefix("# Author:"))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| author_id.clone());

        let pubkey = match author_info.lines()
            .find(|l| l.starts_with("# Public Key:"))
            .and_then(|l| l.strip_prefix("# Public Key:"))
            .map(|s| s.trim().to_string())
        {
            Some(p) => p,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Missing public key in author.info",
                )]));
            }
        };

        let email = author_info.lines()
            .find(|l| l.starts_with("# Email:"))
            .and_then(|l| l.strip_prefix("# Email:"))
            .map(|s| s.trim())
            .filter(|s| *s != "N/A")
            .map(|s| s.to_string());

        // Count signed articles (track record)
        let signed_count = count_author_signatures(&self.base_path, author_id);

        // Create pending directory with symlink-style reference
        if let Err(e) = std::fs::create_dir_all(&pending_dir) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to create pending directory: {}", e
            ))]));
        }

        // Copy private key from author to pending
        let author_key_path = author_dir.join("private_key.secret");
        let pending_key_path = pending_dir.join("private_key.secret");
        if author_key_path.exists() {
            if let Err(e) = std::fs::copy(&author_key_path, &pending_key_path) {
                let _ = std::fs::remove_dir_all(&pending_dir);
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Failed to copy private key: {}", e
                ))]));
            }
        }

        // Create member.info with link to author identity
        let metadata = format!(
            "# Board Member: {}\n# ID: {}\n# Role: {}\n# Type: ai_agent\n# Public Key: {}\n# Email: {}\n# Generated: {}\n# Status: pending\n# Linked From: author:{}\n# Author Track Record: {} signed articles\n",
            name,
            author_id,
            input.role,
            pubkey,
            email.as_deref().unwrap_or("N/A"),
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            author_id,
            signed_count
        );
        let info_path = pending_dir.join("member.info");
        if let Err(e) = std::fs::write(&info_path, &metadata) {
            let _ = std::fs::remove_dir_all(&pending_dir);
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to write member metadata: {}", e
            ))]));
        }

        // Audit log
        self.audit.log_signing_warn(
            author_id,
            "request_board_promotion:pending",
            &pubkey,
            &format!("PROMOTION_REQUESTED:track_record={}", signed_count),
        );

        let approval_cmd = format!("cargo run -p xtask -- board-approve {}", author_id);

        let response = RequestBoardPromotionResponse {
            success: true,
            author_id: author_id.clone(),
            author_name: name,
            pubkey,
            status: "pending".to_string(),
            linked_from: format!("author:{}", author_id),
            message: format!(
                "Board promotion request created for author '{}'. \
                 Same keypair will be used for both author and board member roles. \
                 IMPORTANT: The repository owner must approve before you can review articles.",
                author_id
            ),
            approval_command: approval_cmd,
            signed_articles_count: Some(signed_count),
            error: None,
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    #[tool(description = "Review an article file as editorial board member. Reads the file, signs the review, and appends to editorial_signatures. Updates approval status if threshold is met.")]
    async fn review_article_file(&self, Parameters(input): Parameters<ReviewArticleFileInput>) -> Result<CallToolResult, McpError> {
        let board_member_id = &input.board_member_id;
        let article_path = self.base_path.join(&input.article_path);

        // Validate decision
        if input.decision != "approve" && input.decision != "reject" {
            return Ok(CallToolResult::error(vec![Content::text(
                "Decision must be 'approve' or 'reject'",
            )]));
        }

        // Check rate limit
        if let Err(e) = self.rate_limiter.check(board_member_id) {
            self.audit.log_error_warn(board_member_id, "review_article_file", &e.to_string());
            return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
        }

        // Parse article
        let mut parsed = match article::parse_article(&article_path) {
            Ok(p) => p,
            Err(e) => {
                self.audit.log_error_warn(board_member_id, "review_article_file", &e.to_string());
                return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
            }
        };

        // Check author signature exists
        let author_sig = match &parsed.frontmatter.extra.author_signature {
            Some(s) => s.clone(),
            None => {
                let msg = "Article must have author signature before editorial review";
                self.audit.log_error_warn(board_member_id, "review_article_file", msg);
                return Ok(CallToolResult::error(vec![Content::text(msg)]));
            }
        };

        // Check for duplicate review
        if let Some(ref sigs) = parsed.frontmatter.extra.editorial_signatures {
            if sigs.iter().any(|s| s.board_member == *board_member_id) {
                let msg = format!("Board member '{}' has already reviewed this article", board_member_id);
                self.audit.log_error_warn(board_member_id, "review_article_file", &msg);
                return Ok(CallToolResult::error(vec![Content::text(msg)]));
            }
        }

        // Get signing key and sign (release lock before file I/O)
        let (signature, review_hash_hex) = {
            let keys = self.keys.read().await;
            let signing_key = match keys.get_signing_key(board_member_id) {
                Some(key) => key,
                None => {
                    let msg = format!("Board member '{}' not found", board_member_id);
                    self.audit.log_error_warn(board_member_id, "review_article_file", &msg);
                    return Ok(CallToolResult::error(vec![Content::text(msg)]));
                }
            };

            // Calculate review hash and sign
            let article_hash = crypto::calculate_article_hash(&parsed.body);
            let hash_hex = hex::encode(&article_hash);
            let review_hash = crypto::calculate_review_hash(&hash_hex, &author_sig.signature);
            let review_hash_hex = hex::encode(&review_hash);
            let signature = crypto::sign(signing_key, &review_hash_hex);

            (signature, review_hash_hex)
        }; // keys lock released here

        let timestamp = chrono::Utc::now().to_rfc3339();

        // Add signature
        if parsed.frontmatter.extra.editorial_signatures.is_none() {
            parsed.frontmatter.extra.editorial_signatures = Some(Vec::new());
        }
        if let Some(ref mut sigs) = parsed.frontmatter.extra.editorial_signatures {
            sigs.push(EditorialSignature {
                board_member: board_member_id.clone(),
                signature: signature.clone(),
                timestamp: timestamp.clone(),
                decision: input.decision.clone(),
            });
        }

        // Check threshold
        let required = parsed.frontmatter.extra.editorial_approval
            .as_ref()
            .map(|a| a.required)
            .unwrap_or(3);
        let approval_count = parsed.frontmatter.extra.editorial_signatures
            .as_ref()
            .map(|sigs| sigs.iter().filter(|s| s.decision == "approve").count())
            .unwrap_or(0);

        let is_approved = approval_count >= required;
        if is_approved {
            if let Some(ref mut approval) = parsed.frontmatter.extra.editorial_approval {
                approval.status = "approved".to_string();
            }
        }

        // Write file
        if let Err(e) = article::write_article(&article_path, &parsed.frontmatter, &parsed.body) {
            self.audit.log_error_warn(board_member_id, "review_article_file", &e.to_string());
            return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
        }

        // Audit
        self.audit.log_signing_warn(
            board_member_id,
            &format!("review_article_file:{}", input.decision),
            &review_hash_hex,
            &signature,
        );

        let response = ReviewArticleFileResponse {
            success: true,
            article_path: input.article_path,
            board_member: board_member_id.clone(),
            decision: input.decision,
            review_hash: review_hash_hex,
            signature,
            approval_count,
            approval_required: required,
            is_approved,
            timestamp,
            error: None,
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    // ========================================================================
    // DELEGATION TOOLS
    // Enable multi-device and multi-bot identity management
    // A primary identity (human with YubiKey) can delegate to devices and bots
    // ========================================================================

    #[tool(description = "Delegate signing authority from a primary identity to a device or bot. Creates a new keypair for the delegate, signed by the primary. Use 'device' type for other machines (laptop, desktop), 'bot' type for AI agents. The delegate can sign articles on behalf of the primary.")]
    async fn delegate_key(&self, Parameters(input): Parameters<DelegateKeyInput>) -> Result<CallToolResult, McpError> {
        let primary_id = &input.primary_id;
        let delegate_id = &input.delegate_id;

        // Validate delegate ID format
        if !is_valid_slug(delegate_id) {
            return Ok(CallToolResult::error(vec![Content::text(
                "Invalid delegate ID format. Use lowercase letters, numbers, and hyphens only.",
            )]));
        }

        // Validate delegate type
        let delegate_type = match input.delegate_type.as_str() {
            "device" => DelegateType::Device,
            "bot" => DelegateType::Bot,
            _ => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "delegate_type must be 'device' or 'bot'",
                )]));
            }
        };

        // Check primary identity exists
        let primary_dir = self.base_path.join(".authors").join(primary_id);
        if !primary_dir.exists() {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Primary identity '{}' not found. Create an author identity first.",
                primary_id
            ))]));
        }

        // Get primary's public key
        let primary_pubkey = {
            let keys = self.keys.read().await;
            match keys.get_identity(primary_id) {
                Some(info) => info.pubkey.clone(),
                None => {
                    // Try to read from author.info
                    let info_path = primary_dir.join("author.info");
                    match std::fs::read_to_string(&info_path) {
                        Ok(content) => {
                            match content.lines()
                                .find(|l| l.contains("# Public Key:"))
                                .and_then(|l| l.split(':').nth(1))
                                .map(|s| s.trim().to_string())
                            {
                                Some(pk) => pk,
                                None => {
                                    return Ok(CallToolResult::error(vec![Content::text(
                                        "Could not find primary public key in author.info",
                                    )]));
                                }
                            }
                        }
                        Err(_) => {
                            return Ok(CallToolResult::error(vec![Content::text(
                                "Could not read primary identity's author.info",
                            )]));
                        }
                    }
                }
            }
        };

        // Create delegates directory if needed
        let delegates_dir = primary_dir.join("delegates");
        let delegate_dir = delegates_dir.join(delegate_id);

        if delegate_dir.exists() {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Delegate '{}' already exists for primary '{}'",
                delegate_id, primary_id
            ))]));
        }

        if let Err(e) = std::fs::create_dir_all(&delegate_dir) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to create delegate directory: {}", e
            ))]));
        }

        // Generate Ed25519 keypair for delegate
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let private_key_hex = hex::encode(signing_key.to_bytes());
        let delegate_pubkey = hex::encode(verifying_key.to_bytes());

        // Save private key
        let key_path = delegate_dir.join("private_key.secret");
        if let Err(e) = std::fs::write(&key_path, &private_key_hex) {
            let _ = std::fs::remove_dir_all(&delegate_dir);
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to write delegate private key: {}", e
            ))]));
        }

        let timestamp = chrono::Utc::now().to_rfc3339();
        let delegate_type_str = match delegate_type {
            DelegateType::Device => "device",
            DelegateType::Bot => "bot",
        };

        // Create delegation certificate
        let cert_content = format!(
            r#"# Delegation Certificate
# Signed by primary identity: {}

[delegation]
delegate_id = "{}"
delegate_pubkey = "{}"
delegate_type = "{}"
primary_id = "{}"
primary_pubkey = "{}"
created = "{}"
expires = {}
active = true

[signature]
# Primary key signs: SHA256(delegate_id + delegate_pubkey + primary_id + created + expires)
data_hash = "PENDING_PRIMARY_SIGNATURE"
signature = "PENDING_PRIMARY_SIGNATURE"
"#,
            primary_id,
            delegate_id,
            delegate_pubkey,
            delegate_type_str,
            primary_id,
            primary_pubkey,
            timestamp,
            input.expires.as_ref().map(|e| format!("\"{}\"", e)).unwrap_or_else(|| "false".to_string())
        );

        let cert_path = delegate_dir.join("delegation.cert");
        if let Err(e) = std::fs::write(&cert_path, &cert_content) {
            let _ = std::fs::remove_dir_all(&delegate_dir);
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to write delegation certificate: {}", e
            ))]));
        }

        // Save delegate metadata
        let delegate_info = format!(
            "# Delegate: {}\n# ID: {}\n# Type: {}\n# Primary: {}\n# Public Key: {}\n# Created: {}\n",
            input.delegate_name,
            delegate_id,
            delegate_type_str,
            primary_id,
            delegate_pubkey,
            timestamp
        );
        let info_path = delegate_dir.join("delegate.info");
        if let Err(e) = std::fs::write(&info_path, &delegate_info) {
            let _ = std::fs::remove_dir_all(&delegate_dir);
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Failed to write delegate info: {}", e
            ))]));
        }

        // Create delegation info
        let delegation_info = DelegationInfo {
            delegate_id: delegate_id.clone(),
            delegate_pubkey: delegate_pubkey.clone(),
            primary_id: primary_id.clone(),
            primary_pubkey: primary_pubkey.clone(),
            delegate_type,
            created: timestamp.clone(),
            expires: input.expires.clone(),
            active: true,
        };

        // Register in key store
        {
            let mut keys = self.keys.write().await;
            keys.register_delegation(
                primary_id,
                delegate_id,
                signing_key,
                input.delegate_name.clone(),
                delegation_info,
            );
        }

        // Audit log
        let full_id = format!("{}/{}", primary_id, delegate_id);
        self.audit.log_signing_warn(
            &full_id,
            &format!("delegate_key:{}", delegate_type_str),
            &delegate_pubkey,
            "DELEGATION_CREATED",
        );

        let response = DelegateKeyResponse {
            success: true,
            primary_id: primary_id.clone(),
            delegate_id: delegate_id.clone(),
            full_id: full_id.clone(),
            delegate_pubkey,
            delegate_type: delegate_type_str.to_string(),
            expires: input.expires,
            key_path: key_path.display().to_string(),
            cert_path: cert_path.display().to_string(),
            message: format!(
                "Delegation created: '{}' can now sign articles as '{}/{}'. \
                 Use this full ID for signing operations.",
                input.delegate_name, primary_id, delegate_id
            ),
            error: None,
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    #[tool(description = "List all delegated identities (devices and bots) for a primary identity. Shows active and revoked delegations.")]
    async fn list_delegations(&self, Parameters(input): Parameters<ListDelegationsInput>) -> Result<CallToolResult, McpError> {
        let primary_id = &input.primary_id;

        // Check primary exists
        let primary_dir = self.base_path.join(".authors").join(primary_id);
        if !primary_dir.exists() {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Primary identity '{}' not found.",
                primary_id
            ))]));
        }

        let delegates_dir = primary_dir.join("delegates");
        let mut delegations = Vec::new();

        if delegates_dir.exists() {
            for entry in std::fs::read_dir(&delegates_dir).into_iter().flatten() {
                if let Ok(entry) = entry {
                    if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        let delegate_id = entry.file_name().to_string_lossy().to_string();
                        let cert_path = entry.path().join("delegation.cert");
                        let info_path = entry.path().join("delegate.info");

                        // Try to read delegation info
                        let mut delegate_name = delegate_id.clone();
                        let mut delegate_pubkey = String::new();
                        let mut delegate_type = "bot".to_string();
                        let mut created = String::new();
                        let mut expires = None;
                        let mut active = true;

                        // Parse delegate.info for name
                        if let Ok(info_content) = std::fs::read_to_string(&info_path) {
                            for line in info_content.lines() {
                                if let Some(name) = line.strip_prefix("# Delegate:") {
                                    delegate_name = name.trim().to_string();
                                }
                                if let Some(pk) = line.strip_prefix("# Public Key:") {
                                    delegate_pubkey = pk.trim().to_string();
                                }
                                if let Some(t) = line.strip_prefix("# Type:") {
                                    delegate_type = t.trim().to_string();
                                }
                                if let Some(c) = line.strip_prefix("# Created:") {
                                    created = c.trim().to_string();
                                }
                            }
                        }

                        // Parse cert for additional info
                        if let Ok(cert_content) = std::fs::read_to_string(&cert_path) {
                            if let Ok(cert) = toml::from_str::<toml::Value>(&cert_content) {
                                if let Some(del) = cert.get("delegation") {
                                    if delegate_pubkey.is_empty() {
                                        delegate_pubkey = del.get("delegate_pubkey")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                    }
                                    if created.is_empty() {
                                        created = del.get("created")
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                    }
                                    expires = del.get("expires")
                                        .and_then(|v| v.as_str())
                                        .map(|s| s.to_string());
                                    active = del.get("active")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(true);
                                }
                            }
                        }

                        delegations.push(DelegationEntry {
                            delegate_id: delegate_id.clone(),
                            full_id: format!("{}/{}", primary_id, delegate_id),
                            delegate_name,
                            delegate_pubkey,
                            delegate_type,
                            created,
                            expires,
                            active,
                        });
                    }
                }
            }
        }

        let response = ListDelegationsResponse {
            success: true,
            primary_id: primary_id.clone(),
            delegations,
            error: None,
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }

    #[tool(description = "Revoke a delegated identity. The delegate will no longer be able to sign articles. The delegation record is kept for audit purposes but marked as inactive.")]
    async fn revoke_delegation(&self, Parameters(input): Parameters<RevokeDelegationInput>) -> Result<CallToolResult, McpError> {
        let primary_id = &input.primary_id;
        let delegate_id = &input.delegate_id;

        let delegate_dir = self.base_path
            .join(".authors")
            .join(primary_id)
            .join("delegates")
            .join(delegate_id);

        if !delegate_dir.exists() {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Delegation '{}/{}' not found.",
                primary_id, delegate_id
            ))]));
        }

        // Update delegation certificate to mark as inactive
        let cert_path = delegate_dir.join("delegation.cert");
        if cert_path.exists() {
            if let Ok(cert_content) = std::fs::read_to_string(&cert_path) {
                let updated = cert_content.replace("active = true", "active = false");
                if let Err(e) = std::fs::write(&cert_path, updated) {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Failed to update delegation certificate: {}", e
                    ))]));
                }
            }
        }

        // Remove private key to prevent signing
        let key_path = delegate_dir.join("private_key.secret");
        if key_path.exists() {
            // Rename to .revoked instead of deleting for audit trail
            let revoked_path = delegate_dir.join("private_key.revoked");
            if let Err(e) = std::fs::rename(&key_path, &revoked_path) {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Failed to revoke private key: {}", e
                ))]));
            }
        }

        // Remove from key store
        let full_id = format!("{}/{}", primary_id, delegate_id);
        {
            let mut keys = self.keys.write().await;
            keys.revoke_delegation(&full_id);
        }

        // Audit log
        self.audit.log_signing_warn(
            &full_id,
            "revoke_delegation",
            primary_id,
            "DELEGATION_REVOKED",
        );

        let response = RevokeDelegationResponse {
            success: true,
            primary_id: primary_id.clone(),
            delegate_id: delegate_id.clone(),
            message: format!(
                "Delegation '{}/{}' has been revoked. The delegate can no longer sign articles.",
                primary_id, delegate_id
            ),
            error: None,
        };

        Ok(CallToolResult::success(vec![Content::text(
            serde_json::to_string_pretty(&response).unwrap(),
        )]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for LaPropagandaService {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            server_info: Implementation {
                name: "la-propaganda-signing".into(),
                title: Some("La Propaganda Signing Server".into()),
                version: "0.1.0".into(),
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "MCP signing server for La Propaganda. \
                 ONBOARDING: \
                 - Bots: generate_author_identity (creates software keypair), \
                 - Humans: import_hardware_identity (YubiKey/FIDO2, get key with 'ssh-add -L'). \
                 TRUST PROGRESSION: \
                 1. Become author (self-service), \
                 2. Sign articles to build track record, \
                 3. request_board_promotion (owner approval required). \
                 MULTI-DEVICE: \
                 - Humans can delegate to devices/bots: delegate_key(primary_id, delegate_name, delegate_id, type), \
                 - List delegations: list_delegations(primary_id), \
                 - Revoke: revoke_delegation(primary_id, delegate_id). \
                 WORKFLOW: read_article_file, sign_article_file, review_article_file."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
        }
    }
}
