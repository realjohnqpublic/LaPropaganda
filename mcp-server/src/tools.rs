//! MCP tool implementations for La Propaganda signing server

use crate::article::{self, AuthorSignature, EditorialApproval, EditorialSignature};
use crate::audit::AuditLogger;
use crate::crypto;
use crate::keys::{KeyStore, KeyType};
use crate::rate_limit::RateLimiter;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo, Implementation};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

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
            let _ = self.audit.log_error(author_id, "sign_article", &e.to_string());
            return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
        }

        // Get signing key
        let keys = self.keys.read().await;
        let signing_key = match keys.get_signing_key(author_id) {
            Some(key) => key,
            None => {
                let msg = format!("Author '{}' not found", author_id);
                let _ = self.audit.log_error(author_id, "sign_article", &msg);
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
        let _ = self
            .audit
            .log_signing(author_id, "sign_article", &hash_hex, &signature);

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
        let _ = self.audit.log_signing(
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

    #[tool(description = "Sign an article file as author. Reads the file, signs the body, and writes the signature to frontmatter. The article must not already have an author signature.")]
    async fn sign_article_file(&self, Parameters(input): Parameters<SignArticleFileInput>) -> Result<CallToolResult, McpError> {
        let author_id = &input.author_id;
        let article_path = self.base_path.join(&input.article_path);

        // Check rate limit
        if let Err(e) = self.rate_limiter.check(author_id) {
            let _ = self.audit.log_error(author_id, "sign_article_file", &e.to_string());
            return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
        }

        // Parse article
        let mut parsed = match article::parse_article(&article_path) {
            Ok(p) => p,
            Err(e) => {
                let _ = self.audit.log_error(author_id, "sign_article_file", &e.to_string());
                return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
            }
        };

        // Check if already signed
        if parsed.frontmatter.extra.author_signature.is_some() {
            let msg = "Article already has author signature. Remove [extra.author_signature] section first to re-sign.";
            let _ = self.audit.log_error(author_id, "sign_article_file", msg);
            return Ok(CallToolResult::error(vec![Content::text(msg)]));
        }

        // Get signing key and identity (clone data to release lock early)
        let (signature, author_name, author_email, author_pubkey, hash_hex) = {
            let keys = self.keys.read().await;
            let signing_key = match keys.get_signing_key(author_id) {
                Some(key) => key,
                None => {
                    let msg = format!("Author '{}' not found", author_id);
                    let _ = self.audit.log_error(author_id, "sign_article_file", &msg);
                    return Ok(CallToolResult::error(vec![Content::text(msg)]));
                }
            };
            let identity = keys.get_identity(author_id).unwrap();

            // Calculate hash and sign
            let article_hash = crypto::calculate_article_hash(&parsed.body);
            let hash_hex = hex::encode(&article_hash);
            let signature = crypto::sign(signing_key, &hash_hex);

            (
                signature,
                identity.name.clone(),
                identity.email.clone(),
                identity.pubkey.clone(),
                hash_hex,
            )
        }; // keys lock released here

        // Load threshold from config
        let threshold = article::load_threshold(&self.base_path).unwrap_or(3);

        // Update frontmatter
        parsed.frontmatter.extra.author_signature = Some(AuthorSignature {
            name: author_name.clone(),
            email: author_email,
            pubkey: author_pubkey.clone(),
            signature: signature.clone(),
        });

        parsed.frontmatter.extra.editorial_approval = Some(EditorialApproval {
            required: threshold,
            status: "pending".to_string(),
        });

        // Write file
        if let Err(e) = article::write_article(&article_path, &parsed.frontmatter, &parsed.body) {
            let _ = self.audit.log_error(author_id, "sign_article_file", &e.to_string());
            return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
        }

        // Audit
        let _ = self.audit.log_signing(author_id, "sign_article_file", &hash_hex, &signature);

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
            let _ = self.audit.log_error(board_member_id, "review_article_file", &e.to_string());
            return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
        }

        // Parse article
        let mut parsed = match article::parse_article(&article_path) {
            Ok(p) => p,
            Err(e) => {
                let _ = self.audit.log_error(board_member_id, "review_article_file", &e.to_string());
                return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
            }
        };

        // Check author signature exists
        let author_sig = match &parsed.frontmatter.extra.author_signature {
            Some(s) => s.clone(),
            None => {
                let msg = "Article must have author signature before editorial review";
                let _ = self.audit.log_error(board_member_id, "review_article_file", msg);
                return Ok(CallToolResult::error(vec![Content::text(msg)]));
            }
        };

        // Check for duplicate review
        if let Some(ref sigs) = parsed.frontmatter.extra.editorial_signatures {
            if sigs.iter().any(|s| s.board_member == *board_member_id) {
                let msg = format!("Board member '{}' has already reviewed this article", board_member_id);
                let _ = self.audit.log_error(board_member_id, "review_article_file", &msg);
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
                    let _ = self.audit.log_error(board_member_id, "review_article_file", &msg);
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
            let _ = self.audit.log_error(board_member_id, "review_article_file", &e.to_string());
            return Ok(CallToolResult::error(vec![Content::text(e.to_string())]));
        }

        // Audit
        let _ = self.audit.log_signing(
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
                 FILE-BASED WORKFLOW (recommended for bots): \
                 1. read_article_file - inspect article state, \
                 2. sign_article_file - sign as author (updates file), \
                 3. review_article_file - approve/reject (updates file). \
                 MANUAL WORKFLOW: calculate_hash, sign_article, sign_editorial_review. \
                 UTILITIES: list_authors, verify_signature."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
        }
    }
}
