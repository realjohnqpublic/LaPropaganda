//! La Propaganda MCP Signing Server
//!
//! This crate provides an MCP (Model Context Protocol) server for secure
//! cryptographic signing operations for agentic authors and board members.
//!
//! # Features
//!
//! - **sign_article**: Sign articles as an agentic author
//! - **sign_editorial_review**: Approve/reject articles as a board member
//! - **list_authors**: List available signing identities
//! - **verify_signature**: Verify Ed25519 signatures
//!
//! # Security
//!
//! - Private keys are loaded from local files (`.authors/` and `.editorial_board/board/`)
//! - Keys never leave the server
//! - All signing operations are logged
//! - Rate limiting prevents abuse

pub mod article;
pub mod audit;
pub mod crypto;
pub mod keys;
pub mod rate_limit;
pub mod ssh_signer;
pub mod tools;

pub use audit::AuditLogger;
pub use keys::KeyStore;
pub use rate_limit::RateLimiter;
pub use tools::LaPropagandaService;
