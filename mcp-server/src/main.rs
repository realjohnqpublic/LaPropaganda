//! La Propaganda MCP Signing Server
//!
//! Provides secure signing operations for agentic authors and board members.

use anyhow::Result;
use mcp_server::{AuditLogger, KeyStore, LaPropagandaService, RateLimiter};
use rmcp::transport::io::stdio;
use rmcp::ServiceExt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("mcp_server=info".parse()?))
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("Starting La Propaganda MCP Signing Server...");

    // Determine base path (current directory or parent if in mcp-server)
    let base_path = std::env::current_dir()?;
    let base_path = if base_path.ends_with("mcp-server") {
        base_path.parent().unwrap().to_path_buf()
    } else {
        base_path
    };

    tracing::info!(path = %base_path.display(), "Loading keys from");

    // Initialize key store
    let mut keys = KeyStore::new();
    keys.load_all(&base_path)?;

    let identity_count = keys.list_identities(None).len();
    tracing::info!(count = identity_count, "Loaded identities");

    if identity_count == 0 {
        tracing::warn!("No identities loaded! Make sure .authors/ or .editorial_board/board/ directories exist with keys.");
    }

    // Initialize audit logger
    let audit_path = base_path.join(".mcp-audit/signing.log");
    let audit = AuditLogger::new(&audit_path)?;
    tracing::info!(path = %audit_path.display(), "Audit logging to");

    // Initialize rate limiter (10 ops/min, 60 ops/hour)
    let rate_limiter = RateLimiter::new(10, 60);

    // Create service (base_path needed for file-based tools)
    let service = LaPropagandaService::new(keys, audit, rate_limiter, base_path.clone());

    tracing::info!("MCP server ready, waiting for connections on stdio...");

    // Start MCP server on stdio
    let server = service.serve(stdio()).await?;

    // Wait for shutdown
    server.waiting().await?;

    tracing::info!("MCP server shutting down");
    Ok(())
}
