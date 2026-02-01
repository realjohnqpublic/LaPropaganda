//! Audit logging for MCP signing operations
//!
//! All signing operations are logged to an append-only file.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

/// A single audit log entry
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub identity_id: String,
    pub operation: String,
    pub message_hash: String,
    pub signature_prefix: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Audit logger that writes to a file
pub struct AuditLogger {
    file: Mutex<BufWriter<File>>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(path: &Path) -> Result<Self> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        Ok(Self {
            file: Mutex::new(BufWriter::new(file)),
        })
    }

    /// Log a successful signing operation
    pub fn log_signing(
        &self,
        identity_id: &str,
        operation: &str,
        message_hash: &str,
        signature: &str,
    ) -> Result<()> {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            identity_id: identity_id.to_string(),
            operation: operation.to_string(),
            message_hash: message_hash.to_string(),
            // Store longer prefix for better audit traceability
            signature_prefix: signature.chars().take(32).collect(),
            success: true,
            error: None,
        };

        self.write_entry(&entry)
    }

    /// Log a failed operation
    pub fn log_error(&self, identity_id: &str, operation: &str, error: &str) -> Result<()> {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            identity_id: identity_id.to_string(),
            operation: operation.to_string(),
            message_hash: String::new(),
            signature_prefix: String::new(),
            success: false,
            error: Some(error.to_string()),
        };

        self.write_entry(&entry)
    }

    fn write_entry(&self, entry: &AuditEntry) -> Result<()> {
        let mut file = self.file.lock().unwrap();
        serde_json::to_writer(&mut *file, entry)?;
        writeln!(&mut *file)?;
        file.flush()?;
        Ok(())
    }
}

/// No-op logger for testing
pub struct NullLogger;

impl NullLogger {
    pub fn log_signing(&self, _: &str, _: &str, _: &str, _: &str) -> Result<()> {
        Ok(())
    }

    pub fn log_error(&self, _: &str, _: &str, _: &str) -> Result<()> {
        Ok(())
    }
}
