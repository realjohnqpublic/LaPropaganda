//! Rate limiting for MCP signing operations
//!
//! Prevents abuse by limiting operations per identity per time window.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Rate limiter error
#[derive(Debug, Clone)]
pub struct RateLimitError {
    pub identity_id: String,
    pub limit_type: String,
    pub retry_after_secs: u64,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Rate limit exceeded for '{}' ({}). Retry after {} seconds.",
            self.identity_id, self.limit_type, self.retry_after_secs
        )
    }
}

impl std::error::Error for RateLimitError {}

/// Per-identity rate state
struct IdentityState {
    minute_window: Vec<Instant>,
    hour_window: Vec<Instant>,
}

/// Rate limiter with configurable limits
pub struct RateLimiter {
    ops_per_minute: u32,
    ops_per_hour: u32,
    state: Mutex<HashMap<String, IdentityState>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(ops_per_minute: u32, ops_per_hour: u32) -> Self {
        Self {
            ops_per_minute,
            ops_per_hour,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Check if an operation is allowed for the given identity
    /// Returns Ok(()) if allowed, or Err with retry info if rate limited
    pub fn check(&self, identity_id: &str) -> Result<(), RateLimitError> {
        // Handle mutex poisoning gracefully (fail-closed for security)
        let mut state = self.state.lock().map_err(|_| RateLimitError {
            identity_id: identity_id.to_string(),
            limit_type: "internal-error".to_string(),
            retry_after_secs: 60,
        })?;
        let now = Instant::now();

        let entry = state.entry(identity_id.to_string()).or_insert(IdentityState {
            minute_window: Vec::new(),
            hour_window: Vec::new(),
        });

        // Clean old entries
        entry
            .minute_window
            .retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        entry
            .hour_window
            .retain(|t| now.duration_since(*t) < Duration::from_secs(3600));

        // Check minute limit
        if entry.minute_window.len() >= self.ops_per_minute as usize {
            let oldest = entry.minute_window.first().unwrap();
            let retry_after = 60 - now.duration_since(*oldest).as_secs();
            return Err(RateLimitError {
                identity_id: identity_id.to_string(),
                limit_type: "per-minute".to_string(),
                retry_after_secs: retry_after.max(1),
            });
        }

        // Check hour limit
        if entry.hour_window.len() >= self.ops_per_hour as usize {
            let oldest = entry.hour_window.first().unwrap();
            let retry_after = 3600 - now.duration_since(*oldest).as_secs();
            return Err(RateLimitError {
                identity_id: identity_id.to_string(),
                limit_type: "per-hour".to_string(),
                retry_after_secs: retry_after.max(1),
            });
        }

        // Record this operation
        entry.minute_window.push(now);
        entry.hour_window.push(now);

        Ok(())
    }

    /// Reset rate limit state for an identity (for testing)
    #[cfg(test)]
    pub fn reset(&self, identity_id: &str) {
        let mut state = self.state.lock().unwrap();
        state.remove(identity_id);
    }
}

/// No-op rate limiter for testing
pub struct NoopRateLimiter;

impl NoopRateLimiter {
    pub fn check(&self, _: &str) -> Result<(), RateLimitError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(5, 10);

        for _ in 0..5 {
            assert!(limiter.check("test-id").is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(2, 10);

        assert!(limiter.check("test-id").is_ok());
        assert!(limiter.check("test-id").is_ok());
        assert!(limiter.check("test-id").is_err());
    }

    #[test]
    fn test_rate_limiter_per_identity() {
        let limiter = RateLimiter::new(1, 10);

        assert!(limiter.check("id-1").is_ok());
        assert!(limiter.check("id-2").is_ok());
        assert!(limiter.check("id-1").is_err());
        assert!(limiter.check("id-2").is_err());
    }
}
