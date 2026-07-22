//! Error types for wisp-core.

use thiserror::Error;

/// Top-level error type returned by wisp-core operations.
///
/// Variants are intentionally coarse in Phase 1; later phases add specific
/// wisp/tls/http/proxy variants as those subsystems land.
#[derive(Debug, Error)]
pub enum Error {
    /// A configuration value is malformed or contradicts another option.
    #[error("configuration error: {0}")]
    Config(String),

    /// The transport has not been configured before an operation that
    /// required it (e.g. `perform()` on a `WispHandle` without a URL).
    #[error("no transport configured")]
    NoTransport,

    /// An operation timed out.
    #[error("operation timed out after {0:?}")]
    Timeout(std::time::Duration),

    /// Placeholder for later-phase variants. Never returned in Phase 1.
    #[error("drift internal error: {0}")]
    Internal(String),
}

/// Convenient Result alias.
pub type Result<T> = std::result::Result<T, Error>;
