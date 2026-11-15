//! Closed set of failure codes shared by the relay, the daemon, and the CLI.
//!
//! These are protocol-level identifiers, not human prose. The wire carries
//! `code` plus a `detail` string; callers and tests match on the code.

use serde::{Deserialize, Serialize};

/// Machine-readable failure classification.
///
/// Kept deliberately small. Every rejection path in the daemon maps onto
/// exactly one of these, so an adversarial test can assert a specific code
/// rather than merely "not ok".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed request: unparseable, wrong version, missing field, or a
    /// field that violates a structural limit.
    BadRequest,
    /// Signature was well-formed and verified, but the verified identity is
    /// not permitted to perform this operation on this channel.
    Unauthorized,
    /// Signature verified against a key we hold, but that key is not bound to
    /// any identity in the config. Equivalently: a valid signature from an
    /// identity nobody registered.
    UnknownIdentity,
    /// Signature did not verify against the registered key for the claimed
    /// sender, or the embedded fingerprint disagreed with the registered key.
    BadSignature,
    /// A post whose per-identity sequence number was not strictly greater than
    /// the last one accepted for that identity.
    Replay,
    /// Signed timestamp outside the accepted skew window. Only reachable on
    /// read-only ops, which authenticate by time rather than by counter.
    ClockSkew,
    /// Channel named in the request has no `[channel.*]` entry in the config.
    UnknownChannel,
    /// The caller has used its post budget for the current window.
    ///
    /// Only emitted when the operator configured `[limits]`; the default is no
    /// limit, so this code is unreachable on a default install. It is a
    /// post-path code: reads are never charged, because a poll loop is the
    /// normal way an agent waits and throttling it would break the product
    /// without preventing anything.
    RateLimited,
    /// Daemon-side failure: storage, I/O, or an invariant violation.
    Internal,
    /// A `force_external` identity posted with `self` provenance.
    ///
    /// Every post from such an identity must be `external`, because the operator
    /// has declared that its content is fetched. The wrapper downgrades it
    /// before signing; the daemon rejects a forged self-signed envelope that
    /// bypasses the wrapper.
    ProvenanceRejected,
}

impl ErrorCode {
    /// Stable lowercase identifier used on the wire and in test assertions.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::UnknownIdentity => "unknown_identity",
            Self::BadSignature => "bad_signature",
            Self::Replay => "replay",
            Self::ClockSkew => "clock_skew",
            Self::UnknownChannel => "unknown_channel",
            Self::RateLimited => "rate_limited",
            Self::Internal => "internal",
            Self::ProvenanceRejected => "provenance_rejected",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error carrying a protocol code plus operator-facing detail.
///
/// `detail` is for humans reading daemon logs or a CLI stderr. It must never be
/// the only thing a test asserts on, because it is not a stable contract.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{code}: {detail}")]
pub struct CoreError {
    pub code: ErrorCode,
    pub detail: String,
    /// Milliseconds until a rate-limited caller may retry, when known.
    ///
    /// Diagnostic metadata only; callers must still branch on `code`.
    pub retry_after_ms: Option<u64>,
}

impl CoreError {
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into(), retry_after_ms: None }
    }

    /// Attach a machine-readable retry hint.
    pub fn with_retry_after(mut self, retry_after_ms: Option<u64>) -> Self {
        self.retry_after_ms = retry_after_ms;
        self
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::BadRequest, detail)
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(ErrorCode::Internal, detail)
    }
}

/// Result alias for core operations.
pub type Result<T> = std::result::Result<T, CoreError>;

impl From<serde_json::Error> for CoreError {
    /// Serialisation failure is always a bug in a type's `Serialize` impl rather
    /// than bad input, so it is reported as `Internal` and keeps the underlying
    /// message.
    fn from(e: serde_json::Error) -> Self {
        Self::internal(format!("json encoding failed: {e}"))
    }
}
