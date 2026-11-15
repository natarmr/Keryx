//! The relay: the wrapper's per-invocation socket, and the signing it performs.
//!
//! # The child cannot forge, by construction
//!
//! A [`RelayRequest`] has no field for a sender, a fingerprint, a timestamp, a
//! sequence number, or a signature. There is nowhere for a child to put them, so
//! a child holding a valid token still cannot produce a valid envelope. The
//! wrapper fills all five in.
//!
//! This is the structural half of the design. The other half is that the
//! wrapper's *key* is not in the child's reach, so there is no interface at all
//! for signing something else.
//!
//! # Why a bearer token
//!
//! A local socket name is not a secret. On Unix any process can `stat` the path;
//! on Windows any process can enumerate `\\.\pipe\*`. So the socket name only
//! provides namespacing and collision avoidance — two concurrent wrappers cannot
//! clash, and the pipe namespace does not fill with guessable names.
//!
//! Authentication is the token: 32 random bytes handed to the child through the
//! environment and to nobody else. A process that finds the socket without the
//! token can connect and will be refused. The residual is that a same-user
//! process could read the token out of the child's environment, but a same-user
//! process can also read `~/.idboard/keys/`, so the token raises the bar without
//! defining a new boundary. See the README's trust section.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use idboard_core::error::{CoreError, ErrorCode, Result};
use idboard_core::ids::clamp_read_limit;
use idboard_core::keys::{LocalSigner, SeqCounter};
use idboard_core::wire::{DaemonRequest, DaemonResponse, RelayIdentity, RelayRequest};
use idboard_core::{PROTOCOL_VERSION, now_ms, validate_body, validate_channel};

/// Length of the relay bearer token, in bytes, before hex encoding.
pub const TOKEN_BYTES: usize = 32;

/// Compare two byte strings without an early exit on the first difference.
///
/// The length check still short-circuits, which leaks only the length, and the
/// token is a fixed 64 hex characters, so that is not a concern.
///
/// `pub` rather than `pub(crate)` because `cli.rs` is compiled into both the
/// library and the `keryx` binary, and the binary reaches the library through
/// `idboard::relay`. Two implementations of this would be one too many.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Generate a fresh relay token as lowercase hex.
pub fn generate_token() -> Result<String> {
    let mut buf = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut buf)
        .map_err(|e| CoreError::internal(format!("system CSPRNG unavailable: {e}")))?;
    Ok(hex::encode(buf))
}

/// The wrapper's signing side of a child connection.
pub struct Relay {
    identity: String,
    token: String,
    signer: LocalSigner,
    /// Guards the post counter only. Held briefly to allocate a sequence number,
    /// never across the daemon round trip, so a slow daemon cannot serialise
    /// unrelated posts.
    seq: Mutex<SeqCounter>,
    daemon_socket: PathBuf,
    /// How many messages this relay has signed. For diagnostics.
    signed: Mutex<u64>,
}

impl Relay {
    pub fn new(
        identity: &str,
        token: String,
        signer: LocalSigner,
        start_seq: i64,
        daemon_socket: PathBuf,
    ) -> Self {
        Self {
            identity: identity.to_string(),
            token,
            signer,
            seq: Mutex::new(SeqCounter::after(start_seq)),
            daemon_socket,
            signed: Mutex::new(0),
        }
    }

    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// Handle one request from the child.
    pub fn handle(&self, req: &RelayRequest) -> DaemonResponse {
        match self.dispatch(req) {
            Ok(r) => r,
            Err(e) => DaemonResponse::from_err(&e),
        }
    }

    fn dispatch(&self, req: &RelayRequest) -> Result<DaemonResponse> {
        if req.version() != PROTOCOL_VERSION {
            return Err(CoreError::bad_request(format!(
                "protocol version {} is not supported; this wrapper speaks {PROTOCOL_VERSION}",
                req.version()
            )));
        }
        if !constant_time_eq(req.token().as_bytes(), self.token.as_bytes()) {
            return Err(CoreError::new(
                ErrorCode::Unauthorized,
                "relay token is missing or wrong. This socket belongs to a specific \
                 `keryx run` invocation, and the token is only in that process's \
                 environment.",
            ));
        }

        match req {
            RelayRequest::Post { channel, body, provenance, .. } => self.post(channel, body, *provenance),
            RelayRequest::Read { channel, since, limit, .. } => self.read(channel, *since, *limit),
            RelayRequest::Whoami { .. } => Ok(DaemonResponse::ok().with_identity(RelayIdentity {
                identity: self.identity.clone(),
                fingerprint: self.signer.fingerprint().to_string(),
                pid: std::process::id(),
            })),
            RelayRequest::Inbox { limit, .. } => self.inbox(*limit),
            RelayRequest::Peers { .. } => self.peers(),
        }
    }

    /// Sign a post and forward it.
    ///
    /// Note the order: the sequence number is allocated *before* signing, under
    /// the lock, so two concurrent posts cannot be handed the same number.
    fn post(&self, channel: &str, body: &str, provenance: idboard_core::Provenance) -> Result<DaemonResponse> {
        validate_channel(channel)?;
        validate_body(body)?;

        let seq = self
            .seq
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()?;

        let envelope = self.signer.sign_post(channel, body, provenance, seq, now_ms())?;
        *self.signed.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.forward(envelope, 0, 0)
    }

    /// Sign a read and forward it. Reads never take a sequence number.
    fn read(&self, channel: &str, since: i64, limit: u32) -> Result<DaemonResponse> {
        validate_channel(channel)?;
        let envelope = self.signer.sign_read(channel, now_ms())?;
        self.forward(envelope, since.max(0), limit)
    }

    /// Sign an inbox query and forward it. The daemon decides which channels
    /// appear; the child cannot name one.
    fn inbox(&self, limit: u32) -> Result<DaemonResponse> {
        let envelope = self.signer.sign_inbox(now_ms())?;
        self.forward(envelope, 0, limit)
    }

    /// Sign a peers query and forward it. Read-only, like a handshake, so it
    /// consumes no sequence number.
    fn peers(&self) -> Result<DaemonResponse> {
        let envelope = self.signer.sign_peers(now_ms())?;
        self.forward(envelope, 0, 0)
    }

    fn forward(&self, envelope: idboard_core::Envelope, since: i64, limit: u32) -> Result<DaemonResponse> {
        let req = DaemonRequest { v: PROTOCOL_VERSION, envelope, since, limit };
        match idboard_ipc::round_trip(&self.daemon_socket, &req) {
            Ok(res) => Ok(res),
            Err(e) => Err(CoreError::new(
                ErrorCode::Internal,
                format!(
                    "cannot reach the keryx daemon at {}: {e}. Is `keryxd` running?",
                    self.daemon_socket.display()
                ),
            )),
        }
    }

    /// Messages signed so far, for the shutdown log line.
    pub fn signed_count(&self) -> u64 {
        *self.signed.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The highest sequence number handed out so far.
    pub fn next_seq(&self) -> Option<i64> {
        self.seq.lock().unwrap_or_else(|e| e.into_inner()).peek()
    }
}

/// Clamp a caller-supplied read limit, re-exported for the CLI.
pub fn read_limit(limit: u32) -> usize {
    clamp_read_limit(limit)
}

/// Path to a relay socket for an invocation, derived from a random suffix.
pub fn relay_path(identity: &str, suffix: &str) -> PathBuf {
    idboard_core::layout::relay_socket_name(identity, suffix)
}

/// Generate the random component of a relay socket name.
pub fn random_suffix() -> Result<String> {
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf)
        .map_err(|e| CoreError::internal(format!("system CSPRNG unavailable: {e}")))?;
    Ok(hex::encode(buf))
}

/// Remove a relay socket left on disk by a crashed wrapper. No-op on Windows.
pub fn cleanup(path: &Path) {
    idboard_ipc::cleanup_socket_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use idboard_core::Provenance;

    /// A relay plus the token it will accept, so tests do not have to build a
    /// second relay just to learn the first one's token.
    fn relay(start_seq: i64) -> (Relay, String) {
        let signer = LocalSigner::generate("eng-01").unwrap().0;
        let token = generate_token().unwrap();
        let r = Relay::new("eng-01", token.clone(), signer, start_seq, PathBuf::from("unused"));
        (r, token)
    }

    fn post_req(token: &str, channel: &str, body: &str) -> RelayRequest {
        RelayRequest::Post {
            v: PROTOCOL_VERSION,
            token: token.into(),
            channel: channel.into(),
            body: body.into(),
            provenance: Provenance::SelfOriginated,
        }
    }

    #[test]
    fn tokens_are_long_and_unique() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert_eq!(a.len(), TOKEN_BYTES * 2);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn a_missing_token_is_refused() {
        let (r, _token) = relay(0);
        let res = r.handle(&post_req("wrong", "general", "hi"));
        assert!(!res.ok);
        assert_eq!(res.error, Some(ErrorCode::Unauthorized));
    }

    #[test]
    fn a_prefix_of_the_token_is_refused() {
        let (r, token) = relay(0);
        let truncated = &token[..token.len() - 1];
        assert!(!r.handle(&post_req(truncated, "general", "hi")).ok);
        let extended = format!("{token}0");
        assert!(!r.handle(&post_req(&extended, "general", "hi")).ok);
    }

    /// The daemon is unreachable in these unit tests, so a token-accepted post
    /// fails at the forward step. That is enough to prove authorisation passed.
    #[test]
    fn a_valid_token_passes_authorisation_and_reaches_the_forward_step() {
        let (r, token) = relay(0);
        let res = r.handle(&post_req(&token, "general", "hi"));
        assert_eq!(
            res.error,
            Some(ErrorCode::Internal),
            "authorisation should pass and the forward should fail: {res:?}"
        );
        assert!(res.detail.unwrap().contains("keryxd"), "should name the daemon");
    }

    #[test]
    fn whoami_needs_no_token_round_trip_to_the_daemon() {
        let (r, token) = relay(0);
        let res = r.handle(&RelayRequest::Whoami { v: PROTOCOL_VERSION, token });
        assert!(res.ok, "{res:?}");
        let id = res.identity.unwrap();
        assert_eq!(id.identity, "eng-01");
        assert_eq!(id.pid, std::process::id());
    }

    #[test]
    fn whoami_still_requires_the_token() {
        let (r, _token) = relay(0);
        let res = r.handle(&RelayRequest::Whoami { v: PROTOCOL_VERSION, token: "nope".into() });
        assert!(!res.ok);
        assert!(res.identity.is_none(), "identity must not leak without a token");
    }

    #[test]
    fn a_version_mismatch_is_caught_before_the_token_check() {
        let (r, _token) = relay(0);
        let req = RelayRequest::Post {
            v: PROTOCOL_VERSION + 3,
            token: "whatever".into(),
            channel: "general".into(),
            body: "x".into(),
            provenance: Provenance::SelfOriginated,
        };
        let res = r.handle(&req);
        assert_eq!(res.error, Some(ErrorCode::BadRequest), "{res:?}");
    }

    #[test]
    fn channel_and_body_validation_happen_before_signing() {
        let (r, token) = relay(0);
        assert_eq!(r.handle(&post_req(&token, "", "hi")).error, Some(ErrorCode::BadRequest));
        assert_eq!(r.handle(&post_req(&token, "bad channel", "hi")).error, Some(ErrorCode::BadRequest));
        let huge = "x".repeat(idboard_core::MAX_BODY_LEN + 1);
        assert_eq!(r.handle(&post_req(&token, "general", &huge)).error, Some(ErrorCode::BadRequest));
    }

    #[test]
    fn relay_socket_names_are_namespaced_by_identity_and_suffix() {
        let a = relay_path("eng-01", "aaaabbbbccccdddd");
        let b = relay_path("eng-02", "aaaabbbbccccdddd");
        assert_ne!(a, b);
        assert!(a.to_string_lossy().contains("eng-01"));
        assert_ne!(relay_path("eng-01", "1111"), relay_path("eng-01", "2222"));
    }

    #[test]
    fn random_suffixes_differ() {
        assert_ne!(random_suffix().unwrap(), random_suffix().unwrap());
        assert_eq!(random_suffix().unwrap().len(), 16);
    }

    #[test]
    fn constant_time_eq_behaves_like_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn read_limits_are_clamped() {
        assert_eq!(read_limit(0), 1);
        assert_eq!(read_limit(50), 50);
        assert_eq!(read_limit(u32::MAX), idboard_core::MAX_READ_LIMIT);
    }
}
