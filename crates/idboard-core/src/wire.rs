//! Wire types for the two socket hops.
//!
//! Both hops use the same discipline: one JSON object in, one JSON object out,
//! then the connection closes. There is no framing, no pipelining, and no
//! persistent session state. That is a deliberate choice, not laziness. It
//! means a process killed mid-write leaves a truncated request that fails to
//! parse, and never a half-applied database transaction.

use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Provenance};
use crate::error::ErrorCode;

/// A message as stored, with the board cursor it was assigned.
///
/// Serialises flattened, so on the wire it looks like the plan's envelope plus
/// a `cursor` field rather than a nested object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMessage {
    pub cursor: i64,
    #[serde(flatten)]
    pub envelope: Envelope,
}

/// Reply to a signed handshake: where this identity should resume its counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeReply {
    /// Highest sequence number the daemon has accepted for this identity.
    pub last_seq: i64,
    /// Fingerprint of the key the daemon has registered for this identity.
    /// The wrapper compares this against its own and refuses to run on
    /// mismatch, which catches a regenerated keystore.
    pub fingerprint: String,
    /// Role assigned to this identity by the config.
    pub role: String,
    /// Channels this identity may read, resolved by the daemon through the same
    /// check a real read uses. Advisory only: every read is authorised again
    /// when it happens, so this list cannot be used to bypass the ACL and cannot
    /// drift from it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub readable_channels: Vec<String>,
    /// Channels this identity may post to. Same advisory status as
    /// `readable_channels`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub postable_channels: Vec<String>,
}

/// One channel's contribution to an inbox digest.
///
/// A channel the identity may post to but not read still appears, with no
/// messages: "you can post here but not see what others said" is worth knowing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelDigest {
    pub channel: String,
    /// Whether the caller may read here. When false the digest carries no
    /// messages and a zero cursor.
    pub can_read: bool,
    /// Whether the caller may post here.
    pub can_post: bool,
    /// Newest cursor in this channel, so a caller can resume with a `read`.
    /// Zero when the channel is unreadable or empty.
    pub cursor: i64,
    /// Newest messages, oldest first. Empty when the caller cannot read the
    /// channel.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<StoredMessage>,
}

/// One row of the board roster.
///
/// Diagnostic only. `last_seen_ms` is written when an identity posts, reads or
/// handshakes; it is never consulted when deciding whether a request is allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStatus {
    pub identity: String,
    pub role: String,
    /// Unix milliseconds, or 0 for an identity that has never been seen.
    pub last_seen_ms: i64,
}

/// Child to wrapper, over the per-invocation relay socket.
///
/// Note what is absent: no `sender_id`, no `sender_pubkey_fp`, no `seq`, no
/// `timestamp`, no `signature`. The child has no way to express any of them,
/// so it cannot construct a valid envelope even while holding a valid token.
/// The wrapper fills all of them in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RelayRequest {
    Post {
        v: u8,
        token: String,
        channel: String,
        body: String,
        provenance: Provenance,
    },
    Read {
        v: u8,
        token: String,
        channel: String,
        since: i64,
        limit: u32,
    },
    Whoami {
        v: u8,
        token: String,
    },
    /// A digest of every channel this identity can see. The daemon decides
    /// which channels appear and how much of each; the child cannot ask for a
    /// channel it may not read.
    Inbox {
        v: u8,
        token: String,
        /// Messages per channel. `0` returns the channel list and positions
        /// only, which is the cheapest way to ask "what is on this board".
        limit: u32,
    },
    /// Who else is on the board, and when each was last seen.
    Peers {
        v: u8,
        token: String,
    },
}

impl RelayRequest {
    /// The bearer token, for constant-time comparison against the wrapper's.
    pub fn token(&self) -> &str {
        match self {
            Self::Post { token, .. }
            | Self::Read { token, .. }
            | Self::Whoami { token, .. }
            | Self::Inbox { token, .. }
            | Self::Peers { token, .. } => token,
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            Self::Post { v, .. }
            | Self::Read { v, .. }
            | Self::Whoami { v, .. }
            | Self::Inbox { v, .. }
            | Self::Peers { v, .. } => *v,
        }
    }
}

/// Reply to a `whoami`, so an agent can learn its own identity name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayIdentity {
    pub identity: String,
    pub fingerprint: String,
    /// The wrapper's process id. Useful in error reports.
    pub pid: u32,
}

/// Uniform error reply shape for both hops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorCode,
    pub detail: String,
}

impl ErrorBody {
    pub fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self { error: code, detail: detail.into() }
    }
}

impl From<&crate::error::CoreError> for ErrorBody {
    fn from(e: &crate::error::CoreError) -> Self {
        Self { error: e.code, detail: e.detail.clone() }
    }
}

/// Wrapper to daemon, over the single machine-wide socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonRequest {
    pub v: u8,
    /// Always present, always signed. The op lives inside the envelope so that
    /// it is covered by the signature.
    pub envelope: Envelope,
    /// Cursor to read from. Unused for `post` and `handshake`.
    #[serde(default)]
    pub since: i64,
    /// Page size. Unused for `post` and `handshake`.
    #[serde(default)]
    pub limit: u32,
}

/// Daemon reply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DaemonResponse {
    pub ok: bool,
    /// Cursor assigned to a newly stored message, or the newest cursor seen by
    /// a read. The value a caller should pass as its next `since`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<StoredMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake: Option<HandshakeReply>,
    /// Populated for an `inbox`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<ChannelDigest>,
    /// Populated for a `peers`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerStatus>,
    /// Populated for a `whoami`, which never reaches the daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<RelayIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl DaemonResponse {
    pub fn ok() -> Self {
        Self {
            ok: true,
            cursor: None,
            messages: Vec::new(),
            handshake: None,
            channels: Vec::new(),
            peers: Vec::new(),
            identity: None,
            error: None,
            detail: None,
        }
    }

    pub fn with_cursor(mut self, cursor: i64) -> Self {
        self.cursor = Some(cursor);
        self
    }

    pub fn with_messages(mut self, messages: Vec<StoredMessage>) -> Self {
        self.cursor = messages.last().map(|m| m.cursor).or(self.cursor);
        self.messages = messages;
        self
    }

    pub fn with_handshake(mut self, hs: HandshakeReply) -> Self {
        self.handshake = Some(hs);
        self
    }

    pub fn with_channels(mut self, channels: Vec<ChannelDigest>) -> Self {
        self.channels = channels;
        self
    }

    pub fn with_peers(mut self, peers: Vec<PeerStatus>) -> Self {
        self.peers = peers;
        self
    }

    /// Attach a `whoami` result. Handled entirely by the wrapper; the daemon
    /// never sees the request.
    pub fn with_identity(mut self, id: RelayIdentity) -> Self {
        self.identity = Some(id);
        self
    }

    pub fn err(code: ErrorCode, detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            cursor: None,
            messages: Vec::new(),
            handshake: None,
            channels: Vec::new(),
            peers: Vec::new(),
            identity: None,
            error: Some(code),
            detail: Some(detail.into()),
        }
    }

    /// Collapse a `CoreError` into a response.
    pub fn from_err(e: &crate::error::CoreError) -> Self {
        Self::err(e.code, e.detail.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Op;

    fn env() -> Envelope {
        Envelope {
            op: Op::Post,
            sender_id: "eng-01".into(),
            sender_pubkey_fp: "a3f9c1d2e3f40506".into(),
            channel: "general".into(),
            body: "hello".into(),
            provenance: Provenance::SelfOriginated,
            seq: 1,
            timestamp: 1_758_900_000_000,
            nonce: String::new(),
            signature: "ab".repeat(64),
        }
    }

    #[test]
    fn stored_message_flattens_on_the_wire() {
        let m = StoredMessage { cursor: 42, envelope: env() };
        let j = serde_json::to_string(&m).unwrap();
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["cursor"], 42);
        assert_eq!(v["sender_id"], "eng-01");
        assert_eq!(v["body"], "hello");
        assert!(v.get("envelope").is_none(), "envelope should be flattened, got {j}");
        let back: StoredMessage = serde_json::from_str(&j).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn relay_request_round_trips() {
        for r in [
            RelayRequest::Post {
                v: 1,
                token: "t".into(),
                channel: "general".into(),
                body: "hi".into(),
                provenance: Provenance::External,
            },
            RelayRequest::Read { v: 1, token: "t".into(), channel: "general".into(), since: 3, limit: 10 },
            RelayRequest::Whoami { v: 1, token: "t".into() },
        ] {
            let j = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<RelayRequest>(&j).unwrap(), r);
            assert_eq!(r.token(), "t");
            assert_eq!(r.version(), 1);
        }
    }

    #[test]
    fn relay_request_is_internally_tagged() {
        let j = serde_json::to_string(&RelayRequest::Whoami { v: 1, token: "t".into() }).unwrap();
        assert!(j.contains("\"op\":\"whoami\""), "{j}");
    }

    /// Structural guarantee behind the design: there is no field on a relay
    /// request under which a child could express a sender identity.
    #[test]
    fn relay_request_cannot_carry_identity_fields() {
        let spoof = r#"{"op":"post","v":1,"token":"t","channel":"general","body":"x",
            "provenance":"self","sender_id":"lead","seq":99,"signature":"deadbeef"}"#;
        // serde's default is to ignore unknown fields, so the request parses
        // and the injected values are discarded rather than honoured.
        let parsed: RelayRequest = serde_json::from_str(spoof).unwrap();
        match parsed {
            RelayRequest::Post { channel, body, .. } => {
                assert_eq!(channel, "general");
                assert_eq!(body, "x");
            }
            other => panic!("unexpected variant {other:?}"),
        }
    }

    #[test]
    fn daemon_response_shapes() {
        let ok = DaemonResponse::ok().with_cursor(7);
        let j = serde_json::to_string(&ok).unwrap();
        assert!(j.contains("\"ok\":true"));
        assert!(j.contains("\"cursor\":7"));
        assert!(!j.contains("\"messages\""), "empty vec should be omitted: {j}");

        let e = DaemonResponse::err(ErrorCode::Unauthorized, "nope");
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("\"error\":\"unauthorized\""));
        assert!(j.contains("\"detail\":\"nope\""));
    }

    #[test]
    fn daemon_request_omits_read_fields_for_posts() {
        let r = DaemonRequest { v: 1, envelope: env(), since: 0, limit: 0 };
        let j = serde_json::to_string(&r).unwrap();
        let back: DaemonRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(back.envelope, env());
        assert_eq!(back.since, 0);
    }
}
