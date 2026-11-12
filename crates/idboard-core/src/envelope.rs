//! The signed message envelope and its canonical byte encoding.
//!
//! # Why canonical bytes and not "sign the JSON"
//!
//! The obvious implementation is to serialise the envelope and sign those
//! bytes. That is fragile in two ways: field order in a `serde_json::Value` map
//! is not guaranteed stable across versions, and re-serialising on the verify
//! side can produce different bytes than the signer emitted (escaping, unicode
//! normalisation, float formatting). Either difference looks exactly like
//! tampering, which is a miserable failure mode to debug.
//!
//! So we define an explicit, length-prefixed encoding. Every variable-length
//! field carries its own length, which means no two distinct field tuples can
//! produce the same byte string. `no_field_boundary_ambiguity` tests that
//! property directly.

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::ids::{validate_body, validate_channel, validate_identity};

/// Domain separator. Bumping this invalidates every signature in existence,
/// which is the intended way to make a breaking change to the format.
///
/// Ends in the protocol version, and the two are separate constants, so nothing
/// but [`the_domain_names_this_version`] keeps a bump of one from silently
/// stranding every existing signature under a domain that no longer says which
/// format it covers.
pub const CANONICAL_DOMAIN: &[u8; 11] = b"idboard/v1\0";

/// Protocol version carried on every request.
pub const PROTOCOL_VERSION: u8 = 1;

/// What the sender is asking the daemon to do.
///
/// The discriminant is inside the signed bytes, so a signed `Read` cannot be
/// relabelled as a `Post` without invalidating the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Deliver a message to a channel. Mutating; authenticated by counter.
    Post = 1,
    /// Fetch messages from a channel. Read-only; authenticated by timestamp.
    Read = 2,
    /// Ask the daemon what sequence number to resume from. Read-only.
    Handshake = 3,
    /// Ask for a digest of every channel this identity can see. Read-only, and
    /// not channel-scoped: the daemon decides which channels appear, using the
    /// same authorisation check a real read would.
    Inbox = 4,
    /// Ask who else is on the board and when each identity was last seen.
    /// Read-only. Presence is diagnostic only and never an authorisation input.
    Peers = 5,
}

impl Op {
    /// Whether this op consumes the per-identity monotonic counter.
    ///
    /// Exactly one op does. Read-only ops are authenticated by signed timestamp
    /// plus nonce instead, because a replayed read is harmless: it returns data
    /// the caller was already entitled to see. Charging them to the same
    /// counter would mean a `subscribe` loop burns sequence numbers at its poll
    /// rate, for no security benefit.
    pub const fn uses_counter(self) -> bool {
        matches!(self, Self::Post)
    }

    /// Stable lowercase name for logs and test assertions.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Post => "post",
            Self::Read => "read",
            Self::Handshake => "handshake",
            Self::Inbox => "inbox",
            Self::Peers => "peers",
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Post),
            2 => Some(Self::Read),
            3 => Some(Self::Handshake),
            4 => Some(Self::Inbox),
            5 => Some(Self::Peers),
            _ => None,
        }
    }
}

/// Sender's self-declaration about where the body text came from.
///
/// Carried as data in v1 and never enforced. It exists so a later trust layer
/// has something to consume, and so a reader can see the distinction today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Provenance {
    /// Originated from the sending agent's own reasoning.
    #[serde(rename = "self")]
    SelfOriginated,
    /// Passed through the agent from a fetched or externally supplied source.
    #[serde(rename = "external")]
    External,
    /// Not meaningful for this op (reads and handshakes carry no content).
    #[serde(rename = "n/a")]
    NotApplicable,
}

impl Provenance {
    const fn as_byte(self) -> u8 {
        match self {
            Self::SelfOriginated => 0,
            Self::External => 1,
            Self::NotApplicable => 2,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::SelfOriginated),
            1 => Some(Self::External),
            2 => Some(Self::NotApplicable),
            _ => None,
        }
    }
}

/// A complete request as it travels over a socket, signed.
///
/// The `signature` field is deliberately *not* part of the signed bytes; every
/// other field is. [`SignedFields`] makes that boundary structural rather than a
/// convention someone has to remember.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub op: Op,
    pub sender_id: String,
    /// Hex fingerprint of the sender's public key. Redundant with the registry
    /// lookup, but signed, so a mismatch is a detectable tampering signal
    /// rather than a silent substitution.
    #[serde(rename = "sender_pubkey_fp")]
    pub sender_pubkey_fp: String,
    pub channel: String,
    pub body: String,
    pub provenance: Provenance,
    /// Per-identity monotonic counter. Non-zero for `Post`, zero otherwise.
    pub seq: i64,
    /// Unix milliseconds. Supplied by the wrapper, never by the child.
    pub timestamp: i64,
    /// Hex nonce. Empty for `Post`, non-empty for read-only ops.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nonce: String,
    /// Hex ed25519 signature over [`Envelope::signing_bytes`].
    pub signature: String,
}

/// The exact set of fields a signature covers.
///
/// Kept as a separate borrow of the envelope so that no future field can be
/// added to `Envelope` without someone deciding whether it belongs here. The
/// compiler will not catch that; the review diff will.
#[derive(Debug, Clone, Copy)]
pub struct SignedFields<'a> {
    pub op: Op,
    pub sender_id: &'a str,
    pub sender_pubkey_fp: &'a str,
    pub channel: &'a str,
    pub body: &'a str,
    pub provenance: Provenance,
    pub seq: i64,
    pub timestamp: i64,
    pub nonce: &'a str,
}

fn put_u16(out: &mut Vec<u8>, s: &str) -> Result<()> {
    let b = s.as_bytes();
    let len = u16::try_from(b.len())
        .map_err(|_| CoreError::bad_request(format!("field of {} bytes exceeds u16 length prefix", b.len())))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn put_u32(out: &mut Vec<u8>, s: &str) -> Result<()> {
    let b = s.as_bytes();
    let len = u32::try_from(b.len())
        .map_err(|_| CoreError::bad_request(format!("field of {} bytes exceeds u32 length prefix", b.len())))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(b);
    Ok(())
}

impl<'a> SignedFields<'a> {
    /// Serialise to the canonical, unambiguous byte form.
    ///
    /// Layout, all integers little-endian:
    ///
    /// ```text
    /// "idboard/v1\0"      11 bytes, domain separator
    /// u8                  op
    /// i64                 seq
    /// u16 len + bytes     sender_id
    /// u32 len + bytes     sender_pubkey_fp
    /// u16 len + bytes     channel
    /// u32 len + bytes     body
    /// u8                  provenance
    /// i64                 timestamp_ms
    /// u32 len + bytes     nonce
    /// ```
    ///
    /// Every field is always present, whatever the op. Unused fields are empty
    /// or zero. A variable layout would be shorter but would make the encoder
    /// op-dependent, and an op-dependent encoder is exactly the kind of thing
    /// that eventually disagrees between signer and verifier.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        // Validate before encoding, not after. A length prefix that silently
        // truncated would reintroduce the very ambiguity this format exists to
        // remove.
        validate_identity(self.sender_id)?;
        validate_channel_noncempty(self.channel)?;
        validate_body(self.body)?;

        let mut out =
            Vec::with_capacity(64 + self.sender_id.len() + self.channel.len() + self.body.len());
        out.extend_from_slice(CANONICAL_DOMAIN);
        out.push(self.op as u8);
        out.extend_from_slice(&self.seq.to_le_bytes());
        put_u16(&mut out, self.sender_id)?;
        put_u32(&mut out, self.sender_pubkey_fp)?;
        put_u16(&mut out, self.channel)?;
        put_u32(&mut out, self.body)?;
        out.push(self.provenance.as_byte());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        put_u32(&mut out, self.nonce)?;
        Ok(out)
    }
}

/// `validate_channel` that permits the empty string.
///
/// `handshake` legitimately carries no channel. Every other field keeps its
/// normal validation.
fn validate_channel_noncempty(channel: &str) -> Result<()> {
    if channel.is_empty() {
        return Ok(());
    }
    validate_channel(channel)
}

impl Envelope {
    /// Borrow the fields covered by the signature.
    pub fn signed(&self) -> SignedFields<'_> {
        SignedFields {
            op: self.op,
            sender_id: &self.sender_id,
            sender_pubkey_fp: &self.sender_pubkey_fp,
            channel: &self.channel,
            body: &self.body,
            provenance: self.provenance,
            seq: self.seq,
            timestamp: self.timestamp,
            nonce: &self.nonce,
        }
    }

    /// Bytes the signature is computed over.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        self.signed().to_canonical_bytes()
    }

    /// Structural validation: limits, charset, and per-op field invariants.
    ///
    /// Runs on both the signing and the verifying side, so an envelope that
    /// could not have been legitimately produced is rejected rather than
    /// verified.
    pub fn validate(&self) -> Result<()> {
        validate_identity(&self.sender_id)?;
        validate_channel_noncempty(&self.channel)?;
        validate_body(&self.body)?;
        self.check_op_invariants()
    }

    /// Enforce the field shape each op requires.
    ///
    /// This is what makes one counter safe for the whole protocol: `post` must
    /// carry a sequence number and no nonce, read-only ops must carry a nonce
    /// and no sequence number. A caller cannot smuggle a read's timestamp
    /// authentication into the post path to skip the counter.
    pub fn check_op_invariants(&self) -> Result<()> {
        match self.op {
            Op::Post => {
                if self.seq <= 0 {
                    return Err(CoreError::bad_request(format!(
                        "post requires a positive seq, got {}",
                        self.seq
                    )));
                }
                if !self.nonce.is_empty() {
                    return Err(CoreError::bad_request("post must not carry a nonce"));
                }
                if self.provenance == Provenance::NotApplicable {
                    return Err(CoreError::bad_request("post requires provenance self or external"));
                }
                validate_channel(&self.channel)?;
                Ok(())
            }
            Op::Read => {
                if self.seq != 0 {
                    return Err(CoreError::bad_request(format!(
                        "read must not carry a seq, got {}",
                        self.seq
                    )));
                }
                if self.nonce.is_empty() {
                    return Err(CoreError::bad_request("read requires a nonce"));
                }
                if !self.body.is_empty() {
                    return Err(CoreError::bad_request("read must not carry a body"));
                }
                if self.provenance != Provenance::NotApplicable {
                    return Err(CoreError::bad_request("read provenance must be n/a"));
                }
                validate_channel(&self.channel)?;
                Ok(())
            }
            Op::Handshake | Op::Inbox | Op::Peers => {
                // All three are channel-less queries, authenticated the same way:
                // a signed timestamp plus a nonce, and no sequence number.
                let op = self.op.as_str();
                if self.seq != 0 {
                    return Err(CoreError::bad_request(format!(
                        "{op} must not carry a seq, got {}",
                        self.seq
                    )));
                }
                if self.nonce.is_empty() {
                    return Err(CoreError::bad_request(format!("{op} requires a nonce")));
                }
                if !self.body.is_empty() {
                    return Err(CoreError::bad_request(format!("{op} must not carry a body")));
                }
                if !self.channel.is_empty() {
                    return Err(CoreError::bad_request(format!(
                        "{op} must not carry a channel"
                    )));
                }
                if self.provenance != Provenance::NotApplicable {
                    return Err(CoreError::bad_request(format!("{op} provenance must be n/a")));
                }
                Ok(())
            }
        }
    }

    /// True when this op is authenticated by counter rather than by timestamp.
    pub const fn uses_counter(&self) -> bool {
        self.op.uses_counter()
    }
}

/// Encode an op discriminant back from a byte, used by canonical-byte tests.
#[doc(hidden)]
pub fn op_from_byte(b: u8) -> Option<Op> {
    Op::from_byte(b)
}

/// Encode a provenance discriminant back from a byte, used by canonical-byte tests.
#[doc(hidden)]
pub fn provenance_from_byte(b: u8) -> Option<Provenance> {
    Provenance::from_byte(b)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            signature: String::new(),
        }
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let e = env();
        assert_eq!(e.signing_bytes().unwrap(), e.signing_bytes().unwrap());
    }

    #[test]
    fn canonical_bytes_start_with_domain_separator() {
        let b = env().signing_bytes().unwrap();
        assert_eq!(&b[..CANONICAL_DOMAIN.len()], CANONICAL_DOMAIN);
    }

    /// The domain separator and the protocol version are two constants, and
    /// nothing else ties them together. Bump one without the other and every
    /// existing signature is stranded under a domain that no longer describes
    /// the format it covers — silently, because a mismatch is only ever visible
    /// as `bad_signature` on messages that used to verify.
    #[test]
    fn the_domain_separator_names_this_protocol_version() {
        let want = format!("idboard/v{PROTOCOL_VERSION}\0");
        assert_eq!(
            std::str::from_utf8(CANONICAL_DOMAIN).unwrap(),
            want,
            "CANONICAL_DOMAIN and PROTOCOL_VERSION disagree: bump both, or the domain is a lie"
        );
    }

    #[test]
    fn signature_is_not_covered() {
        let mut e = env();
        let before = e.signing_bytes().unwrap();
        e.signature = "deadbeef".repeat(16);
        assert_eq!(before, e.signing_bytes().unwrap());
    }

    #[test]
    fn every_signed_field_affects_the_bytes() {
        let base = env().signing_bytes().unwrap();
        let mutators: Vec<(&str, Box<dyn Fn(&mut Envelope)>)> = vec![
            ("op", Box::new(|e: &mut Envelope| e.op = Op::Read)),
            ("sender_id", Box::new(|e: &mut Envelope| e.sender_id = "eng-02".into())),
            ("fp", Box::new(|e: &mut Envelope| e.sender_pubkey_fp = "b".repeat(16))),
            ("channel", Box::new(|e: &mut Envelope| e.channel = "other".into())),
            ("body", Box::new(|e: &mut Envelope| e.body = "hellO".into())),
            ("provenance", Box::new(|e: &mut Envelope| e.provenance = Provenance::External)),
            ("seq", Box::new(|e: &mut Envelope| e.seq = 2)),
            ("timestamp", Box::new(|e: &mut Envelope| e.timestamp += 1)),
            ("nonce", Box::new(|e: &mut Envelope| e.nonce = "ab".into())),
        ];
        for (name, f) in mutators {
            let mut e = env();
            f(&mut e);
            assert_ne!(base, e.signing_bytes().unwrap(), "field {name} did not affect signing bytes");
        }
    }

    /// The property that motivates length prefixes.
    ///
    /// If adjacent fields lacked their length prefixes, these pairs would
    /// serialise identically and one message's signature would verify against
    /// the other's contents.
    #[test]
    fn no_field_boundary_ambiguity() {
        // ("engab", "c") vs ("enga", "bc"): adjacent u16-prefixed fields.
        let mut a = env();
        a.sender_id = "engab".into();
        a.channel = "c".into();
        a.body = String::new();
        let mut b = env();
        b.sender_id = "enga".into();
        b.channel = "bc".into();
        b.body = String::new();
        assert_ne!(a.signing_bytes().unwrap(), b.signing_bytes().unwrap(), "sender_id/channel boundary");

        // ("gen", "x") vs ("g", "enx"): a u16-prefixed field followed by a
        // u32-prefixed one, with a different prefix width between them.
        let mut a = env();
        a.channel = "gen".into();
        a.body = "x".into();
        let mut b = env();
        b.channel = "g".into();
        b.body = "enx".into();
        assert_ne!(a.signing_bytes().unwrap(), b.signing_bytes().unwrap(), "channel/body boundary");

        // Trailing field: a nonce that could otherwise be mistaken for the tail
        // of the body.
        let mut a = env();
        a.op = Op::Read;
        a.body = String::new();
        a.nonce = "abcd".into();
        let mut b = env();
        b.op = Op::Read;
        b.body = "abcd".into();
        b.nonce = String::new();
        assert_ne!(a.signing_bytes().unwrap(), b.signing_bytes().unwrap(), "body/nonce boundary");
    }

    /// Independent proof of unambiguity: parse the canonical bytes back with a
    /// decoder written against the documented layout and recover every field
    /// exactly.
    ///
    /// This is stronger than asserting two encodings differ, because a decoder
    /// that round-trips proves the layout is self-describing. If a prefix were
    /// ever dropped or a field reordered, this fails.
    #[test]
    fn canonical_bytes_round_trip_through_an_independent_decoder() {
        for e in [
            env(),
            Envelope { channel: String::new(), nonce: "00ff".into(), op: Op::Handshake, body: String::new(), ..env() },
            Envelope { body: "multi\nline\tbody with unicode: \u{00e9}\u{4e16}".into(), ..env() },
            Envelope { sender_pubkey_fp: "0".repeat(64), seq: i64::MAX, ..env() },
        ] {
            let bytes = e.signing_bytes().unwrap();

            let mut p = CANONICAL_DOMAIN.len();
            let op = Op::from_byte(bytes[p]).expect("known op byte");
            p += 1;
            let seq = i64::from_le_bytes(bytes[p..p + 8].try_into().unwrap());
            p += 8;
            let (sender_id, np) = take_u16_str(&bytes, p);
            p = np;
            let (fp, np) = take_u32_str(&bytes, p);
            p = np;
            let (channel, np) = take_u16_str(&bytes, p);
            p = np;
            let (body, np) = take_u32_str(&bytes, p);
            p = np;
            let provenance = Provenance::from_byte(bytes[p]).expect("known provenance byte");
            p += 1;
            let timestamp = i64::from_le_bytes(bytes[p..p + 8].try_into().unwrap());
            p += 8;
            let (nonce, np) = take_u32_str(&bytes, p);
            p = np;

            assert_eq!(p, bytes.len(), "decoder consumed {} of {} bytes", p, bytes.len());
            assert_eq!(op, e.op);
            assert_eq!(seq, e.seq);
            assert_eq!(sender_id, e.sender_id);
            assert_eq!(fp, e.sender_pubkey_fp);
            assert_eq!(channel, e.channel);
            assert_eq!(body, e.body);
            assert_eq!(provenance, e.provenance);
            assert_eq!(timestamp, e.timestamp);
            assert_eq!(nonce, e.nonce);
        }
    }

    fn take_u16_str(b: &[u8], at: usize) -> (String, usize) {
        let len = u16::from_le_bytes(b[at..at + 2].try_into().unwrap()) as usize;
        let s = String::from_utf8(b[at + 2..at + 2 + len].to_vec()).unwrap();
        (s, at + 2 + len)
    }

    fn take_u32_str(b: &[u8], at: usize) -> (String, usize) {
        let len = u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
        let s = String::from_utf8(b[at + 4..at + 4 + len].to_vec()).unwrap();
        (s, at + 4 + len)
    }

    #[test]
    fn post_invariants() {
        assert!(env().check_op_invariants().is_ok());

        let mut e = env();
        e.seq = 0;
        assert!(e.check_op_invariants().is_err(), "post with seq 0 must fail");

        let mut e = env();
        e.nonce = "abcd".into();
        assert!(e.check_op_invariants().is_err(), "post with nonce must fail");

        let mut e = env();
        e.provenance = Provenance::NotApplicable;
        assert!(e.check_op_invariants().is_err(), "post with n/a provenance must fail");

        let mut e = env();
        e.channel = String::new();
        assert!(e.check_op_invariants().is_err(), "post without channel must fail");
    }

    #[test]
    fn read_invariants() {
        let mut e = env();
        e.op = Op::Read;
        e.seq = 0;
        e.body = String::new();
        e.provenance = Provenance::NotApplicable;
        e.nonce = "00112233445566778899aabbccddeeff".into();
        assert!(e.check_op_invariants().is_ok());

        let mut bad = e.clone();
        bad.seq = 5;
        assert!(bad.check_op_invariants().is_err(), "read with a seq must fail");

        let mut bad = e.clone();
        bad.nonce = String::new();
        assert!(bad.check_op_invariants().is_err(), "read without nonce must fail");

        let mut bad = e.clone();
        bad.body = "x".into();
        assert!(bad.check_op_invariants().is_err(), "read with body must fail");
    }

    #[test]
    fn handshake_invariants() {
        let mut e = env();
        e.op = Op::Handshake;
        e.seq = 0;
        e.channel = String::new();
        e.body = String::new();
        e.provenance = Provenance::NotApplicable;
        e.nonce = "00112233445566778899aabbccddeeff".into();
        assert!(e.check_op_invariants().is_ok());

        let mut bad = e.clone();
        bad.channel = "general".into();
        assert!(bad.check_op_invariants().is_err(), "handshake with channel must fail");

        let mut bad = e.clone();
        bad.seq = 1;
        assert!(bad.check_op_invariants().is_err(), "handshake with seq must fail");
    }

    #[test]
    fn op_and_provenance_round_trip_through_bytes() {
        for op in [Op::Post, Op::Read, Op::Handshake, Op::Inbox, Op::Peers] {
            assert_eq!(op_from_byte(op as u8), Some(op));
        }
        assert_eq!(op_from_byte(0), None);
        assert_eq!(op_from_byte(6), None);
        for p in [Provenance::SelfOriginated, Provenance::External, Provenance::NotApplicable] {
            assert_eq!(provenance_from_byte(p.as_byte()), Some(p));
        }
        assert_eq!(provenance_from_byte(3), None);
    }

    #[test]
    fn only_post_uses_the_counter() {
        assert!(Op::Post.uses_counter());
        assert!(!Op::Read.uses_counter());
        assert!(!Op::Handshake.uses_counter());
        assert!(!Op::Inbox.uses_counter(), "inbox is a query; it must not burn a sequence number");
        assert!(!Op::Peers.uses_counter(), "peers is a query; it must not burn a sequence number");
    }

    /// The channel-less queries share one shape, so a digest request cannot
    /// smuggle a channel in and be answered as if it were a read.
    #[test]
    fn channel_less_queries_reject_a_channel_a_body_and_a_seq() {
        for op in [Op::Handshake, Op::Inbox, Op::Peers] {
            let mut e = env();
            e.op = op;
            e.seq = 0;
            e.channel = String::new();
            e.body = String::new();
            e.provenance = Provenance::NotApplicable;
            e.nonce = "00112233445566778899aabbccddeeff".into();
            assert!(e.check_op_invariants().is_ok(), "{op:?} should be well formed");

            let mut bad = e.clone();
            bad.channel = "general".into();
            assert!(bad.check_op_invariants().is_err(), "{op:?} with a channel must fail");

            let mut bad = e.clone();
            bad.seq = 1;
            assert!(bad.check_op_invariants().is_err(), "{op:?} with a seq must fail");

            let mut bad = e.clone();
            bad.body = "hi".into();
            assert!(bad.check_op_invariants().is_err(), "{op:?} with a body must fail");
        }
    }

    #[test]
    fn over_long_channel_is_rejected_not_truncated() {
        // A truncated length prefix would let two distinct channels collide.
        // The encoder must refuse instead.
        let mut e = env();
        e.channel = "c".repeat(crate::ids::MAX_CHANNEL_LEN + 1);
        assert!(e.signing_bytes().is_err());
    }

    #[test]
    fn wire_json_round_trip() {
        let e = env();
        let j = serde_json::to_string(&e).unwrap();
        let back: Envelope = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn wire_json_omits_empty_nonce() {
        let j = serde_json::to_string(&env()).unwrap();
        assert!(!j.contains("nonce"), "post envelope should not carry a nonce field: {j}");
    }
}
