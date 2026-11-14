//! Core types for idboard: the signed envelope, its canonical byte encoding,
//! and the ed25519 identity primitives.
//!
//! This crate has no I/O beyond reading the system CSPRNG. It is where the
//! security properties live, so it is kept free of sockets, storage, and
//! configuration to stay straightforward to audit and to test exhaustively.
//!
//! # The two authentication mechanisms
//!
//! keryx uses two different mechanisms, on purpose, because the ops have two
//! different guarantees to make.
//!
//! **Posts** mutate the board, so they are authenticated by a per-identity
//! monotonic sequence number. The daemon stores the highest number it has
//! accepted for each identity and rejects anything not strictly greater. A
//! captured post therefore cannot be resubmitted. Gaps are tolerated, because
//! a send that fails in flight is normal and must not permanently lock an
//! identity out.
//!
//! **Reads and handshakes** are read-only, so they are authenticated by a
//! signed timestamp inside a skew window, plus a nonce for hygiene. Replaying
//! one returns data the caller was already authorised to read, so a counter
//! would buy nothing — while charging reads to the same counter would make a
//! `subscribe` loop burn sequence numbers at its poll rate.
//!
//! The separation is enforced structurally by
//! [`Envelope::check_op_invariants`], not by convention: a post must carry a
//! sequence number and no nonce, a read must carry a nonce and no sequence
//! number.
//!
//! # Trust boundary
//!
//! Verification happens in exactly one place, [`keys::verify_with_key`], and
//! the daemon must call it with the key its config registers for the claimed
//! identity. A caller can put any string it likes in `sender_id`; that string is
//! only ever a *claim*, and it is authenticated by possession of the
//! corresponding private key. See the README for what this does and does not
//! defend against.

pub mod envelope;
pub mod error;
pub mod ids;
pub mod keys;
pub mod layout;
pub mod wire;

pub use envelope::{CANONICAL_DOMAIN, Envelope, Op, PROTOCOL_VERSION, Provenance, SignedFields};
pub use error::{CoreError, ErrorCode, Result};
pub use ids::{
    DEFAULT_READ_LIMIT, MAX_BODY_LEN, MAX_CHANNEL_LEN, MAX_IDENTITY_LEN, MAX_READ_LIMIT, NONCE_BYTES,
    READ_SKEW_MS, SINCE_CURRENT_END, validate_body, validate_channel, validate_identity,
};
pub use keys::{
    FINGERPRINT_BYTES, LocalSigner, SeqCounter, VerifiedSender, fingerprint_of, generate_nonce,
    pubkey_from_hex, verify_with_key, verify_with_pubkey_hex,
};
pub use layout::{
    ENV_CONFIG, ENV_DAEMON, ENV_HOME, ENV_RELAY, ENV_TOKEN, daemon_socket, idboard_home, key_path,
    keys_dir, lock_path, now_ms, run_dir,
};
pub use wire::{DaemonRequest, DaemonResponse, ErrorBody, HandshakeReply, RelayRequest, RelayIdentity, StoredMessage};
