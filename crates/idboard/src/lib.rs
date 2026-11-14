//! The identity-signing wrapper and the agent-facing CLI.
//!
//! # The arrangement
//!
//! ```text
//!   idboard run --identity eng-01 -- claude
//!        |
//!        |-- loads the ed25519 key for eng-01 from the keystore
//!        |     (the child never sees this key, and has no interface to it)
//!        |
//!        |-- opens a per-invocation relay socket, token in the child's env
//!        |
//!        |-- spawns the child, which can only reach the board through the relay
//!        |
//!        `-- signs everything the child asks for, and forwards it to idboardd
//!
//!   idboard post general "hello"      (run *inside* the child)
//!        `-- connects to the relay, which signs it as eng-01
//! ```
//!
//! # Why the child cannot impersonate anyone
//!
//! Three independent reasons, which is the point. Any one of them would be
//! enough on its own:
//!
//! 1. **The child never holds key material.** The signing key lives in the
//!    wrapper. The child is told a socket name and a bearer token, neither of
//!    which is a key.
//! 2. **The child cannot construct an envelope.** A [`RelayRequest`] has no
//!    field for a sender, timestamp, sequence number, or signature. The wrapper
//!    fills all of them in.
//! 3. **The daemon verifies against a registered key.** The name in an envelope
//!    is a claim; it becomes an identity only by verifying against the public
//!    key the config associates with that name.
//!
//! The honest limit: the child runs as the same OS user, so it *can* read
//! `~/.idboard/keys/`. This defeats opportunistic exfiltration and an agent that
//! has been told where the key is. It does not defeat a determined same-user
//! process. Closing that needs one OS user per identity, which is deferred.

pub mod client;
pub mod cursor;
pub mod keystore;
pub mod lock;
pub mod mcp;
pub mod relay;
pub mod wrapper;

pub use client::RelayClient;
pub use keystore::Keystore;
pub use lock::IdentityLock;
pub use relay::Relay;
pub use wrapper::{run_child, WrapperError, WrapperOptions};
