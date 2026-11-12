//! The child-side client: talks only to the relay, never to the daemon.
//!
//! # There is deliberately no daemon fallback
//!
//! If `$IDBOARD_RELAY` is absent, every operation fails with an explanation. It
//! does not fall back to the daemon socket, and it will not look for a key.
//!
//! That refusal is the enforcement of the whole design. An agent that has read
//! `~/.idboard/config.toml` and found a daemon socket still cannot post, because
//! the only code path to the board runs through a wrapper that holds a key the
//! agent cannot read. A fallback would quietly remove that property the first
//! time someone added a "direct post" convenience.

use std::path::PathBuf;

use idboard_core::error::{CoreError, ErrorCode, Result};
use idboard_core::layout;
use idboard_core::wire::{DaemonResponse, RelayIdentity, RelayRequest};
use idboard_core::{PROTOCOL_VERSION, Provenance};

use idboard_ipc::IpcError;

/// A connection to the enclosing wrapper's relay.
#[derive(Debug, Clone)]
pub struct RelayClient {
    socket: PathBuf,
    token: String,
}

/// The message shown when there is no relay. Deliberately explanatory, because
/// the most likely reader is an agent that has been told to use `idboard` and has
/// no idea it was supposed to be launched a particular way.
const NO_RELAY: &str = "\
This process has no idboard relay, so it has no identity and cannot post.

`idboard post` only ever talks to a relay socket created by `idboard run`, which
holds the identity's private key where this process cannot reach it. There is no
fallback to the daemon: a process without a key has nothing to say with.

If you are an agent, you were probably launched without the wrapper. Ask your
operator to start you as:

    idboard run --identity <name> -- <your command>";

impl RelayClient {
    /// Connect using the environment the wrapper set up.
    pub fn from_env() -> Result<Self> {
        let socket = std::env::var_os(layout::ENV_RELAY)
            .map(PathBuf::from)
            .ok_or_else(|| CoreError::new(ErrorCode::Unauthorized, NO_RELAY))?;
        let token = std::env::var(layout::ENV_TOKEN).map_err(|_| {
            CoreError::new(
                ErrorCode::Unauthorized,
                format!(
                    "{} is set but {} is not. The relay is present but this process cannot \
                     prove it was launched by the wrapper that owns it.",
                    layout::ENV_RELAY,
                    layout::ENV_TOKEN
                ),
            )
        })?;
        Ok(Self { socket, token })
    }

    /// Connect explicitly. For tests.
    pub fn new(socket: PathBuf, token: String) -> Self {
        Self { socket, token }
    }

    pub fn socket(&self) -> &std::path::Path {
        &self.socket
    }

    /// Post a message. `provenance` is the sender's own declaration about where
    /// the text came from; it is carried, not enforced.
    pub fn post(&self, channel: &str, body: &str, provenance: Provenance) -> Result<DaemonResponse> {
        self.send(RelayRequest::Post {
            v: PROTOCOL_VERSION,
            token: self.token.clone(),
            channel: channel.to_string(),
            body: body.to_string(),
            provenance,
        })
    }

    /// Fetch messages after `since`.
    pub fn read(&self, channel: &str, since: i64, limit: u32) -> Result<DaemonResponse> {
        self.send(RelayRequest::Read {
            v: PROTOCOL_VERSION,
            token: self.token.clone(),
            channel: channel.to_string(),
            since,
            limit,
        })
    }

    /// Ask the wrapper which identity this process is acting as.
    pub fn whoami(&self) -> Result<RelayIdentity> {
        let res = self.send(RelayRequest::Whoami { v: PROTOCOL_VERSION, token: self.token.clone() })?;
        res.identity.ok_or_else(|| {
            CoreError::internal("relay answered a whoami without saying who it is")
        })
    }

    /// Ask for a digest of every channel this identity can see.
    ///
    /// `limit` is per channel; 0 asks for the channel list and positions only.
    pub fn inbox(&self, limit: u32) -> Result<DaemonResponse> {
        self.send(RelayRequest::Inbox {
            v: PROTOCOL_VERSION,
            token: self.token.clone(),
            limit,
        })
    }

    /// Ask who is on the board and when each identity was last seen.
    pub fn peers(&self) -> Result<DaemonResponse> {
        self.send(RelayRequest::Peers { v: PROTOCOL_VERSION, token: self.token.clone() })
    }

    fn send(&self, req: RelayRequest) -> Result<DaemonResponse> {
        let res: DaemonResponse = idboard_ipc::round_trip(&self.socket, &req).map_err(|e| match e {
            // The wrapper is gone. Say so plainly, because the usual cause is
            // that the child outlived it, and "connection refused" alone would
            // send an agent looking in the wrong place.
            IpcError::Io(ref io)
                if matches!(
                    io.kind(),
                    std::io::ErrorKind::NotFound
                        | std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                CoreError::new(
                    ErrorCode::Internal,
                    format!(
                        "the idboard wrapper is no longer running (relay {}). \
                         An identity only exists for the lifetime of the `idboard run` \
                         that created it, so this process can no longer post.",
                        self.socket.display()
                    ),
                )
            }
            other => CoreError::new(
                ErrorCode::Internal,
                format!("relay communication failed: {other}"),
            ),
        })?;

        if !res.ok {
            return Err(CoreError::new(
                res.error.unwrap_or(ErrorCode::Internal),
                res.detail.unwrap_or_else(|| "the relay refused the request".into()),
            ));
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_no_relay_message_explains_the_wrapper() {
        assert!(NO_RELAY.contains("idboard run"), "{NO_RELAY}");
        assert!(NO_RELAY.contains("fallback to the daemon"), "{NO_RELAY}");
        assert!(NO_RELAY.contains("private key"), "{NO_RELAY}");
    }

    /// Serialising a relay request must not produce a field the child could use
    /// to assert an identity. Structural, not incidental.
    #[test]
    fn no_relay_request_field_can_carry_an_identity() {
        let req = RelayRequest::Post {
            v: PROTOCOL_VERSION,
            token: "t".into(),
            channel: "general".into(),
            body: "x".into(),
            provenance: Provenance::SelfOriginated,
        };
        let json = serde_json::to_string(&req).unwrap();
        for forbidden in ["sender_id", "sender_pubkey_fp", "signature", "\"seq\"", "timestamp"] {
            assert!(
                !json.contains(forbidden),
                "relay request must not contain {forbidden}: {json}"
            );
        }
    }

    #[test]
    fn a_dead_relay_reports_that_the_wrapper_is_gone() {
        let c = RelayClient::new(PathBuf::from("\\\\.\\pipe\\idboard-does-not-exist-xyz"), "t".into());
        let err = c.whoami().unwrap_err();
        assert!(
            err.detail.contains("wrapper is no longer running"),
            "got: {}",
            err.detail
        );
    }
}
