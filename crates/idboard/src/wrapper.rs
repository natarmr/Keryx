//! `idboard run`: the wrapper that makes an identity real.
//!
//! Owns the private key, signs everything the child asks for, and gives the
//! child no way to sign anything itself. See the crate docs for the three
//! independent reasons a child cannot impersonate another identity.
//!
//! # Exit codes
//!
//! Distinct codes so a supervising script can tell a refusal from a child
//! failure, which matters because the refusals are all operator-fixable and none
//! of them are the child's fault.
//!
//! | code | meaning |
//! |------|---------|
//! | 0    | the child exited 0 |
//! | 1..  | the child's own exit code |
//! | 2    | the identity is already in use by another wrapper |
//! | 3    | the identity is not in the config |
//! | 4    | the keystore key does not match the configured key |
//! | 5    | the daemon is unreachable |
//! | 6    | the child could not be spawned |
//! | 7    | the relay socket could not be created |
//! | 130  | interrupted (Ctrl-C) |

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use idboard_acl::Config;
use idboard_core::error::{CoreError, ErrorCode};
use idboard_core::layout;
use idboard_core::wire::{DaemonRequest, DaemonResponse, RelayRequest};
use idboard_core::{PROTOCOL_VERSION, now_ms};

use crate::keystore::Keystore;
use crate::lock::{IdentityLock, LockError};
use crate::relay::{self, Relay};

pub const EXIT_IDENTITY_LOCKED: i32 = 2;
pub const EXIT_NOT_IN_CONFIG: i32 = 3;
pub const EXIT_KEY_MISMATCH: i32 = 4;
pub const EXIT_DAEMON_UNREACHABLE: i32 = 5;
pub const EXIT_SPAWN_FAILED: i32 = 6;
pub const EXIT_RELAY_FAILED: i32 = 7;
pub const EXIT_INTERRUPTED: i32 = 130;

/// How long to keep serving after the child exits, so a post already in flight
/// is not lost.
const DRAIN: Duration = Duration::from_millis(150);

/// How often the serve loop wakes to check on the child and drain the socket.
const TICK: Duration = Duration::from_millis(5);

/// Everything `run_child` needs. Paths are explicit so tests can drive it.
#[derive(Debug, Clone)]
pub struct WrapperOptions {
    pub identity: String,
    /// The child command and arguments, already split.
    pub command: Vec<String>,
    pub config_path: PathBuf,
    pub daemon_socket: PathBuf,
    pub keystore: Keystore,
    /// Extra environment for the child, applied after the wrapper's own
    /// variables. For tests.
    pub extra_env: Vec<(String, String)>,
    /// Pin the lock file path instead of deriving it from the environment.
    ///
    /// Defaults to `~/.idboard/run/<identity>.lock`. Exposed so that a caller who
    /// relocates the config, socket, and keystore can relocate the lock too, rather
    /// than having it silently follow `IDBOARD_HOME`.
    pub lock_path: Option<PathBuf>,
    /// Pin the relay socket name instead of generating one.
    ///
    /// A legitimate operator affordance when a supervising process needs to know
    /// the socket path in advance; the default random name needs no coordination
    /// and is what almost every caller wants.
    pub relay_path: Option<PathBuf>,
    /// Supply the relay token instead of generating one.
    ///
    /// Lets an operator take the token from a secret manager rather than have
    /// the wrapper mint it. The token must still be random and unguessable, and
    /// the wrapper hands this exact value to the child.
    pub token: Option<String>,
    /// Skip binding a real socket. For tests that only exercise startup.
    pub dry_run: bool,
}

impl WrapperOptions {
    pub fn new(identity: &str, command: Vec<String>) -> Self {
        Self {
            identity: identity.to_string(),
            command,
            config_path: layout::config_path(),
            daemon_socket: layout::daemon_socket(),
            keystore: Keystore::standard(),
            extra_env: Vec::new(),
            lock_path: None,
            relay_path: None,
            token: None,
            dry_run: false,
        }
    }
}

/// Anything that stops the wrapper from starting or running the child.
#[derive(Debug, thiserror::Error)]
pub enum WrapperError {
    #[error("{0}")]
    Locked(#[from] LockError),

    #[error("identity {identity:?} is not in {config}. Keys are never learned on first use.\n  Run: idboard keygen {identity}\n  Then add it under [identity.{identity}] in {config}")]
    NotInConfig { identity: String, config: String },

    #[error(
        "keystore key for {identity:?} does not match the key in {config}.\n  \
         keystore fingerprint: {keystore_fp}\n  config fingerprint:    {config_fp}\n  \
         This is either a deliberate key rotation, or a regenerated keystore. \
         To rotate, update pubkey in the config and restart idboardd."
    )]
    KeyMismatch {
        identity: String,
        config: String,
        keystore_fp: String,
        config_fp: String,
    },

    #[error("idboard daemon is unreachable at {socket}: {detail}\n  Start it with: idboardd")]
    DaemonUnreachable { socket: String, detail: String },

    #[error("cannot start {command:?}: {source}")]
    Spawn {
        command: String,
        #[source]
        source: std::io::Error,
    },

    #[error("cannot create the relay socket at {path}: {detail}")]
    Relay { path: String, detail: String },

    #[error("config error: {0}")]
    Config(#[from] idboard_acl::ConfigError),

    #[error("keystore error: {0}")]
    Keystore(#[from] crate::keystore::KeystoreError),

    #[error("{0}")]
    Core(#[from] CoreError),
}

impl WrapperError {
    /// The process exit code for this failure.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Locked(_) => EXIT_IDENTITY_LOCKED,
            Self::NotInConfig { .. } => EXIT_NOT_IN_CONFIG,
            Self::KeyMismatch { .. } => EXIT_KEY_MISMATCH,
            Self::DaemonUnreachable { .. } => EXIT_DAEMON_UNREACHABLE,
            Self::Spawn { .. } => EXIT_SPAWN_FAILED,
            Self::Relay { .. } => EXIT_RELAY_FAILED,
            Self::Config(_) | Self::Keystore(_) | Self::Core(_) => 1,
        }
    }
}

/// Run `command` as `identity`, signing its board traffic.
///
/// Returns the exit code the wrapper should use: the child's own code on a
/// normal exit, or one of the `EXIT_*` constants.
pub fn run_child(opts: &WrapperOptions) -> Result<i32, WrapperError> {
    // 1. One live wrapper per identity, so sequence numbers cannot interleave.
    let lock_path = opts
        .lock_path
        .clone()
        .unwrap_or_else(|| layout::lock_path(&opts.identity));
    let _lock = IdentityLock::try_acquire_at(lock_path, &opts.identity)?;

    // 2. Key. Generated on first use, and the operator is told below.
    let (signer, created) = opts.keystore.load_or_create(&opts.identity)?;

    // 3. The config must already know this identity and this key.
    let config = Config::load(&opts.config_path)?;
    let registered = config.identity(&opts.identity).ok_or_else(|| WrapperError::NotInConfig {
        identity: opts.identity.clone(),
        config: opts.config_path.display().to_string(),
    })?;

    if registered.pubkey_hex != signer.public_hex() {
        return Err(WrapperError::KeyMismatch {
            identity: opts.identity.clone(),
            config: opts.config_path.display().to_string(),
            keystore_fp: signer.fingerprint().to_string(),
            config_fp: registered.fingerprint.clone(),
        });
    }

    if created {
        // A brand-new key is registered and usable, so this is informational
        // rather than fatal. Worth saying out loud, because it means a typo in
        // the identity name silently produced a second key.
        eprintln!(
            "idboard: generated a new key for {:?}\n  fingerprint: {}\n  pubkey: {}",
            opts.identity,
            signer.fingerprint(),
            signer.public_hex()
        );
    }

    // 4. Ask the daemon where to resume. Signed, so learning a counter requires
    //    the identity's key.
    let start_seq = handshake(&signer, &opts.daemon_socket)?;

    // 5. Relay socket. The name is unpredictable and namespaced by identity; the
    //    token is the actual credential.
    let token = match &opts.token {
        Some(t) => t.clone(),
        None => relay::generate_token()?,
    };
    let relay_path = match &opts.relay_path {
        Some(p) => p.clone(),
        None => relay::relay_path(&opts.identity, &relay::random_suffix()?),
    };
    let socket = if opts.dry_run {
        None
    } else {
        if let Err(e) = layout::ensure_private_dir(&layout::run_dir()) {
            return Err(WrapperError::Relay {
                path: layout::run_dir().display().to_string(),
                detail: e.to_string(),
            });
        }
        match idboard_ipc::bind_nonblocking(&relay_path) {
            Ok(l) => Some(l),
            Err(e) => {
                return Err(WrapperError::Relay { path: relay_path.display().to_string(), detail: e.to_string() });
            }
        }
    };

    let relay = Arc::new(Relay::new(
        &opts.identity,
        token.clone(),
        signer,
        start_seq,
        opts.daemon_socket.clone(),
    ));

    // 6. Child.
    let mut child = spawn_child(opts, &relay_path, &token)?;

    let code = if let Some(listener) = socket {
        serve_until_exit(&relay, listener, &mut child, opts)?
    } else {
        child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1)
    };

    relay::cleanup(&relay_path);
    eprintln!(
        "idboard: identity {:?} signed {} message(s); next seq would be {:?}",
        opts.identity,
        relay.signed_count(),
        relay.next_seq()
    );
    Ok(code)
}

/// Perform the signed handshake that establishes the starting sequence number.
fn handshake(signer: &idboard_core::keys::LocalSigner, daemon: &PathBuf) -> Result<i64, WrapperError> {
    let envelope = signer.sign_handshake(now_ms())?;
    let req = DaemonRequest { v: PROTOCOL_VERSION, envelope, since: 0, limit: 0 };

    let res: DaemonResponse = idboard_ipc::round_trip(daemon, &req).map_err(|e| {
        WrapperError::DaemonUnreachable { socket: daemon.display().to_string(), detail: e.to_string() }
    })?;

    if !res.ok {
        return Err(WrapperError::DaemonUnreachable {
            socket: daemon.display().to_string(),
            detail: format!("{}: {}", res.error.unwrap_or(ErrorCode::Internal), res.detail.unwrap_or_default()),
        });
    }

    let hs = res
        .handshake
        .ok_or_else(|| WrapperError::DaemonUnreachable {
            socket: daemon.display().to_string(),
            detail: "daemon did not answer the handshake".into(),
        })?;

    // The daemon echoes the fingerprint it has registered. If it disagrees with
    // ours, something changed underneath us and continuing would post messages
    // nobody can attribute.
    if hs.fingerprint != signer.fingerprint() {
        return Err(WrapperError::KeyMismatch {
            identity: signer.sender_id().to_string(),
            config: "<daemon>".into(),
            keystore_fp: signer.fingerprint().to_string(),
            config_fp: hs.fingerprint,
        });
    }

    Ok(hs.last_seq)
}

/// Build the child process: argv, environment, and stdio.
///
/// Split out from [`spawn_child`] so a test can inspect or capture the result.
/// The environment is the contract being tested, and it is identical either way —
/// `spawn_child` adds nothing to the command but `.spawn()`.
fn child_command(opts: &WrapperOptions, relay_path: &PathBuf, token: &str) -> std::result::Result<Command, WrapperError> {
    let (program, args) = opts
        .command
        .split_first()
        .ok_or_else(|| WrapperError::Spawn {
            command: String::new(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "no command given after `--`"),
        })?;

    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.env(layout::ENV_RELAY, relay_path);
    cmd.env(layout::ENV_TOKEN, token);
    // Strip the paths the wrapper itself needed. Defence in depth only: the real
    // control is that this process has no key, so knowing where the daemon is
    // buys nothing. Removing them just removes the temptation.
    cmd.env_remove(layout::ENV_DAEMON);
    cmd.env_remove(layout::ENV_CONFIG);
    cmd.env_remove(layout::ENV_HOME);
    for (k, v) in &opts.extra_env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());
    Ok(cmd)
}

fn spawn_child(opts: &WrapperOptions, relay_path: &PathBuf, token: &str) -> Result<Child, WrapperError> {
    let mut cmd = child_command(opts, relay_path, token)?;
    cmd.spawn().map_err(|source| WrapperError::Spawn { command: cmd.get_program().to_string_lossy().into_owned(), source })
}

/// Serve the relay until the child exits, then drain.
fn serve_until_exit(
    relay: &Arc<Relay>,
    listener: idboard_ipc::Listener,
    child: &mut Child,
    _opts: &WrapperOptions,
) -> Result<i32, WrapperError> {
    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let flag = interrupted.clone();
        // A second Ctrl-C should not be needed, but a handler that can fail to
        // install must not stop the wrapper from running.
        let _ = ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst));
    }

    let exit = loop {
        if interrupted.load(Ordering::SeqCst) {
            let _ = child.kill();
            break Ok::<i32, WrapperError>(EXIT_INTERRUPTED);
        }

        match child.try_wait() {
            Ok(Some(status)) => break Ok(status.code().unwrap_or(1)),
            Ok(None) => {}
            Err(e) => {
                return Err(WrapperError::Spawn { command: "<child>".into(), source: e });
            }
        }

        // Must run every tick even when idle: on Windows an unaccepted pipe
        // connection blocks every later client until accept drains it.
        //
        // `serve_one` is bounded by the I/O deadline rather than by the peer, so
        // a stalled client costs this loop one tick rather than the wrapper.
        loop {
            match idboard_ipc::try_accept(&listener) {
                Ok(Some(stream)) => serve_one(relay, stream),
                Ok(None) => break,
                Err(e) => {
                    eprintln!("idboard: relay accept failed: {e}");
                    break;
                }
            }
        }

        std::thread::sleep(TICK);
    };

    // Let a post that was already in flight finish.
    let deadline = Instant::now() + DRAIN;
    while Instant::now() < deadline {
        while let Ok(Some(stream)) = idboard_ipc::try_accept(&listener) {
            serve_one(relay, stream);
        }
        std::thread::sleep(TICK);
    }

    exit
}

/// Handle one child connection: read a request, answer it, close.
///
/// Called synchronously from the accept loop, so it must not be able to block it
/// indefinitely. The relay token is checked *inside* [`Relay::handle`], which is
/// reached only after a complete frame has arrived — so a process that finds the
/// relay pipe and never writes would otherwise stop this wrapper accepting,
/// stop it reaping the child, and keep the identity lock held, forever. The
/// bounded read is what prevents that.
///
/// The residual is that the accept loop's tick degrades to the I/O deadline while
/// a peer is stalling it. A bounded worker set mirroring the daemon's would fix
/// that too; it is not worth the threads until it is measured to matter.
fn serve_one(relay: &Arc<Relay>, stream: idboard_ipc::Stream) {
    let response: DaemonResponse = match idboard_ipc::read_frame_deadline::<RelayRequest>(&stream) {
        Ok(Some(req)) => relay.handle(&req),
        Ok(None) => return,
        Err(e) => DaemonResponse::err(
            ErrorCode::BadRequest,
            format!("could not read the request: {e}"),
        ),
    };

    let mut writer = stream;
    if let Err(e) = idboard_ipc::write_frame(&mut writer, &response) {
        eprintln!("idboard: could not answer the relay request: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spawn the child and read back the environment it actually received.
    ///
    /// A real spawn, not an inspected `Command`: the property under test is what
    /// the child *receives*, and asserting on a `Command` we built ourselves would
    /// only prove we called `env_remove`. Stdout is piped rather than inherited,
    /// which is the one deliberate difference from [`spawn_child`] and does not
    /// touch the environment.
    fn child_env(opts: &WrapperOptions) -> String {
        let relay = PathBuf::from("unused-relay");
        let mut cmd = child_command(opts, &relay, "token-value").expect("probe command must build");
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let out = cmd.output().expect("the probe child must spawn");
        assert!(
            out.status.success(),
            "probe child failed: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A command that dumps the environment of the process running it.
    fn env_probe_command() -> Vec<String> {
        #[cfg(windows)]
        {
            vec!["cmd".into(), "/c".into(), "set".into()]
        }
        #[cfg(unix)]
        {
            vec!["env".into()]
        }
    }

    /// The wrapper sets the relay and token, and strips the three variables that
    /// would tell the child where the daemon, the config, and the state root
    /// live.
    ///
    /// This was a documented contract in `AGENTS.md` and `README.md` with no unit
    /// and no e2e coverage at all: `wrapper.rs` had no `#[cfg(test)]` module, so
    /// the stripping could have been deleted without a single test noticing.
    ///
    /// Note what this is *not*. Stripping is defence in depth, not the control.
    /// A child that knew where the daemon was still could not post, because it
    /// has no key. See `AGENTS.md`.
    #[test]
    fn the_child_gets_the_relay_and_not_the_wrappers_own_paths() {
        // This test mutates the process environment, so it must take the same
        // lock the `lock` module's tests take. Without it, a concurrent
        // `lock::tests::*` can observe `IDBOARD_HOME=SENTINEL-VALUE`, resolve its
        // lock path under the sentinel directory, and fail for a reason that has
        // nothing to do with locks. `set_var` is process-global; there is one
        // lock for it in this crate and this is it.
        let _guard = crate::lock::tests::env_lock();

        // Set to a sentinel to prove these are *removed* rather than merely
        // absent. Restored below.
        let restore: Vec<(String, Option<String>)> = [layout::ENV_DAEMON, layout::ENV_CONFIG, layout::ENV_HOME]
            .iter()
            .map(|v| ((*v).to_string(), std::env::var(v).ok()))
            .collect();
        for var in [layout::ENV_DAEMON, layout::ENV_CONFIG, layout::ENV_HOME] {
            unsafe { std::env::set_var(var, "SENTINEL-VALUE") };
        }

        let mut opts = WrapperOptions::new("eng-01", env_probe_command());
        opts.dry_run = true;
        let seen = child_env(&opts);

        for (var, was) in restore {
            match was {
                Some(v) => unsafe { std::env::set_var(&var, v) },
                None => unsafe { std::env::remove_var(&var) },
            }
        }

        assert!(
            seen.contains(&format!("{}=", layout::ENV_RELAY)),
            "the child must be told where its relay is:\n{seen}"
        );
        assert!(
            seen.contains("IDBOARD_TOKEN=token-value"),
            "the child must receive the token:\n{seen}"
        );
        for var in [layout::ENV_DAEMON, layout::ENV_CONFIG, layout::ENV_HOME] {
            assert!(
                !seen.contains(&format!("{var}=")),
                "{var} reached the child; it must not learn where the daemon or the key live:\n{seen}"
            );
        }
        assert!(
            !seen.contains("SENTINEL-VALUE"),
            "a stripped variable's value leaked into the child environment:\n{seen}"
        );
    }

    /// A command with no executable after `--` is a spawn failure, not a panic and
    /// not a silently empty child.
    #[test]
    fn an_empty_command_is_a_spawn_error() {
        let mut opts = WrapperOptions::new("eng-01", vec![]);
        opts.dry_run = true;
        let err = spawn_child(&opts, &PathBuf::from("unused-relay"), "t").unwrap_err();
        assert!(matches!(err, WrapperError::Spawn { .. }), "{err:?}");
        assert_eq!(err.exit_code(), EXIT_SPAWN_FAILED);
    }

    /// A command that does not exist is a spawn failure carrying the OS error,
    /// with the documented exit code a supervising script depends on.
    #[test]
    fn a_missing_executable_reports_the_spawn_exit_code() {
        let mut opts = WrapperOptions::new(
            "eng-01",
            vec!["idboard-no-such-binary-4f2a9c".into(), "arg".into()],
        );
        opts.dry_run = true;
        let err = spawn_child(&opts, &PathBuf::from("unused-relay"), "t").unwrap_err();
        assert!(matches!(err, WrapperError::Spawn { .. }), "{err:?}");
        assert_eq!(err.exit_code(), EXIT_SPAWN_FAILED);
    }

    /// The exit codes are a contract for supervising scripts, and 2/3/4 are
    /// deliberately exact: they are the three that distinguish "locked", "not in
    /// config", and "key mismatch" in a launch script's error handling.
    #[test]
    fn the_identity_failure_exit_codes_are_exact() {
        let locked = WrapperError::Locked(LockError::Held {
            identity: "x".into(),
            path: "p".into(),
            pid: 1,
        });
        assert_eq!(locked.exit_code(), EXIT_IDENTITY_LOCKED);
        assert_eq!(EXIT_IDENTITY_LOCKED, 2);
        assert_eq!(EXIT_NOT_IN_CONFIG, 3);
        assert_eq!(EXIT_KEY_MISMATCH, 4);
        assert_eq!(EXIT_DAEMON_UNREACHABLE, 5);
        assert_eq!(EXIT_SPAWN_FAILED, 6);
        assert_eq!(EXIT_RELAY_FAILED, 7);
    }
}
