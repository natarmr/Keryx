//! Cross-platform local socket transport, plus JSON framing.
//!
//! # Transport
//!
//! `interprocess` gives one API over two mechanisms: Unix domain sockets on
//! Unix, named pipes on Windows. Both are reachable only from the same machine
//! and neither is a network listener, so "no network exposure in v1" holds on
//! both platforms.
//!
//! On Windows a pipe name is **not** a secret. Any local process can enumerate
//! `\\.\pipe\*` and find ours. The same is true of a Unix socket path, which any
//! process can `stat`. Neither is a security boundary, and neither is treated as
//! one here. The relay socket's actual authentication is the bearer token that
//! the wrapper hands the child through the environment; see
//! `idboard_core::layout::ENV_TOKEN`.
//!
//! # Framing
//!
//! One JSON object per line, one line per connection, then close. There is no
//! multiplexing and no persistent session. That is a deliberate simplification
//! with a security benefit: a process killed mid-write leaves a truncated line
//! that fails to parse, so it can never half-apply a database transaction.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, sync_channel};

use interprocess::local_socket::prelude::*;
use interprocess::local_socket::{GenericFilePath, ListenerNonblockingMode, ListenerOptions};
use interprocess::TryClone;
use idboard_core::PROTOCOL_VERSION;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Largest single frame we will read, in bytes.
///
/// A body is capped at 64 KiB by `idboard-core`, and an envelope adds a few
/// hundred bytes of JSON overhead. 1 MiB leaves generous headroom while still
/// refusing to let a caller make the daemon allocate without bound.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

// Re-exported so callers can name the types they must hold, without taking a
// direct dependency on `interprocess`. Callers should not need to know which
// crate underneath is providing sockets.
pub use interprocess::local_socket::{Listener, Stream};

/// How long to wait on a single connection before giving up.
///
/// A daemon thread must not be pinnable by a client that connects and then goes
/// quiet. Short, because every legitimate request is a single small write
/// followed by a read.
pub const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Transport-level failures.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("socket io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("frame exceeds {MAX_FRAME_BYTES} bytes")]
    FrameTooLarge,

    #[error("malformed frame: {0}")]
    Decode(#[from] serde_json::Error),

    #[error("protocol version {got} is not supported; this build speaks {PROTOCOL_VERSION}")]
    VersionMismatch { got: u8 },

    #[error("connection closed before a complete frame arrived")]
    UnexpectedEof,

    #[error("peer sent no complete frame within the I/O deadline")]
    Timeout,
}

impl IpcError {
    /// Whether retrying the same request could plausibly succeed.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Io(e) => matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionRefused
            ),
            Self::UnexpectedEof | Self::Timeout => true,
            _ => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, IpcError>;

/// Map a filesystem path to a local socket name.
///
/// On Windows the path must begin with `\\.\pipe\`; `GenericFilePath` rejects
/// anything else, which is a useful guard against accidentally pointing at a
/// real file. `idboard_core::layout` is responsible for producing such paths.
fn name_for(path: &Path) -> Result<interprocess::local_socket::Name<'_>> {
    Ok(path.as_os_str().to_fs_name::<GenericFilePath>()?)
}

/// Bind a listener, reclaiming a stale socket left by a crashed daemon.
///
/// `try_overwrite` is left at its default of `false`, so a second daemon cannot
/// silently displace a live one. On Unix, `reclaim_name` (on by default) removes
/// a leftover socket file from a previous crash, which is not the same thing.
///
/// No security descriptor is set. See [`listener_custody_statement`].
pub fn bind(path: &Path) -> Result<Listener> {
    let name = name_for(path)?;
    Ok(ListenerOptions::new().name(name).create_sync()?)
}

/// Bind a listener whose `accept` never blocks, while the accepted streams
/// still block normally.
///
/// This split is exactly what the wrapper needs: it can poll for a connection
/// without giving up ordinary blocking reads on the one it just accepted.
///
/// No security descriptor is set. See [`listener_custody_statement`].
pub fn bind_nonblocking(path: &Path) -> Result<Listener> {
    let name = name_for(path)?;
    Ok(ListenerOptions::new()
        .name(name)
        .nonblocking(ListenerNonblockingMode::Accept)
        .create_sync()?)
}

/// Who is allowed to open a listener this module created.
///
/// Stated rather than enforced, and deliberately kept separate from the config's
/// custody statement because the two are different assumptions about different
/// surfaces. The config is the trust root; the socket is the door to it, and it
/// is the surface every local process can actually *reach* — a signature check
/// that anyone may attempt.
///
/// Neither `bind` nor `bind_nonblocking` sets a security descriptor, so on
/// Windows the listener inherits the **creating token's default DACL**, which on
/// a standard profile is the creating account, SYSTEM, and Administrators. There
/// is no transport-level restriction in front of the signature check.
///
/// That is a real residual with two consequences worth being explicit about. A
/// *different* local account is excluded by that default on a standard profile,
/// so this is not an open door in the ordinary case. A *same-user* process is not
/// excluded and never was: the README places same-user inside the documented
/// boundary, and every control behind this socket is a signature check plus the
/// bounded work in `read_frame_deadline`.
///
/// Whether the assumption holds is a property of the machine, not of this crate.
/// The operator can check it with `check-custody.ps1`; the alternative would be
/// `interprocess`'s `ListenerOptionsExt::security_descriptor`, which needs a
/// hand-built `ACL` because the crate exposes no way to adopt an SDDL string.
pub fn listener_custody_statement() -> &'static str {
    #[cfg(windows)]
    {
        "socket custody: no security descriptor is set. The listener inherits the creating \
         token's default DACL (on a standard profile: you, SYSTEM, Administrators), so a \
         different local account is excluded by default but a same-user process is not. Every \
         control behind the socket is a signature check. Verify with: scripts\\check-custody.ps1"
    }
        #[cfg(unix)]
        {
            "socket custody: the listener is a filesystem socket in a 0700 directory, so the \
             directory mode is the access control and a different local user cannot reach it. \
             A same-user process is not excluded, and every control behind the socket is a \
             signature check. Verify with: scripts/check-custody.ps1"
        }
}

/// Duplicate a stream so one handle can read while the other writes.
///
/// Every request here is one write followed by one read on the same connection,
/// which a single handle could manage with a half-duplex dance. Cloning is far
/// easier to reason about, and it keeps `TryClone` from leaking out of this
/// crate.
pub fn split(stream: &Stream) -> Result<Stream> {
    Ok(stream.try_clone()?)
}

/// Block until a client connects, then return the stream.
pub fn accept(listener: &Listener) -> Result<Stream> {
    let stream = listener.accept()?;
    apply_timeouts(&stream)?;
    Ok(stream)
}

/// Accept one connection if one is already pending, without blocking.
///
/// Requires a listener bound with [`bind_nonblocking`]. Returns `Ok(None)` when
/// the listener is idle, so a serve loop can poll.
///
/// Must be called regularly even when the caller has no work to do. On Windows a
/// named-pipe client that connects and then disconnects leaves a
/// dead-on-arrival connection in the pipe instance, which blocks every
/// subsequent client until `accept` drains it. A wrapper that only accepted when
/// it expected traffic would wedge its own relay.
pub fn try_accept(listener: &Listener) -> Result<Option<Stream>> {
    match listener.accept() {
        Ok(stream) => {
            apply_timeouts(&stream)?;
            Ok(Some(stream))
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Connect to a listener, with I/O deadlines applied.
pub fn connect(path: &Path) -> Result<Stream> {
    let name = name_for(path)?;
    let stream = Stream::connect(name)?;
    apply_timeouts(&stream)?;
    Ok(stream)
}

/// Best-effort I/O deadlines on an accepted or connected stream.
///
/// **Windows named pipes do not support these.** `interprocess` returns
/// `ErrorKind::Unsupported` unconditionally for a named-pipe stream, so on the
/// project's primary platform this function installs *nothing* every single time.
/// It records that in [`deadlines_installed`] rather than reporting a success it
/// did not achieve, so a caller can log the real state of the world instead of
/// trusting a comment.
///
/// The consequence of no deadline is a bounded weakness, not an unbounded one: a
/// client that connects and then never writes occupies the thread reading it
/// until it disconnects. [`read_frame_deadline`] is what actually bounds that;
/// the fixed pools in the daemon and the wrapper are the second line. See the
/// residual-risks note in the README.
fn apply_timeouts(stream: &Stream) -> Result<()> {
    let results = [
        stream.set_recv_timeout(Some(IO_TIMEOUT)),
        stream.set_send_timeout(Some(IO_TIMEOUT)),
    ];
    for r in results {
        match r {
            Ok(()) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::Unsupported => {
                DEADLINES_INSTALLED.store(false, Ordering::Relaxed);
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Whether every stream this process has touched so far carried a real I/O
/// deadline.
///
/// `false` on Windows, always. Callers that care should say so out loud at
/// startup rather than leaving the operator to infer it from a comment.
pub fn deadlines_installed() -> bool {
    DEADLINES_INSTALLED.load(Ordering::Relaxed)
}

/// Starts optimistic so a process that never opens a stream does not warn.
static DEADLINES_INSTALLED: AtomicBool = AtomicBool::new(true);

/// Read one newline-delimited JSON frame, giving up if the peer goes quiet.
///
/// The platform deadline in [`apply_timeouts`] is not dependable — on Windows it
/// is never installed — so the bound here is enforced by this function rather
/// than by the socket. A reader thread does the blocking read and the caller
/// waits a fixed [`IO_TIMEOUT`] for its result.
///
/// On timeout the reader thread is *not* cancelled: it holds the read handle and
/// exits when the peer finally writes or disconnects. That is deliberate, because
/// cancelling a blocked read on a Windows pipe handle is not something
/// `interprocess` exposes. The cost of a stalled peer is therefore one parked
/// thread, bounded by how many such peers arrive, instead of a worker slot and
/// whatever shared lock that worker was holding.
pub fn read_frame_deadline<T: DeserializeOwned + Send + 'static>(stream: &Stream) -> Result<Option<T>> {
    read_frame_within(stream, IO_TIMEOUT)
}

/// [`read_frame_deadline`] with an explicit wait, so a test can pin the
/// behaviour without spending the production deadline.
fn read_frame_within<T: DeserializeOwned + Send + 'static>(
    stream: &Stream,
    timeout: std::time::Duration,
) -> Result<Option<T>> {
    let reader = split(stream)?;
    let (tx, rx) = sync_channel(1);
    std::thread::spawn(move || {
        let _ = tx.send(read_frame::<T, _>(reader));
    });
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(IpcError::Timeout),
        Err(RecvTimeoutError::Disconnected) => Err(IpcError::UnexpectedEof),
    }
}

/// Read one newline-delimited JSON frame.
///
/// Returns `Ok(None)` on a clean end of stream with nothing pending, which lets
/// a serve loop distinguish "no connection" from "connection closed".
pub fn read_frame<T: DeserializeOwned, S: Read>(stream: S) -> Result<Option<T>> {
    let mut reader = BufReader::new(stream);
    read_frame_from(&mut reader)
}

/// Read one frame from an existing reader.
pub fn read_frame_from<T: DeserializeOwned, R: BufRead>(reader: &mut R) -> Result<Option<T>> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);

    loop {
        let available = match reader.fill_buf() {
            Ok(b) => b,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if available.is_empty() {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(IpcError::UnexpectedEof)
            };
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(i) => {
                if buf.len() + i > MAX_FRAME_BYTES {
                    return Err(IpcError::FrameTooLarge);
                }
                buf.extend_from_slice(&available[..i]);
                reader.consume(i + 1);
                return decode_frame(&buf).map(Some);
            }
            None => {
                let n = available.len();
                if buf.len() + n > MAX_FRAME_BYTES {
                    return Err(IpcError::FrameTooLarge);
                }
                buf.extend_from_slice(available);
                reader.consume(n);
            }
        }
    }
}

fn decode_frame<T: DeserializeOwned>(buf: &[u8]) -> Result<T> {
    // Tolerate CRLF, since a Windows client may send it.
    let trimmed = match buf.split_last() {
        Some((b'\r', rest)) => rest,
        _ => buf,
    };
    if trimmed.iter().all(|b| b.is_ascii_whitespace()) {
        return Err(IpcError::Decode(serde_json::from_str::<serde_json::Value>("").unwrap_err()));
    }
    Ok(serde_json::from_slice(trimmed)?)
}

/// Write one JSON frame followed by a newline, then flush.
///
/// The size check happens *while* serialising, not after. Checking afterwards
/// means the whole frame has already been built in memory to be measured: a
/// caller that assembles a large value pays for all of it and then gets an
/// error, which is the worst of both. The counting writer below refuses to grow
/// past the cap in the first place, so an oversized value costs at most
/// [`MAX_FRAME_BYTES`].
pub fn write_frame<T: Serialize, W: Write>(mut writer: W, value: &T) -> Result<()> {
    let mut sink = CappedWriter {
        inner: Vec::with_capacity(1024),
        cap: MAX_FRAME_BYTES,
        written: 0,
    };
    serde_json::to_writer(&mut sink, value)?;
    if sink.inner.len() > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge);
    }
    sink.inner.push(b'\n');
    writer.write_all(&sink.inner)?;
    writer.flush()?;
    Ok(())
}

/// A `Vec<u8>` that refuses to grow past a cap.
///
/// Exists so the frame bound is enforced during serialisation. A
/// `std::io::ErrorKind::WriteZero` surfaces out of `serde_json` as a
/// `Serialize`-shaped error rather than silently truncating, which is what we
/// want: the caller's frame is either complete or refused.
struct CappedWriter {
    inner: Vec<u8>,
    cap: usize,
    written: usize,
}

impl Write for CappedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next = self.written.saturating_add(buf.len());
        if next > self.cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                IpcError::FrameTooLarge,
            ));
        }
        self.inner.extend_from_slice(buf);
        self.written = next;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Send one request and read one reply on a fresh connection.
pub fn round_trip<Req: Serialize, Res: DeserializeOwned>(path: &Path, request: &Req) -> Result<Res> {
    let stream = connect(path)?;
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(e) => return Err(e.into()),
    });
    write_frame(&stream, request)?;
    match read_frame_from(&mut reader)? {
        Some(v) => Ok(v),
        None => Err(IpcError::UnexpectedEof),
    }
}

/// Remove a socket file left behind on Unix. A no-op on Windows, where pipes
/// vanish with their last handle.
pub fn cleanup_socket_file(path: &Path) {
    #[cfg(unix)]
    {
        let _ = std::fs::remove_file(path);
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Reject a frame whose declared protocol version this build does not speak.
pub fn check_version(got: u8) -> Result<()> {
    if got == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(IpcError::VersionMismatch { got })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use idboard_core::wire::{DaemonRequest, DaemonResponse};
    use std::path::PathBuf;

    fn temp_socket(tag: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let name = format!("keryx-test-{tag}-{}-{:?}", std::process::id(), std::thread::current().id());
        // Named pipes dislike some characters; keep it simple.
        let name: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
        let path = if cfg!(windows) {
            PathBuf::from(format!(r"\\.\pipe\{name}"))
        } else {
            dir.path().join(format!("{name}.sock"))
        };
        (dir, path)
    }

    #[test]
    fn request_response_round_trip_over_a_real_socket() {
        let (_dir, path) = temp_socket("rt");

        // Bind before spawning, so the client cannot race the server's bind.
        let listener = bind(&path).unwrap();

        let server = std::thread::spawn(move || {
            let mut stream = listener.accept().unwrap();
            let req: DaemonRequest = read_frame(stream.try_clone().unwrap()).unwrap().unwrap();
            assert_eq!(req.envelope.channel, "general");
            write_frame(&mut stream, &DaemonResponse::ok().with_cursor(7)).unwrap();
            req
        });

        let req = DaemonRequest {
            v: PROTOCOL_VERSION,
            envelope: idboard_core::Envelope {
                op: idboard_core::Op::Post,
                sender_id: "eng-01".into(),
                sender_pubkey_fp: "a3f9c1d2e3f40506".into(),
                channel: "general".into(),
                body: "hello".into(),
                provenance: idboard_core::Provenance::SelfOriginated,
                seq: 1,
                timestamp: 1,
                nonce: String::new(),
                signature: "ab".repeat(64),
            },
            since: 0,
            limit: 0,
        };
        let res: DaemonResponse = round_trip(&path, &req).unwrap();
        assert!(res.ok);
        assert_eq!(res.cursor, Some(7));
        let got = server.join().unwrap();
        assert_eq!(got.envelope.body, "hello");
    }

    #[test]
    fn empty_stream_reads_as_none_not_an_error() {
        let data: &[u8] = b"";
        let v: Option<DaemonResponse> = read_frame::<_, _>(data).unwrap();
        assert!(v.is_none());
    }

    #[test]
    fn truncated_frame_is_an_error() {
        let data: &[u8] = b"{\"ok\":true";
        let err = read_frame::<DaemonResponse, _>(data).unwrap_err();
        assert!(matches!(err, IpcError::UnexpectedEof), "{err}");
    }

    #[test]
    fn malformed_json_is_rejected() {
        let data: &[u8] = b"not json at all\n";
        assert!(read_frame::<DaemonResponse, _>(data).is_err());
    }

    #[test]
    fn crlf_line_endings_are_tolerated() {
        let data: &[u8] = b"{\"ok\":true,\"cursor\":3}\r\n";
        let v: DaemonResponse = read_frame::<_, _>(data).unwrap().unwrap();
        assert_eq!(v.cursor, Some(3));
    }

    #[test]
    fn oversized_frames_are_refused_before_allocation() {
        let mut data = vec![b'{'];
        data.extend(std::iter::repeat_n(b'x', MAX_FRAME_BYTES + 10));
        data.push(b'\n');
        let err = read_frame::<DaemonResponse, _>(&data[..]).unwrap_err();
        assert!(matches!(err, IpcError::FrameTooLarge), "{err}");
    }

    #[test]
    fn version_mismatch_is_distinguishable() {
        assert!(check_version(PROTOCOL_VERSION).is_ok());
        let err = check_version(PROTOCOL_VERSION + 1).unwrap_err();
        assert!(matches!(err, IpcError::VersionMismatch { .. }));
    }

    #[test]
    fn nonblocking_accept_reports_no_connection() {
        let (_dir, path) = temp_socket("nb");
        let listener = bind_nonblocking(&path).unwrap();
        assert!(
            try_accept(&listener).unwrap().is_none(),
            "an idle nonblocking listener should report no connection"
        );
    }

    #[test]
    fn connecting_to_a_missing_socket_is_an_io_error() {
        let (_dir, path) = temp_socket("missing");
        let err = connect(&path).unwrap_err();
        assert!(matches!(err, IpcError::Io(_)));
    }

    /// Must succeed on Windows too, where named pipes reject I/O timeouts.
    ///
    /// The point of this test is that the tolerance is real, not that the function
    /// returns `Ok` — which it would either way. The reported support is the part
    /// worth pinning, because a caller logs it.
    #[test]
    fn applying_timeouts_never_fails_and_reports_what_it_actually_installed() {
        let (_dir, path) = temp_socket("timeouts");
        let listener = bind(&path).unwrap();
        let _client = connect(&path);
        let accepted = try_accept(&listener).unwrap().expect("client should connect");
        let before = deadlines_installed();
        apply_timeouts(&accepted)
            .expect("Unsupported from Windows named pipes must be tolerated, not propagated");
        let after = deadlines_installed();
        #[cfg(unix)]
        assert!(after, "SO_RCVTIMEO applies on Unix, so a deadline must be reported");
        #[cfg(windows)]
        assert!(!after, "named pipes have no SO_RCVTIMEO; reporting one would be a lie");
        let _ = before;
    }

    /// A peer that connects and never writes must not pin the reader past the
    /// deadline. This is the observable half of the Windows no-timeout story.
    #[test]
    fn a_peer_that_never_writes_is_given_up_on_rather_than_waited_forever() {
        const SHORT: std::time::Duration = std::time::Duration::from_millis(300);
        // Generous on purpose. This is the *control*, so its job is to show the
        // deadline does not fire on a peer that behaves — a tight window here
        // would only measure how busy the machine is when the suite runs.
        const CONTROL: std::time::Duration = std::time::Duration::from_secs(5);

        let (_dir, path) = temp_socket("stall");
        let listener = bind(&path).unwrap();
        let _stalled = connect(&path).unwrap();
        let accepted = try_accept(&listener).unwrap().expect("client should connect");

        let started = std::time::Instant::now();
        let err = read_frame_within::<DaemonRequest>(&accepted, SHORT).unwrap_err();
        let elapsed = started.elapsed();

        assert!(matches!(err, IpcError::Timeout), "{err}");
        assert!(err.is_transient(), "a stalled peer is plausibly worth retrying");
        assert!(
            elapsed >= SHORT - std::time::Duration::from_millis(100),
            "gave up after {elapsed:?}, before the deadline: the test proved nothing"
        );

        // Control: a peer that writes from the client end must be served, which
        // is the shape every real request takes.
        let (_dir2, path2) = temp_socket("ctl");
        let listener2 = bind(&path2).unwrap();
        let client2 = connect(&path2).unwrap();
        let accepted2 = try_accept(&listener2).unwrap().expect("client should connect");
        let writer = std::thread::spawn(move || {
            let mut w = client2;
            let _ = w.write_all(b"{\"ok\":true,\"cursor\":3}\n");
            let _ = w.flush();
        });
        let got = read_frame_within::<DaemonResponse>(&accepted2, CONTROL)
            .expect("a prompt peer must be served normally")
            .expect("a complete frame");
        assert_eq!(got.cursor, Some(3));
        writer.join().expect("the writer thread must not panic");
    }

    /// The two-listener test is gone as a tautology: a second bind of a live name
    /// must fail, and `e2e.rs::a_second_daemon_cannot_displace_a_live_one` covers
    /// the same property end to end against a real daemon.
    #[test]
    fn two_listeners_cannot_both_bind_the_same_name() {
        let (_dir, path) = temp_socket("dup");
        let _first = bind(&path).unwrap();
        // `try_overwrite` is left false, so a second bind cannot displace a live
        // listener. Whichever way the platform reports it, the call must be an
        // error rather than a silent second success.
        let second = bind(&path);
        assert!(second.is_err(), "a second bind of a live name must be refused");
    }

    /// A custody statement that over-claims is worse than no statement, because
    /// an operator reads it and stops looking.
    #[test]
    fn the_listener_custody_statement_does_not_over_claim() {
        let s = listener_custody_statement();

        // It must name a way to check, or it is just an assertion in prose.
        assert!(s.contains("check-custody.ps1"), "must say how to verify: {s}");

        // It must not claim to restrict anyone, because it does not.
        for overclaim in ["only you", "denies Everyone", "restricts access", "enforced"] {
            assert!(
                !s.contains(overclaim),
                "the statement over-claims ({overclaim:?}) while no descriptor is set: {s}"
            );
        }

        // The honest residual must be present: same-user is not excluded, and
        // that is a decision rather than an oversight.
        assert!(s.contains("same-user"), "must name the in-boundary peer: {s}");
        assert!(s.contains("signature"), "must name what actually guards the socket: {s}");
    }
}
