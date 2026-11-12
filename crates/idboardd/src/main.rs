//! `idboardd`: the daemon.
//!
//! Deliberately thin. Every security decision lives in [`idboardd::Board`],
//! which is tested without a socket; this file moves bytes and logs.

use std::process::ExitCode;
use std::sync::mpsc::sync_channel;
use std::thread;

use clap::Parser;
use idboard_acl::Config;
use idboard_core::error::{CoreError, ErrorCode};
use idboard_core::layout;
use idboard_core::wire::{DaemonRequest, DaemonResponse};
use idboard_store::Store;

use idboardd::{Board, rejection_line};

/// Concurrent connections handled at once.
///
/// Bounded on purpose. Windows named pipes do not support per-connection I/O
/// timeouts, so a client that connects and then stalls occupies a worker until it
/// disconnects. With a fixed pool that costs throughput; with unbounded threads
/// it would cost the process.
const WORKERS: usize = 4;

/// Connections that may be waiting for a worker before the listener stops
/// accepting. Keeps a burst from growing the queue without limit.
const QUEUE_DEPTH: usize = 64;

#[derive(Debug, Parser)]
#[command(name = "idboardd", version, about = "The idboard daemon.", long_about = None)]
struct Args {
    /// Path to the identity and ACL config.
    #[arg(long)]
    config: Option<std::path::PathBuf>,

    /// Path to the daemon socket or named pipe.
    #[arg(long)]
    socket: Option<std::path::PathBuf>,

    /// Path to the SQLite database.
    #[arg(long)]
    db: Option<std::path::PathBuf>,

    /// Validate the config and the stored keys, then exit without listening.
    #[arg(long)]
    check: bool,

    /// Print the resolved ACL matrix and exit.
    #[arg(long)]
    show_acl: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("idboardd: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> anyhow::Result<()> {
    let config_path = args.config.unwrap_or_else(layout::config_path);
    let socket_path = args.socket.unwrap_or_else(layout::daemon_socket);
    let db_path = args.db.unwrap_or_else(layout::db_path);

    let config = Config::load(&config_path).map_err(|e| anyhow::anyhow!("{e:#}"))?;

    eprintln!("idboardd: loaded {}", config_path.display());
    eprintln!("idboardd: {}", Config::custody_statement());
    eprintln!("idboardd: {}", idboard_ipc::listener_custody_statement());
    eprint!("{}", config.summary());
    for warning in config.role_inheritance_warnings() {
        eprintln!("idboardd: warning: {warning}");
    }

    if args.show_acl {
        return Ok(());
    }

    let store = Store::open(&db_path)?;
    let (board, rotated) = Board::new(config, store)?;

    for identity in rotated {
        eprintln!(
            "idboardd: warning: the public key for {identity:?} differs from the one stored in {}. \
             Messages signed with the old key will no longer verify. If this was not a deliberate \
             rotation, restore the previous pubkey in the config.",
            db_path.display()
        );
    }

    if args.check {
        eprintln!("idboardd: check passed; {} identities, socket {}", board.config().identity_count(), socket_path.display());
        return Ok(());
    }

    // Clear a socket left by a previous crash. `reclaim_name` handles this for
    // Unix; on Windows pipes disappear with their handles and there is nothing
    // to clean.
    idboard_ipc::cleanup_socket_file(&socket_path);

    let listener = idboard_ipc::bind(&socket_path)
        .map_err(|e| anyhow::anyhow!("cannot listen on {}: {e}", socket_path.display()))?;

    eprintln!("idboardd: listening on {}", socket_path.display());
    eprintln!("idboardd: database {}", db_path.display());

    let (tx, rx) = sync_channel::<idboard_ipc::Stream>(QUEUE_DEPTH);
    let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));

    // The board is the only mutable shared state, so exactly one worker may own
    // it at a time. SQLite writes are serialised anyway, and taking a lock per
    // request is not a cost worth optimising away at this scale.
    let board = std::sync::Arc::new(std::sync::Mutex::new(board));

    let mut handles = Vec::with_capacity(WORKERS);
    for _ in 0..WORKERS {
        let rx = rx.clone();
        let board = board.clone();
        handles.push(thread::spawn(move || {
            loop {
                let stream = {
                    let guard = match rx.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    match guard.recv() {
                        Ok(s) => s,
                        Err(_) => return,
                    }
                };
                serve(&board, stream);
            }
        }));
    }

    eprintln!("idboardd: {WORKERS} workers ready");
    if !idboard_ipc::deadlines_installed() {
        eprintln!(
            "idboardd: note: this platform's named pipes carry no I/O deadline. A peer that \
             connects and stops writing is given up after {}s, and costs one parked thread.",
            idboard_ipc::IO_TIMEOUT.as_secs()
        );
    }
    loop {
        match idboard_ipc::accept(&listener) {
            Ok(s) => {
                if tx.send(s).is_err() {
                    break;
                }
            }
            Err(e) => {
                // One bad connection must not take the daemon down.
                eprintln!("idboardd: accept failed: {e}");
            }
        }
    }

    drop(tx);
    for h in handles {
        let _ = h.join();
    }
    idboard_ipc::cleanup_socket_file(&socket_path);
    Ok(())
}

/// Answer one connection.
///
/// The board lock is taken *here*, tightly around [`Board::handle`], and not by
/// the caller. It used to be taken by the worker before this function was called,
/// which meant the guard was already held before the first byte was read — so one
/// unauthenticated peer that connected and went quiet withheld the board from
/// *every* identity, not just its own. The board is a shared multi-tenant
/// resource and a peer-paced read is not bounded by anything the daemon controls
/// on Windows, so the read must not happen under the lock.
///
/// Holding it this narrowly weakens nothing: [`Board::handle`] does bounded local
/// work and never touches the stream. The wrapper already applies exactly this
/// discipline to its own sequence mutex.
fn serve(board: &std::sync::Mutex<Board>, mut stream: idboard_ipc::Stream) {
    let response: DaemonResponse = match idboard_ipc::read_frame_deadline::<DaemonRequest>(&stream) {
        Ok(Some(req)) => {
            let res = {
                let mut guard = match board.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                guard.handle(&req)
            };
            if !res.ok {
                let code = res.error.unwrap_or(ErrorCode::Internal);
                let detail = res.detail.clone().unwrap_or_default();
                eprintln!(
                    "idboardd: {}",
                    rejection_line(&req.envelope, &CoreError::new(code, detail))
                );
            }
            res
        }
        Ok(None) => return,
        Err(e) => DaemonResponse::err(ErrorCode::BadRequest, format!("could not read the request: {e}")),
    };

    if let Err(e) = idboard_ipc::write_frame(&mut stream, &response) {
        eprintln!("idboardd: could not answer: {e}");
    }
}
