//! bus commands.
//!
//! Split from `cli.rs` by group with no behavior change (E3).
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand, ValueEnum};
use idboard_core::error::Result;
use idboard_core::ids::DEFAULT_READ_LIMIT;
use idboard_core::layout;
use idboard_core::{Provenance, validate_body, validate_channel, validate_identity};

use idboard::client::RelayClient;
use idboard::cursor::CursorStore;
use idboard::keystore::Keystore;
use idboard::wrapper::{self, WrapperOptions};
use idboard::tasks::*;

use super::*;

pub(crate) fn cmd_post(json: bool, channel: &str, body: &str, provenance: Provenance) -> Result<i32> {
    validate_channel(channel)?;
    let client = RelayClient::from_env()?;
    let res = match client.post(channel, body, provenance) {
        Ok(res) => res,
        Err(e) => {
            // `--json` keeps failures machine-readable too, including the optional
            // rate-limit hint and a small set of actionable referrals.
            if json {
                let (visible, closest) = match e.code {
                    idboard_core::ErrorCode::Unauthorized | idboard_core::ErrorCode::UnknownChannel => {
                        let visible = client.inbox(0).ok().map(|r| {
                            r.channels.into_iter().map(|c| c.channel).collect::<Vec<_>>()
                        });
                        let closest = visible
                            .as_ref()
                            .map(|v| closest_names(channel, v, 3))
                            .unwrap_or_default();
                        (visible, Some(closest))
                    }
                    _ => (None, None),
                };
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "error": e.code.as_str(),
                        "detail": e.detail,
                        "retry_after_ms": e.retry_after_ms,
                        "hint": post_error_hint(e.code),
                        "visible_channels": visible,
                        "closest_channels": closest,
                    })
                );
                return Ok(1);
            }
            return Err(e);
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&res)?);
    } else {
        println!("posted to {channel} as cursor {}", res.cursor.unwrap_or(0));
    }
    Ok(0)
}

pub(crate) fn cmd_read(
    json: bool,
    channel: &str,
    since: Option<i64>,
    since_last: bool,
    save_cursor: bool,
    limit: u32,
) -> Result<i32> {
    validate_channel(channel)?;
    let client = RelayClient::from_env()?;
    let mut store = cursor_store(&client, since, since_last, save_cursor)?;
    let cursor = match (since, since_last) {
        (Some(s), _) => s,
        (None, true) => store.as_ref().expect("store is open for since_last").get(channel),
        (None, false) => 0,
    };
    let res = client.read(channel, cursor, limit)?;
    let final_cursor = res.cursor.unwrap_or(cursor);
    if let Some(mut store) = store.take() {
        if save_cursor {
            store.set(channel, final_cursor);
        }
        store.flush()?;
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&res)?);
        return Ok(0);
    }
    if res.messages.is_empty() {
        eprintln!("no messages in {channel} after cursor {cursor}");
        return Ok(0);
    }
    for m in &res.messages {
        println!("{}", render_message(&m.envelope.sender_id, m.cursor, &m.envelope.provenance, &m.envelope.body));
    }
    eprintln!("-- cursor {} --", final_cursor);
    Ok(0)
}

/// Poll loop.
///
/// Polling rather than a server push is a deliberate v1 choice. Presence means
/// "this process is alive and asking", which a poll establishes on its own, and
/// a push design would need the daemon to track subscriber connections and fan
/// out to them. If dogfooding shows staleness actually matters, the fix is a
/// long-lived subscription behind this same interface, not a change to the
/// protocol.
pub(crate) fn cmd_subscribe(
    json: bool,
    channel: &str,
    interval_ms: u64,
    since: Option<i64>,
    since_last: bool,
    save_cursor: bool,
    for_: Option<&str>,
    exit_on: Option<&str>,
    exit_on_json: Option<&str>,
    exit_on_task: Option<&str>,
    count: Option<u64>,
) -> Result<i32> {
    validate_channel(channel)?;
    let client = RelayClient::from_env()?;
    let interval = Duration::from_millis(interval_ms.max(10));
    let mut store = cursor_store(&client, since, since_last, save_cursor)?;

    // Without an explicit start, begin at the current end so a subscriber does
    // not replay history. That matches "presence = alive and asking".
    // `SINCE_CURRENT_END` is the daemon's documented way to ask for exactly that;
    // it answers with the real high-water mark rather than echoing the sentinel.
    let mut cursor = match (since, since_last) {
        (Some(s), _) => s,
        (None, true) => store.as_ref().expect("store is open for since_last").get(channel),
        (None, false) => client
            .read(channel, idboard_core::SINCE_CURRENT_END, 1)?
            .cursor
            .unwrap_or(0),
    };
    let deadline = for_.map(parse_duration_ms).transpose()?.map(|ms| Instant::now() + Duration::from_millis(ms));
    let exit_on_json = exit_on_json.map(parse_exit_on_json).transpose()?;
    let mut seen: u64 = 0;

    loop {
        if deadline.is_some_and(|at| Instant::now() >= at) {
            if let Some(mut store) = store {
                store.flush()?;
            }
            return Ok(0);
        }
        let res = client.read(channel, cursor, DEFAULT_READ_LIMIT)?;
        for m in &res.messages {
            let rendered = render_message(
                &m.envelope.sender_id,
                m.cursor,
                &m.envelope.provenance,
                &m.envelope.body,
            );
            if json {
                println!("{}", serde_json::to_string(m)?);
            } else {
                println!("{rendered}");
            }
            seen += 1;
            if let Some(store) = store.as_mut() {
                if save_cursor {
                    store.set(channel, m.cursor);
                }
            }
            if exit_on.is_some_and(|needle| m.envelope.body.contains(needle)) {
                if let Some(mut store) = store {
                    store.flush()?;
                }
                return Ok(0);
            }
            if exit_on_json.as_ref().is_some_and(|(key, value)| json_message_matches(&m.envelope.body, key, value)) {
                if let Some(mut store) = store {
                    store.flush()?;
                }
                return Ok(0);
            }
            if let Some(task_id) = exit_on_task {
                if !task_id.is_empty()
                    && let Some(ev) = trusted_task_event(&m)
                    && ev.kind == "done"
                    && ev.id == task_id
                {
                    if let Some(mut store) = store {
                        store.flush()?;
                    }
                    return Ok(0);
                }
            }
            if let Some(limit) = count {
                if seen >= limit {
                    if let Some(mut store) = store {
                        store.flush()?;
                    }
                    return Ok(0);
                }
            }
        }
        cursor = res.cursor.unwrap_or(cursor);
        if let Some(store) = store.as_mut() {
            if save_cursor {
                store.set(channel, cursor);
                store.flush()?;
            }
        }
        std::thread::sleep(interval);
    }
}

/// One screenful of "what is on this board and where do I stand".
///
/// This is the question a freshly launched agent actually has, and it costs one
/// signed request instead of one per channel. The daemon decides which channels
/// appear, so this can never show a channel the caller could not read.
pub(crate) fn cmd_inbox(json: bool, limit: u32, since_last: bool, save_cursor: bool) -> Result<i32> {
    let client = RelayClient::from_env()?;
    let mut res = client.inbox(limit)?;
    let mut store = cursor_store(&client, None, since_last, save_cursor)?;

    if let Some(store) = store.as_ref() {
        if since_last {
            res.channels.retain(|digest| digest.cursor > store.get(&digest.channel));
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&res)?);
    } else {
        if res.channels.is_empty() {
            eprintln!("no channels are visible to this identity");
        } else {
            for digest in &res.channels {
                let access = match (digest.can_read, digest.can_post) {
                    (true, true) => "read+post",
                    (true, false) => "read",
                    (false, true) => "post only",
                    (false, false) => continue,
                };
                println!(
                    "== {} == ({access}, cursor {})",
                    digest.channel, digest.cursor
                );
                for m in &digest.messages {
                    println!(
                        "{}",
                        render_message(&m.envelope.sender_id, m.cursor, &m.envelope.provenance, &m.envelope.body)
                    );
                }
                println!();
            }
        }
    }
    if let Some(mut store) = store.take() {
        if save_cursor {
            for digest in &res.channels {
                store.set(&digest.channel, digest.cursor);
            }
        }
        store.flush()?;
    }
    Ok(0)
}

/// Who is on the board. Presence is diagnostic: it is never an authorization
/// input, and a peer that has never been seen is still a valid peer.
pub(crate) fn cmd_peers(json: bool, since: Option<&str>, watch: bool, watch_interval_ms: u64) -> Result<i32> {
    let since_ms = since.map(parse_duration_ms).transpose()?;
    let interval = Duration::from_millis(watch_interval_ms.max(10));

    loop {
        let client = RelayClient::from_env()?;
        let res = client.peers()?;
        let now = idboard_core::now_ms();
        let mut peers = res.peers;
        if let Some(window) = since_ms {
            let cutoff = now.saturating_sub(window as i64);
            peers.retain(|peer| peer.last_seen_ms >= cutoff && peer.last_seen_ms > 0);
        }

        if json {
            // Diagnostic only; the filter is local presentation, not a protocol change.
            println!("{}", serde_json::json!({ "ok": res.ok, "peers": peers }));
        } else {
            for peer in &peers {
                println!(
                    "{:<16} {:<12} {}",
                    peer.identity,
                    peer.role,
                    last_seen_label(now, peer.last_seen_ms)
                );
            }
        }

        if !watch {
            return Ok(0);
        }
        println!("---");
        std::thread::sleep(interval);
    }
}

pub(crate) fn cmd_whoami(json: bool) -> Result<i32> {
    let client = RelayClient::from_env()?;
    let id = client.whoami()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&id)?);
    } else {
        println!("identity: {}", id.identity);
        println!("fingerprint: {}", id.fingerprint);
        println!("wrapper pid: {}", id.pid);
    }
    Ok(0)
}

pub(crate) fn cmd_run(args: RunArgs) -> Result<i32> {
    validate_identity(&args.identity)?;
    let opts = WrapperOptions::new(&args.identity, args.command);
    // `run_child` takes the identity lock itself, so a second wrapper for a live
    // identity fails there with exit code 2 rather than after spawning a child
    // that could never post.
    match wrapper::run_child(&opts) {
        Ok(code) => Ok(code),
        Err(e) => {
            eprintln!("keryx: {e}");
            Ok(e.exit_code())
        }
    }
}
