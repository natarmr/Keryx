//! operator commands.
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

/// Read-only aggregate for humans and agents.
///
/// Local checks always run. Board-visible state is included only inside a
/// wrapper, because board reads require the wrapper's signing path.
/// `--brief` collapses each refresh to one heartbeat-sized line and composes
/// with `--watch`, which re-prints until interrupted.
pub(crate) fn cmd_console(json: bool, limit: u32, brief: bool, watch: bool, watch_interval_ms: u64) -> Result<i32> {
    let interval = Duration::from_millis(watch_interval_ms.max(10));

    loop {
        let checks = collect_doctor_checks();
        let (problems, local_ok) = summarize_doctor_checks(&checks);
        let board = board_summary(limit);
        let ok = local_ok;

        if json {
            println!("{}", console_report_json(ok, &checks, &problems, &board));
        } else if brief {
            println!("{}", brief_line(ok, &board));
        } else {
            println!("keryx console: {}", if ok { "ok" } else { "attention" });
            println!("local:");
            for check in &checks {
                let name = check["name"].as_str().unwrap_or("check");
                let status = if check["ok"].as_bool().unwrap_or(false) { "ok" } else { "FAIL" };
                println!("  {status:<4} {name}: {}", check["detail"].as_str().unwrap_or(""));
            }
            if board["available"].as_bool().unwrap_or(false) {
                let identity = board["identity"].as_str().unwrap_or("unknown");
                println!("board:");
                println!("  identity: {identity}");
                println!("  channels: {}", board["channels"].as_array().map(|c| c.len()).unwrap_or(0));
                println!("  last message: {}", board["last_message_age"].as_str().unwrap_or("never"));
                println!(
                    "  tasks: {} open, {} claimed, {} done ({} active leases, {} expired)",
                    board["tasks"]["open"].as_u64().unwrap_or(0),
                    board["tasks"]["claimed"].as_u64().unwrap_or(0),
                    board["tasks"]["done"].as_u64().unwrap_or(0),
                    board["tasks"]["leases_active"].as_u64().unwrap_or(0),
                    board["tasks"]["leases_expired"].as_u64().unwrap_or(0)
                );
                let claimed_by = board["tasks"]["claimed_by"]
                    .as_object()
                    .map(|object| {
                        object
                            .iter()
                            .map(|(who, n)| format!("{who}={n}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                if !claimed_by.is_empty() {
                    println!("  claimed by: {claimed_by}");
                }
                if let Some(oldest) = board["tasks"]["oldest_unclaimed"].as_object() {
                    println!(
                        "  oldest unclaimed: {} {} in {}",
                        oldest["id"].as_str().unwrap_or("?"),
                        oldest["title"].as_str().unwrap_or("?"),
                        oldest["channel"].as_str().unwrap_or("?")
                    );
                }
                let recent = board["recent"].as_array().map(|v| v.as_slice()).unwrap_or(&[]);
                if !recent.is_empty() {
                    println!("  recent messages:");
                    for m in recent {
                        println!(
                            "    [{} cursor {}] {}",
                            m["channel"].as_str().unwrap_or("?"),
                            m["cursor"].as_i64().unwrap_or(0),
                            render_message(
                                m["sender"].as_str().unwrap_or("?"),
                                m["cursor"].as_i64().unwrap_or(0),
                                &Provenance::SelfOriginated,
                                m["body"].as_str().unwrap_or(""),
                            )
                        );
                    }
                }
            } else {
                println!("board: unavailable outside `keryx run`; local summary still shown");
            }
        }
        if !watch {
            return Ok(if ok { 0 } else { 1 });
        }
        println!("---");
        std::thread::sleep(interval);
    }
}

pub(crate) fn cmd_web(json: bool, bind: &str, once: bool) -> Result<i32> {
    if !web_bind_is_loopback(bind) {
        return Err(idboard_core::error::CoreError::bad_request(
            "--bind must be a loopback address (127.0.0.1, ::1 or localhost); the console is local/read-only",
        ));
    }

    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind(bind).map_err(|e| {
        idboard_core::error::CoreError::internal(format!("failed to bind web console at {bind}: {e}"))
    })?;
    let local = listener.local_addr().map_err(|e| {
        idboard_core::error::CoreError::internal(format!("failed to read web console address: {e}"))
    })?;
    // The string check above is not the control: `--bind localhost:8080` resolves
    // through the system resolver, so the *resolved* address is what must be
    // loopback. Refuse rather than serve a console the operator did not intend.
    if !local.ip().is_loopback() {
        return Err(idboard_core::error::CoreError::bad_request(format!(
            "web console resolved {bind} to {}, which is not a loopback address; refusing to serve",
            local.ip()
        )));
    }
    // The console token is the only credential on this surface, so it gets the
    // full 32 bytes the relay token uses rather than the 8-byte socket suffix.
    let token = idboard::relay::generate_token()?;
    let url = format!("http://{local}/{token}/");
    if json {
        println!("{}", serde_json::json!({ "ok": true, "url": url }));
    } else {
        println!("web console: {url}");
        println!("read-only; served only on loopback; leave this process running (Ctrl-C to stop).");
    }

    let mut count = 0;
    loop {
        let Ok((mut socket, _)) = listener.accept() else { continue };
        socket.set_read_timeout(Some(Duration::from_secs(3))).ok();
        let mut request = Vec::with_capacity(2048);
        let mut buf = [0u8; 2048];
        loop {
            let read = match socket.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            request.extend_from_slice(&buf[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") || request.len() > 8192 {
                break;
            }
        }
        let Ok(request_text) = std::str::from_utf8(&request) else {
            let _ = socket.write_all(b"HTTP/1.0 400 Bad Request\r\ncontent-length: 11\r\n\r\nbad request\n");
            if once {
                return Ok(0);
            }
            continue;
        };
        let method = request_text.split_whitespace().next().unwrap_or("");
        let (status, content_type, body) = response_for_request(request_text, &token, 5, &local.to_string());
        let status_line = match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            405 => "Method Not Allowed",
            _ => "Error",
        };
        let head_body = if method == "HEAD" { Vec::new() } else { body };
        let response = format!(
            "HTTP/1.0 {status} {status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\r\n",
            head_body.len()
        );
        let _ = socket.write_all(response.as_bytes());
        let _ = socket.write_all(&head_body);
        count += 1;
        if once && count >= 1 {
            return Ok(0);
        }
    }
}

/// `strict` additionally fails on operator warnings (role-inheritance
/// grants), so CI can gate on them. Without it, warnings are informational.
pub(crate) fn cmd_doctor(json: bool, strict: bool) -> Result<i32> {
    let mut checks = collect_doctor_checks();
    if strict {
        // Role warnings need the config; collect_doctor_checks already loaded
        // it for the `config` check, so re-load is cheap and keeps this pure.
        if let Ok(config) = idboard_acl::Config::load(&layout::config_path()) {
            for warning in config.role_inheritance_warnings() {
                checks.push(serde_json::json!({ "name": "role-warning", "ok": false, "detail": warning }));
            }
        }
    }
    let (problems, ok) = summarize_doctor_checks(&checks);
    if json {
        println!("{}", serde_json::json!({
            "ok": ok,
            "report_version": 1,
            "checks": checks,
            "problems": problems,
        }));
    } else {
        println!("keryx doctor: {}", if ok { "ok" } else { "failed" });
        for check in checks {
            let name = check["name"].as_str().unwrap_or("check");
            let status = if check["ok"].as_bool().unwrap_or(false) { "ok" } else { "FAIL" };
            println!("{status:<4} {name}: {}", check["detail"].as_str().unwrap_or(""));
        }
    }
    Ok(if ok { 0 } else { 1 })
}

pub(crate) fn cmd_admin(json: bool, command: Option<AdminCommand>) -> Result<i32> {
    match command.unwrap_or(AdminCommand::Report) {
        AdminCommand::Report => cmd_admin_report(json),
        AdminCommand::Recent { limit, channel } => cmd_admin_recent(json, limit, channel.as_deref()),
    }
}

pub(crate) fn cmd_admin_report(json: bool) -> Result<i32> {
    let path = layout::config_path();
    let config = idboard_acl::Config::load(&path).map_err(|e| {
        idboard_core::error::CoreError::internal(format!(
            "cannot load config at {}: {e}",
            path.display()
        ))
    })?;
    let key_status = admin_key_status(&config);
    let report = admin_report_value(&config, &key_status);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("keryx admin report: {} identities, {} channels", config.identity_count(), report["channels"].as_array().map(|c| c.len()).unwrap_or(0));
        for id in report["identities"].as_array().map(|v| v.as_slice()).unwrap_or(&[]) {
            let key = match (id["key_present"].as_bool(), id["key_matches_config"].as_bool()) {
                (Some(true), Some(true)) => "key=match",
                (Some(true), _) => "key=MISMATCH",
                _ => "key=missing",
            };
            let force = if id["force_external"].as_bool().unwrap_or(false) {
                " force_external=true"
            } else {
                ""
            };
            println!(
                "  {:<16} role={:<12} fp={} {key}{force}",
                id["identity"].as_str().unwrap_or("?"),
                id["role"].as_str().unwrap_or("?"),
                id["fingerprint"].as_str().unwrap_or("?")
            );
        }
        for c in report["channels"].as_array().map(|v| v.as_slice()).unwrap_or(&[]) {
            println!(
                "  {:<20} post=[{}] read=[{}] allow_external={}",
                c["channel"].as_str().unwrap_or("?"),
                c["post"].as_array().map(|g| g.iter().filter_map(|g| g.as_str()).collect::<Vec<_>>().join(" ")).unwrap_or_default(),
                c["read"].as_array().map(|g| g.iter().filter_map(|g| g.as_str()).collect::<Vec<_>>().join(" ")).unwrap_or_default(),
                c["allow_external"].as_bool().unwrap_or(true)
            );
        }
        let limits = &report["limits"];
        if limits["unlimited"].as_bool().unwrap_or(true) {
            println!("  limits: none");
        } else {
            println!(
                "  limits: {} posts per identity per {}s",
                limits["posts_per_window"].as_u64().unwrap_or(0),
                limits["window_ms"].as_u64().unwrap_or(0) / 1000
            );
        }
        for w in report["role_warnings"].as_array().map(|v| v.as_slice()).unwrap_or(&[]) {
            println!("  warning: {}", w.as_str().unwrap_or(""));
        }
    }
    Ok(0)
}

pub(crate) fn cmd_admin_recent(json: bool, limit: u32, channel: Option<&str>) -> Result<i32> {
    if let Some(channel) = channel {
        validate_channel(channel)?;
    }
    let client = RelayClient::from_env()?;
    // `inbox` reports the newest page per channel plus each channel's cursor,
    // all under the same authorisation a real read uses. A filtered view is a
    // local projection of that digest, not a second permission model.
    let inbox = client.inbox(limit.max(1))?;
    let mut digests = inbox.channels;
    if let Some(channel) = channel {
        digests.retain(|digest| digest.channel == channel);
        let Some(digest) = digests.pop() else {
            return Err(idboard_core::error::CoreError::new(
                idboard_core::ErrorCode::UnknownChannel,
                format!("no visible channel {channel:?}; see `keryx inbox --limit 0` for what this identity may see"),
            ));
        };
        if !digest.can_read {
            return Err(idboard_core::error::CoreError::new(
                idboard_core::ErrorCode::Unauthorized,
                format!("this identity may not read {channel:?}"),
            ));
        }
        // Reuse the read path for the payload so the bytes come from the same
        // authorised, bounded page a `read` would return.
        let start = recent_window_start(digest.cursor, limit.max(1));
        let res = client.read(channel, start, limit.max(1))?;
        if json {
            println!("{}", serde_json::json!({
                "ok": true,
                "channel": channel,
                "cursor": res.cursor,
                "messages": res.messages,
            }));
        } else if res.messages.is_empty() {
            eprintln!("no messages in {channel}");
        } else {
            for m in &res.messages {
                println!("{}", render_message(&m.envelope.sender_id, m.cursor, &m.envelope.provenance, &m.envelope.body));
            }
            eprintln!("-- cursor {} --", res.cursor.unwrap_or(start));
        }
        return Ok(0);
    }
    let mut recent: Vec<(i64, serde_json::Value)> = Vec::new();
    for digest in &digests {
        if !digest.can_read {
            continue;
        }
        for m in &digest.messages {
            recent.push((
                m.cursor,
                serde_json::json!({
                    "channel": digest.channel,
                    "cursor": m.cursor,
                    "sender": m.envelope.sender_id,
                    "body": m.envelope.body,
                }),
            ));
        }
    }
    recent.sort_by(|a, b| b.0.cmp(&a.0));
    let recent: Vec<_> = recent.into_iter().take(limit as usize).map(|(_, v)| v).collect();
    if json {
        println!("{}", serde_json::json!({ "ok": true, "messages": recent }));
    } else if recent.is_empty() {
        eprintln!("no recent messages");
    } else {
        for m in &recent {
            println!(
                "[{} cursor {}] {}",
                m["channel"].as_str().unwrap_or("?"),
                m["cursor"].as_i64().unwrap_or(0),
                render_message(
                    m["sender"].as_str().unwrap_or("?"),
                    m["cursor"].as_i64().unwrap_or(0),
                    &Provenance::SelfOriginated,
                    m["body"].as_str().unwrap_or(""),
                )
            );
        }
    }
    Ok(0)
}

/// Show or manage this process' saved local cursor for a channel.
///
/// Read-only parts of the operation never touch the relay; mutating parts only
/// update the local file. Nothing here is consulted by the daemon.
pub(crate) fn cmd_cursor(json: bool, channel: &str, clear: bool, set: Option<i64>) -> Result<i32> {
    validate_channel(channel)?;
    if clear && set.is_some() {
        return Err(idboard_core::error::CoreError::bad_request("pass either --clear or --set, not both"));
    }
    if let Some(cursor) = set {
        if cursor < 0 {
            return Err(idboard_core::error::CoreError::bad_request("cursor must be non-negative"));
        }
        let identity = RelayClient::from_env()?.whoami()?.identity;
        let mut store = CursorStore::for_identity(&identity)?;
        store.set(channel, cursor);
        store.flush()?;
        if json {
            println!("{}", serde_json::json!({ "channel": channel, "cursor": cursor, "cleared": false }));
        } else {
            println!("cursor[{channel}] set to {cursor}");
        }
        return Ok(0);
    }
    if clear {
        let identity = RelayClient::from_env()?.whoami()?.identity;
        let mut store = CursorStore::for_identity(&identity)?;
        store.remove(channel);
        store.flush()?;
        if json {
            println!("{}", serde_json::json!({ "channel": channel, "cleared": true }));
        } else {
            println!("cursor[{channel}] cleared");
        }
        return Ok(0);
    }

    let identity = RelayClient::from_env()?.whoami()?.identity;
    match CursorStore::for_identity(&identity) {
        Ok(store) => {
            let cursor = store.get(channel);
            if json {
                println!("{}", serde_json::json!({ "ok": true, "channel": channel, "cursor": cursor }));
            } else {
                println!("cursor[{channel}] = {cursor}");
            }
            Ok(0)
        }
        Err(e) => {
            if json {
                println!("{}", serde_json::json!({ "ok": false, "channel": channel, "error": e.code.as_str(), "detail": e.detail }));
                Ok(1)
            } else {
                Err(e)
            }
        }
    }
}

/// Substring search over message bodies via the existing read API.
///
/// Channels are small on a local bus, so each readable channel is read from
/// the start (`read(channel, 0, 1000)`, the daemon's maximum read) and
/// filtered client-side. No daemon change: this is a convenience over `read`.
pub(crate) fn cmd_search(json: bool, query: &str, channel: Option<&str>, limit: u32) -> Result<i32> {
    if query.is_empty() {
        return Err(idboard_core::error::CoreError::bad_request(
            "search query must not be empty",
        ));
    }
    if let Some(channel) = channel {
        validate_channel(channel)?;
    }
    let client = RelayClient::from_env()?;
    let channels = match channel {
        Some(channel) => vec![channel.to_string()],
        None => visible_readable_channels(&client)?,
    };
    let cap = if limit == 0 { 0 } else { limit as usize };
    let mut hits = Vec::new();
    for channel in &channels {
        let res = client.read(channel, 0, 1000)?;
        let mut channel_hits = collect_search_hits(channel, &res.messages, query, 0);
        if cap > 0 {
            let remaining = cap.saturating_sub(hits.len());
            if remaining == 0 {
                break;
            }
            channel_hits.truncate(remaining);
        }
        hits.extend(channel_hits);
        if cap > 0 && hits.len() >= cap {
            break;
        }
    }

    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "query": query,
                "matches": hits.iter().map(|h| serde_json::json!({
                    "channel": h.channel,
                    "cursor": h.cursor,
                    "sender": h.sender,
                    "body": h.body,
                })).collect::<Vec<_>>(),
            })
        );
        return Ok(0);
    }
    if hits.is_empty() {
        eprintln!("no messages matching {query:?}");
        return Ok(0);
    }
    for hit in &hits {
        println!(
            "[{} #{}] {}",
            hit.channel,
            hit.cursor,
            render_message(&hit.sender, hit.cursor, &Provenance::SelfOriginated, &hit.body)
        );
    }
    Ok(0)
}

/// Show the messages around an anchor cursor via the existing read API.
///
/// The channel is read from the start (`read(channel, 0, 1000)`, the daemon's
/// maximum read) and sliced client-side into a `before`/`after` window. `around`
/// calls this with `before == after == radius`. No daemon change.
pub(crate) fn cmd_thread(json: bool, channel: &str, cursor: i64, before: u32, after: u32) -> Result<i32> {
    validate_channel(channel)?;
    if cursor <= 0 {
        return Err(idboard_core::error::CoreError::bad_request(
            "thread cursor must be positive",
        ));
    }
    let client = RelayClient::from_env()?;
    let res = client.read(channel, 0, 1000)?;
    let window = thread_window(&res.messages, cursor, before as usize, after as usize);

    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "channel": channel,
                "cursor": cursor,
                "before": before,
                "after": after,
                "messages": window,
            })
        );
        return Ok(0);
    }
    if window.is_empty() {
        eprintln!("no messages in {channel} around cursor {cursor}");
        return Ok(0);
    }
    for m in window {
        let marker = if m.cursor == cursor { ">" } else { " " };
        println!(
            "{marker} {}",
            render_message(&m.envelope.sender_id, m.cursor, &m.envelope.provenance, &m.envelope.body)
        );
    }
    Ok(0)
}

pub(crate) fn cmd_keygen(identity: &str, pubkey_only: bool, dry_run: bool, force: bool) -> Result<i32> {
    validate_identity(identity)?;
    if dry_run && force {
        return Err(idboard_core::error::CoreError::bad_request(
            "pass either --dry-run or --force, not both",
        ));
    }

    // Validate-only: generate in memory, report what WOULD be registered,
    // write nothing.
    if dry_run {
        let (signer, _) = idboard_core::keys::LocalSigner::generate(identity)?;
        if pubkey_only {
            println!("{}", signer.public_hex());
        } else {
            print_key_dry_run(&signer, identity);
        }
        return Ok(0);
    }

    // Refuse to clobber an existing key unless --force was given. Overwriting
    // would silently change the identity's key while the config still names the
    // old one, and the symptom is a daemon that rejects everything with
    // `bad_signature`.
    let keystore = Keystore::standard();
    if let Some(existing) = keystore.load_seed(identity)? {
        if !force {
            if pubkey_only {
                let signer = idboard_core::keys::LocalSigner::from_seed(&existing, identity)?;
                println!("{}", signer.public_hex());
                return Ok(0);
            }
            return Err(idboard::keystore::KeystoreError::AlreadyExists {
                identity: identity.to_string(),
                path: keystore.key_path(identity).display().to_string(),
            }
            .into());
        }
        // --force: rotation. Load the old public key first so the operator sees
        // what is being replaced, warn loudly, then remove-then-create so the
        // new seed still goes through the atomic link path in `save_seed`
        // (never rename-overwrite).
        let old_signer = idboard_core::keys::LocalSigner::from_seed(&existing, identity)?;
        eprintln!(
            "rotating key for {identity:?}: old pubkey {} fingerprint {} will stop verifying; \
             update the config pubkey and restart the daemon after this.",
            old_signer.public_hex(),
            old_signer.fingerprint()
        );
        std::fs::remove_file(keystore.key_path(identity)).map_err(|source| {
            idboard_core::error::CoreError::internal(format!(
                "failed to remove old key for rotation at {}: {source}",
                keystore.key_path(identity).display()
            ))
        })?;
        let (signer, seed) = idboard_core::keys::LocalSigner::generate(identity)?;
        keystore.save_seed(identity, &seed)?;
        if pubkey_only {
            println!("{}", signer.public_hex());
        } else {
            print_key_rotated(&signer, identity, &old_signer);
        }
        return Ok(0);
    }

    let (signer, seed) = idboard_core::keys::LocalSigner::generate(identity)?;
    keystore.save_seed(identity, &seed)?;
    if pubkey_only {
        println!("{}", signer.public_hex());
    } else {
        print_key(&signer, identity, true);
    }
    Ok(0)
}

pub(crate) fn cmd_instructions(json: bool, harness: HarnessArg, identity: Option<&str>) -> Result<i32> {
    if let Some(name) = identity {
        validate_identity(name)?;
    }
    let name = identity.unwrap_or("<identity>");
    let text = instructions_text(harness, name);

    if json {
        println!(
            "{}",
            serde_json::json!({ "harness": harness.as_str(), "identity": name, "instructions": text })
        );
    } else {
        println!("{text}");
    }
    Ok(0)
}
