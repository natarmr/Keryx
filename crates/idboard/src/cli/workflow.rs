//! workflow commands.
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

pub(crate) fn ensure_task_write_allowed(client: &RelayClient) -> Result<()> {
    let who = client.whoami()?;
    if who.force_external {
        return Err(idboard_core::error::CoreError::new(
            idboard_core::error::ErrorCode::ProvenanceRejected,
            format!(
                "identity {:?} has force_external=true; task events from this identity are stored as external and ignored by the task fold. Task create/claim/complete/link are no-ops for this identity; use a non-fetcher identity for tasks",
                who.identity
            ),
        ));
    }
    Ok(())
}

pub(crate) fn cmd_task(json: bool, command: Option<TaskCommand>) -> Result<i32> {
    let command = command.unwrap_or(TaskCommand::List { channel: None, open: true, all: false, mine: false, stale: None });
    match command {
        TaskCommand::Create { channel, title, body } => {
            validate_channel(&channel)?;
            if title.trim().is_empty() || title.len() > 256 {
                return Err(idboard_core::error::CoreError::bad_request(
                    "task title must be non-empty and at most 256 bytes",
                ));
            }
            if let Some(body) = &body {
                validate_body(body)?;
            }
            let task_id = format!("t-{:x}-{}", idboard_core::now_ms(), std::process::id());
            let event = serde_json::json!({
                "v": 1,
                "id": task_id.clone(),
                "kind": "create",
                "title": title,
                "body": body,
            });
            let body = format!("task:{}", event);
            validate_body(&body)?;
            let client = RelayClient::from_env()?;
            if let Err(e) = ensure_task_write_allowed(&client) {
                if json {
                    println!("{}", serde_json::json!({ "ok": false, "error": e.code.as_str(), "detail": e.detail }));
                    return Ok(1);
                }
                return Err(e);
            }
            let res = match client.post(&channel, &body, Provenance::SelfOriginated) {
                Ok(res) => res,
                Err(e) => {
                    if json {
                        println!("{}", serde_json::json!({
                            "ok": false,
                            "error": e.code.as_str(),
                            "detail": e.detail,
                            "retry_after_ms": e.retry_after_ms,
                        }));
                        return Ok(1);
                    }
                    return Err(e);
                }
            };
            if json {
                println!("{}", serde_json::json!({
                    "ok": true,
                    "task_id": task_id,
                    "channel": channel,
                    "cursor": res.cursor,
                }));
            } else {
                println!("created task {task_id} in {channel} as cursor {}", res.cursor.unwrap_or(0));
            }
            Ok(0)
        }
        TaskCommand::Claim { channel, task_id, lease } => {
            validate_channel(&channel)?;
            let lease_ms = lease.as_deref().map(parse_duration_ms).transpose()?;
            {
                let client = RelayClient::from_env()?;
                if let Err(e) = ensure_task_write_allowed(&client) {
                    if json {
                        println!("{}", serde_json::json!({ "ok": false, "error": e.code.as_str(), "detail": e.detail }));
                        return Ok(1);
                    }
                    return Err(e);
                }
            }
            let mut event = serde_json::json!({ "v": 1, "id": task_id, "kind": "claim" });
            if let Some(lease_ms) = lease_ms {
                event["lease_ms"] = serde_json::json!(lease_ms);
                event["claimed_at_ms"] = serde_json::json!(idboard_core::now_ms());
            }
            super::bus::cmd_post(json, &channel, &format!("task:{}", event), Provenance::SelfOriginated)
        }
        TaskCommand::Done { channel, task_id } => {
            validate_channel(&channel)?;
            {
                let client = RelayClient::from_env()?;
                if let Err(e) = ensure_task_write_allowed(&client) {
                    if json {
                        println!("{}", serde_json::json!({ "ok": false, "error": e.code.as_str(), "detail": e.detail }));
                        return Ok(1);
                    }
                    return Err(e);
                }
            }
            let body = serde_json::json!({ "v": 1, "id": task_id, "kind": "done", "result": "ok" });
            super::bus::cmd_post(json, &channel, &format!("task:{}", body), Provenance::SelfOriginated)
        }
        TaskCommand::Link { channel, task_id, depends_on } => {
            validate_channel(&channel)?;
            if task_id.trim().is_empty() || depends_on.trim().is_empty() {
                return Err(idboard_core::error::CoreError::bad_request(
                    "task link needs a non-empty task id and prerequisite id",
                ));
            }
            if task_id == depends_on {
                return Err(idboard_core::error::CoreError::bad_request(
                    "a task cannot depend on itself",
                ));
            }
            {
                let client = RelayClient::from_env()?;
                if let Err(e) = ensure_task_write_allowed(&client) {
                    if json {
                        println!("{}", serde_json::json!({ "ok": false, "error": e.code.as_str(), "detail": e.detail }));
                        return Ok(1);
                    }
                    return Err(e);
                }
            }
            let body = serde_json::json!({ "v": 1, "id": task_id, "kind": "link", "depends_on": depends_on });
            super::bus::cmd_post(json, &channel, &format!("task:{}", body), Provenance::SelfOriginated)
        }
        TaskCommand::Ready { channel, mine } => {
            if channel.as_ref().is_some_and(|channel| validate_channel(channel).is_err()) {
                return Err(idboard_core::error::CoreError::bad_request("invalid channel"));
            }
            let client = RelayClient::from_env()?;
            let channels = match channel {
                Some(channel) => vec![channel],
                None => visible_readable_channels(&client)?,
            };
            let (identity, records) = load_tasks(&client, &channels)?;
            let mut ready: Vec<_> = ready_tasks(&records)
                .into_iter()
                .filter(|record| {
                    !mine
                        || record.view.created_by == identity
                        || record.view.claimed_by.as_deref() == Some(identity.as_str())
                })
                .collect();
            ready.sort_by_key(|record| record.create_cursor);
            if json {
                let tasks: Vec<serde_json::Value> = ready.iter().map(|record| task_json(record)).collect();
                println!("{}", serde_json::json!({ "tasks": tasks }));
            } else if ready.is_empty() {
                eprintln!("no ready tasks");
            } else {
                for record in ready {
                    let claimed = record.view.claimed_by.as_deref().unwrap_or("unclaimed");
                    println!(
                        "open {} {} {} (creator {}, claimed {claimed})",
                        record.channel, record.view.id, record.view.title, record.view.created_by
                    );
                }
            }
            Ok(0)
        }
        TaskCommand::Reopen { channel, task_id } => {
            validate_channel(&channel)?;
            {
                let client = RelayClient::from_env()?;
                if let Err(e) = ensure_task_write_allowed(&client) {
                    if json {
                        println!("{}", serde_json::json!({ "ok": false, "error": e.code.as_str(), "detail": e.detail }));
                        return Ok(1);
                    }
                    return Err(e);
                }
            }
            let body = serde_json::json!({ "v": 1, "id": task_id, "kind": "reopen" });
            super::bus::cmd_post(json, &channel, &format!("task:{}", body), Provenance::SelfOriginated)
        }
        TaskCommand::Abandon { channel, task_id } => {
            validate_channel(&channel)?;
            {
                let client = RelayClient::from_env()?;
                if let Err(e) = ensure_task_write_allowed(&client) {
                    if json {
                        println!("{}", serde_json::json!({ "ok": false, "error": e.code.as_str(), "detail": e.detail }));
                        return Ok(1);
                    }
                    return Err(e);
                }
            }
            let body = serde_json::json!({ "v": 1, "id": task_id, "kind": "abandon" });
            super::bus::cmd_post(json, &channel, &format!("task:{}", body), Provenance::SelfOriginated)
        }
        TaskCommand::Reclaim { channel, task_id } => {
            validate_channel(&channel)?;
            {
                let client = RelayClient::from_env()?;
                if let Err(e) = ensure_task_write_allowed(&client) {
                    if json {
                        println!("{}", serde_json::json!({ "ok": false, "error": e.code.as_str(), "detail": e.detail }));
                        return Ok(1);
                    }
                    return Err(e);
                }
            }
            let body = serde_json::json!({ "v": 1, "id": task_id, "kind": "reclaim" });
            super::bus::cmd_post(json, &channel, &format!("task:{}", body), Provenance::SelfOriginated)
        }
        TaskCommand::List { channel, open: _, all, mine, stale } => {
            if channel.as_ref().is_some_and(|channel| validate_channel(channel).is_err()) {
                return Err(idboard_core::error::CoreError::bad_request("invalid channel"));
            }
            let stale_ms = stale.as_deref().map(parse_watch_duration_ms).transpose()?;
            let client = RelayClient::from_env()?;
            let channels = match channel {
                Some(channel) => vec![channel],
                None => visible_readable_channels(&client)?,
            };
            let (identity, mut records) = load_tasks(&client, &channels)?;
            if !all {
                records.retain(|record| !record.view.done);
            }
            if mine {
                records.retain(|record| {
                    record.view.created_by == identity || record.view.claimed_by.as_deref() == Some(identity.as_str())
                });
            }
            if let Some(threshold) = stale_ms {
                let now_ms = idboard_core::now_ms();
                records.retain(|record| {
                    let claimed = record.view.claimed_by.is_some();
                    is_unclaimed_stale(record.created_at_ms, record.view.done, claimed, now_ms, threshold)
                        || is_claim_stalled(record.claimed_at_ms, claimed, record.view.done, now_ms, threshold)
                });
            }
            if json {
                let tasks: Vec<serde_json::Value> = records.iter().map(task_json).collect();
                println!("{}", serde_json::json!({ "tasks": tasks }));
            } else if records.is_empty() {
                eprintln!("no tasks");
            } else {
                let done_by_id: std::collections::HashMap<String, bool> =
                    records.iter().map(|record| (record.view.id.clone(), record.view.done)).collect();
                for record in &records {
                    let claimed = record.view.claimed_by.as_deref().unwrap_or("unclaimed");
                    let status = if record.view.done {
                        "done"
                    } else if task_is_blocked(&record, &done_by_id) {
                        "blocked"
                    } else {
                        "open"
                    };
                    println!(
                        "{status} {} {} {} (creator {}, claimed {claimed})",
                        record.channel,
                        record.view.id,
                        record.view.title,
                        record.view.created_by
                    );
                }
            }
            Ok(0)
        }
        TaskCommand::Next { channel } => {
            if channel.as_ref().is_some_and(|channel| validate_channel(channel).is_err()) {
                return Err(idboard_core::error::CoreError::bad_request("invalid channel"));
            }
            let client = RelayClient::from_env()?;
            let channels = match channel {
                Some(channel) => vec![channel],
                None => visible_readable_channels(&client)?,
            };
            let (_, records) = load_tasks(&client, &channels)?;
            // Blocked tasks are skipped: `task ready` (or finishing the
            // prerequisites) is how they become actionable.
            let next = ready_tasks(&records).into_iter().find(|record| record.view.claimed_by.is_none());
            if json {
                println!("{}", match &next {
                    Some(record) => serde_json::json!({ "next": task_json(record) }),
                    None => serde_json::json!({ "next": serde_json::Value::Null }),
                });
                return Ok(0);
            }
            let Some(next) = next else {
                eprintln!("no unblocked, unclaimed open tasks (use `task list` to see blocked ones)");
                return Ok(0);
            };
            println!("next task {} in {}: {}", next.view.id, next.channel, next.view.title);
            println!("claim: keryx task claim {} {}", next.channel, next.view.id);
            Ok(0)
        }
        TaskCommand::Complete { channel, task_id, body, body_file, result, note } => {
            validate_channel(&channel)?;
            if let Some(note) = &note {
                validate_body(note)?;
            }
            if let Some(result) = &result {
                if !matches!(result.as_str(), "ok" | "blocked" | "failed") {
                    return Err(idboard_core::error::CoreError::bad_request(
                        "result must be one of ok, blocked, failed",
                    ));
                }
            }
            let body = read_body(body.as_deref(), body_file.as_deref())?;
            let client = RelayClient::from_env()?;
            if let Err(e) = ensure_task_write_allowed(&client) {
                return json_or_result_error(json, &e);
            }
            let post_body = |body: &str| client.post(&channel, body, Provenance::SelfOriginated);
            let report = match post_body(&body) {
                Ok(res) => res,
                Err(e) => return json_or_result_error(json, &e),
            };
            let mut done_event = serde_json::json!({ "v": 1, "id": task_id, "kind": "done" });
            if let Some(result) = result {
                done_event["result"] = serde_json::json!(result);
            }
            if let Some(note) = note {
                done_event["note"] = serde_json::json!(note);
            }
            let done_body = format!("task:{done_event}");
            let done = match post_body(&done_body) {
                Ok(res) => res,
                Err(e) => return json_or_result_error(json, &e),
            };
            if json {
                println!("{}", serde_json::json!({
                    "ok": true,
                    "task_id": task_id,
                    "report_cursor": report.cursor,
                    "done_cursor": done.cursor,
                }));
            } else {
                println!(
                    "posted report as cursor {} and marked task {task_id} done as cursor {}",
                    report.cursor.unwrap_or(0),
                    done.cursor.unwrap_or(0)
                );
            }
            Ok(0)
        }
    }
}

/// Single-evaluation watch: read task state like `task list` does and report
/// staleness locally. No push, no new socket, no daemon change.
pub(crate) fn cmd_watch(
    json: bool,
    unclaimed_longer_than: Option<&str>,
    claimed_without_progress: Option<&str>,
    channel: Option<&str>,
    watch: bool,
    watch_interval_ms: u64,
) -> Result<i32> {
    if unclaimed_longer_than.is_none() && claimed_without_progress.is_none() {
        return Err(idboard_core::error::CoreError::bad_request(
            "pass --unclaimed-longer-than and/or --claimed-without-progress, e.g. --unclaimed-longer-than 30m",
        ));
    }
    let unclaimed_threshold = unclaimed_longer_than.map(parse_watch_duration_ms).transpose()?;
    let claimed_threshold = claimed_without_progress.map(parse_watch_duration_ms).transpose()?;
    if let Some(name) = channel {
        validate_channel(name)?;
    }
    let interval = Duration::from_millis(watch_interval_ms.max(10));

    // The read-and-filter path is identical on every evaluation, single or
    // looped, so `--watch` output never disagrees with the one-shot check.
    loop {
        let client = RelayClient::from_env()?;
        let channels = match channel {
            Some(name) => vec![name.to_string()],
            None => visible_readable_channels(&client)?,
        };
        let (_, records) = load_tasks(&client, &channels)?;
        let now_ms = idboard_core::now_ms();
        let stale = select_stale_tasks(&records, now_ms, unclaimed_threshold, claimed_threshold);

        if json {
            let entries: Vec<serde_json::Value> = stale.iter().map(stale_alert_json).collect();
            println!("{}", serde_json::json!({ "stale": entries, "now_ms": now_ms }));
        } else if stale.is_empty() {
            eprintln!("no stale tasks");
        } else {
            for alert in &stale {
                println!(
                    "stale[{}] {} {} {} age_ms={}",
                    alert.reason, alert.record.channel, alert.record.view.id, alert.record.view.title, alert.age_ms
                );
            }
        }

        if !watch {
            return Ok(i32::from(!stale.is_empty()));
        }
        println!("---");
        std::thread::sleep(interval);
    }
}

/// Agent heartbeat: one actionable summary per run.
///
/// Read-only. Reports the tasks this identity holds, the next unclaimed ready
/// task, and anything stale (when thresholds are given), plus a single
/// recommendation an agent or supervisor loop can act on without parsing prose.
pub(crate) fn cmd_heartbeat(
    json: bool,
    unclaimed_longer_than: Option<&str>,
    claimed_without_progress: Option<&str>,
) -> Result<i32> {
    let unclaimed_threshold = unclaimed_longer_than.map(parse_watch_duration_ms).transpose()?;
    let claimed_threshold = claimed_without_progress.map(parse_watch_duration_ms).transpose()?;
    let client = RelayClient::from_env()?;
    let channels = visible_readable_channels(&client)?;
    let (identity, records) = load_tasks(&client, &channels)?;
    let now_ms = idboard_core::now_ms();

    let mut my_claimed: Vec<&TaskRecord> = records
        .iter()
        .filter(|record| {
            !record.view.done && record.view.claimed_by.as_deref() == Some(identity.as_str())
        })
        .collect();
    my_claimed.sort_by_key(|record| record.create_cursor);

    let next = ready_tasks(&records).into_iter().find(|record| record.view.claimed_by.is_none());
    let stale = select_stale_tasks(&records, now_ms, unclaimed_threshold, claimed_threshold);

    // The recommendation is a machine-readable action: continue what this
    // identity already holds, claim the next ready task, or stay idle.
    let recommendation = if let Some(task) = my_claimed.first() {
        serde_json::json!({ "action": "continue", "channel": task.channel, "id": task.view.id, "title": task.view.title })
    } else if let Some(task) = next {
        serde_json::json!({
            "action": "claim",
            "channel": task.channel,
            "id": task.view.id,
            "title": task.view.title,
            "command": format!("keryx task claim {} {}", task.channel, task.view.id),
        })
    } else {
        serde_json::json!({ "action": "idle" })
    };

    if json {
        println!("{}", serde_json::json!({
            "identity": identity,
            "my_claimed_tasks": my_claimed.iter().map(|record| task_json(record)).collect::<Vec<_>>(),
            "next": next.map(|record| task_json(record)),
            "stale": stale.iter().map(stale_alert_json).collect::<Vec<_>>(),
            "recommendation": recommendation,
        }));
        return Ok(0);
    }

    println!("heartbeat: {identity}");
    println!("my claimed tasks: {}", my_claimed.len());
    for task in &my_claimed {
        println!("  continue {} {} {}", task.channel, task.view.id, task.view.title);
    }
    match next {
        Some(task) => {
            println!("next: {} {} {}", task.channel, task.view.id, task.view.title);
            println!("claim: keryx task claim {} {}", task.channel, task.view.id);
        }
        None => println!("next: no actionable work"),
    }
    if stale.is_empty() {
        println!("stale: none");
    } else {
        for alert in &stale {
            println!(
                "stale[{}] {} {} {} age_ms={}",
                alert.reason, alert.record.channel, alert.record.view.id, alert.record.view.title, alert.age_ms
            );
        }
    }
    match recommendation["action"].as_str() {
        Some("continue") => println!(
            "action: continue {} {}",
            recommendation["channel"].as_str().unwrap_or("?"),
            recommendation["id"].as_str().unwrap_or("?")
        ),
        Some("claim") => println!(
            "action: claim {} {}",
            recommendation["channel"].as_str().unwrap_or("?"),
            recommendation["id"].as_str().unwrap_or("?")
        ),
        _ => println!("action: idle"),
    }
    Ok(0)
}

pub(crate) fn cmd_focus(json: bool, limit: u32) -> Result<i32> {
    let client = RelayClient::from_env()?;
    let identity = client.whoami()?.identity;
    let board = board_summary(limit);

    if !board["available"].as_bool().unwrap_or(false) {
        return Err(idboard_core::error::CoreError::internal(
            "focus needs a wrapper: this command is for agents inside `keryx run`",
        ));
    }

    let channels = visible_readable_channels(&client)?;
    let (_, records) = load_tasks(&client, &channels)?;
    let my_claimed = records
        .iter()
        .filter(|record| {
            !record.view.done && record.view.claimed_by.as_deref() == Some(identity.as_str())
        })
        .count();
    let next = ready_tasks(&records).into_iter().find(|record| record.view.claimed_by.is_none());

    if json {
        println!("{}", serde_json::json!({
            "identity": identity,
            "channels": board["channels"],
            "tasks": board["tasks"],
            "next": next.map(|record| task_json(record)),
            "your_claimed_tasks": my_claimed,
            "recent": board["recent"],
        }));
        return Ok(0);
    }

    println!("focus: {identity}");
    println!("channels: {}", board["channels"].as_array().map(|c| c.len()).unwrap_or(0));
    println!("your claimed tasks: {my_claimed}");
    match next {
        Some(record) => {
            println!("next: {} {} ({})", record.channel, record.view.id, record.view.title);
            println!("claim: keryx task claim {} {}", record.channel, record.view.id);
        }
        None => println!("next: no unclaimed tasks"),
    }
    println!("recent messages:");
    for message in board["recent"].as_array().map(|v| v.as_slice()).unwrap_or(&[]) {
        println!(
            "  [{} cursor {}] {}",
            message["channel"].as_str().unwrap_or("?"),
            message["cursor"].as_i64().unwrap_or(0),
            render_message(
                message["sender"].as_str().unwrap_or("?"),
                message["cursor"].as_i64().unwrap_or(0),
                &Provenance::SelfOriginated,
                message["body"].as_str().unwrap_or(""),
            )
        );
    }
    Ok(0)
}

pub(crate) fn cmd_replay(
    json: bool,
    channel: Option<&str>,
    task: Option<&str>,
    since: Option<i64>,
    since_last: bool,
    limit: Option<u32>,
    save_cursor: bool,
) -> Result<i32> {
    if task.is_some() && (since_last || save_cursor || since.is_some()) {
        return Err(idboard_core::error::CoreError::bad_request(
            "--task selects the task's own event trail; combine it only with --limit",
        ));
    }
    if channel.is_some() && (since_last || save_cursor || since.is_none()) {
        // A single channel can still use --since-last/--save-cursor; the
        // condition is documentation only, not a constraint.
    }
    if since_last && since.is_some() {
        return Err(idboard_core::error::CoreError::bad_request(
            "pass either --since or --since-last, not both",
        ));
    }

    let client = RelayClient::from_env()?;
    let per_channel = limit.unwrap_or(50) as usize;
    let channels = match channel {
        Some(channel) => {
            validate_channel(channel)?;
            vec![channel.to_string()]
        }
        None => visible_readable_channels(&client)?,
    };

    let mut store = None;
    if (since_last || save_cursor) && (!channels.is_empty() || channel.is_some()) {
        if since_last {
            let identity = client.whoami()?.identity;
            store = Some(CursorStore::for_identity(&identity)?);
        } else {
            let identity = client.whoami()?.identity;
            store = Some(CursorStore::for_identity(&identity)?);
        }
    }

    let mut output_channels = Vec::new();
    for channel in channels {
        let start = if let Some(explicit) = since {
            explicit
        } else if since_last {
            store.as_ref().expect("store is open for --since-last").get(&channel)
        } else {
            0
        };
        let res = client.read(&channel, start, 1000)?;
        let mut messages: Vec<_> = res.messages.into_iter().collect();
        if let Some(task_id) = task {
            messages.retain(|message| {
                trusted_task_event(message).is_some_and(|event| event.id == task_id)
            });
        }
        let messages: Vec<_> = truncate_to_last(messages, per_channel);
        let final_cursor = messages.last().map(|message| message.cursor).unwrap_or(start);
        if let Some(store) = store.as_mut() {
            if save_cursor {
                store.set(&channel, final_cursor);
            }
        }
        output_channels.push(ReplayChannel { channel, start, final_cursor, messages });
    }

    if let Some(mut store) = store {
        store.flush()?;
    }

    if json {
        let channels: Vec<_> = output_channels
            .iter()
            .map(|channel| serde_json::json!({
                "channel": channel.channel,
                "since": channel.start,
                "cursor": channel.final_cursor,
                "messages": channel.messages,
            }))
            .collect();
        println!("{}", serde_json::json!({
            "ok": true,
            "channels": channels,
            "limit_per_channel": per_channel,
        }));
        return Ok(0);
    }
    for channel in output_channels {
        println!("== {} ==", channel.channel);
        for message in channel.messages {
            println!(
                "{}",
                render_message(
                    &message.envelope.sender_id,
                    message.cursor,
                    &message.envelope.provenance,
                    &message.envelope.body,
                )
            );
        }
        println!();
    }
    Ok(0)
}
