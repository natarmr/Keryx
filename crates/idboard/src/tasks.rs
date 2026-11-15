//! Cooperative task state reconstructed from plain signed messages.
//!
//! Task messages are an ordinary channel convention, not a new protocol type:
//! `task:{"v":1,...}` on a normal signed message. This keeps old boards
//! interoperable and means ACL/enforcement code stays untouched.
//!
//! This module owns the whole task domain so the CLI (`keryx task ...`) and the
//! MCP server (`tasks`, `task_claim`, ...) share one implementation. A second
//! implementation is free to disagree about what "open" means, and the
//! disagreement would surface only when an agent acted on a stale view.

use std::collections::{BTreeMap, HashMap};

use idboard_core::error::{CoreError, Result};

use crate::client::RelayClient;

/// Parse a small human duration: `ms`, `s`, `m`, `h`, `d`, or bare seconds.
/// Shared by the CLI and the MCP server so both spell leases the same way.
pub fn parse_duration_ms(input: &str) -> Result<u64> {
    let s = input.trim();
    if s.is_empty() {
        return Err(CoreError::bad_request("duration must not be empty"));
    }
    let (number, unit_ms) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1_000)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3_600_000)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86_400_000)
    } else {
        (s, 1_000)
    };
    let value: u64 = number.trim().parse().map_err(|_| {
        CoreError::bad_request(format!("invalid duration {input:?}; use e.g. 30s, 10m, 2h or 1d"))
    })?;
    if value == 0 {
        return Err(CoreError::bad_request("duration must be greater than zero"));
    }
    value.checked_mul(unit_ms).ok_or_else(|| CoreError::bad_request(format!("duration {input:?} is too large")))
}

/// One task event as posted on the board.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaskEvent {
    pub v: u8,
    pub id: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Lease duration in ms. Only set on `claim`; absent means no expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_ms: Option<u64>,
    /// Wall-clock time the claim was made. Compared against `now_ms` at read time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at_ms: Option<i64>,
    /// Prerequisite task id. Only set on `link`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<String>,
    /// Completion outcome. Only set on `done`: `ok`, `blocked`, or `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// Human note attached to the outcome. Only set on `done`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A task's reconstructed state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaskView {
    pub id: String,
    pub title: String,
    pub created_by: String,
    pub claimed_by: Option<String>,
    pub done: bool,
    /// Lease duration in ms from the last claim, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_ms: Option<u64>,
    /// Absolute expiry of the last claim, if leased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at_ms: Option<i64>,
    /// Prerequisite task ids. Empty means the task is unblocked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    /// Completion outcome, if done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    /// Human note attached to the outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A task record with ordering metadata kept off the JSON wire.
#[derive(Debug)]
pub struct TaskRecord {
    pub channel: String,
    pub view: TaskView,
    pub create_cursor: i64,
    /// Envelope timestamp of the `create` event, for poll-based staleness.
    pub created_at_ms: i64,
    /// Envelope timestamp of the latest `claim`/`reclaim`, cleared on
    /// `abandon`/`reopen`. `None` when unclaimed.
    pub claimed_at_ms: Option<i64>,
}

/// Milliseconds since `event_ms`, saturating at zero for future timestamps.
pub fn watch_age_ms(event_ms: i64, now_ms: i64) -> u64 {
    now_ms.saturating_sub(event_ms).max(0) as u64
}

/// Pure staleness predicate: an open, unclaimed task is stale once its age
/// reaches the threshold.
pub fn is_unclaimed_stale(created_at_ms: i64, done: bool, claimed: bool, now_ms: i64, threshold_ms: u64) -> bool {
    !done && !claimed && watch_age_ms(created_at_ms, now_ms) >= threshold_ms
}

/// Pure stall predicate: a claimed, unfinished task is stalled once the time
/// since its latest claim reaches the threshold.
pub fn is_claim_stalled(claimed_at_ms: Option<i64>, claimed: bool, done: bool, now_ms: i64, threshold_ms: u64) -> bool {
    match (claimed, done, claimed_at_ms) {
        (true, false, Some(at)) => watch_age_ms(at, now_ms) >= threshold_ms,
        _ => false,
    }
}

/// One stale entry: the task plus why it was flagged and how old it is.
pub struct StaleAlert<'a> {
    pub record: &'a TaskRecord,
    pub reason: &'static str,
    pub age_ms: u64,
}

/// Select stale tasks from already-loaded records. Pure in `now_ms`, so unit
/// tests never touch the clock or the board.
pub fn select_stale_tasks(
    records: &[TaskRecord],
    now_ms: i64,
    unclaimed_threshold_ms: Option<u64>,
    claimed_threshold_ms: Option<u64>,
) -> Vec<StaleAlert<'_>> {
    let mut out = Vec::new();
    for record in records {
        let claimed = record.view.claimed_by.is_some();
        if let Some(threshold) = unclaimed_threshold_ms
            && is_unclaimed_stale(record.created_at_ms, record.view.done, claimed, now_ms, threshold)
        {
            out.push(StaleAlert {
                record,
                reason: "unclaimed",
                age_ms: watch_age_ms(record.created_at_ms, now_ms),
            });
            continue;
        }
        if let Some(threshold) = claimed_threshold_ms
            && is_claim_stalled(record.claimed_at_ms, claimed, record.view.done, now_ms, threshold)
        {
            out.push(StaleAlert {
                // `claimed_at_ms` is `Some` whenever `is_claim_stalled` is true.
                record,
                reason: "claimed-without-progress",
                age_ms: watch_age_ms(record.claimed_at_ms.unwrap_or(now_ms), now_ms),
            });
        }
    }
    out
}

pub fn stale_alert_json(alert: &StaleAlert<'_>) -> serde_json::Value {
    serde_json::json!({
        "channel": alert.record.channel,
        "id": alert.record.view.id,
        "title": alert.record.view.title,
        "reason": alert.reason,
        "age_ms": alert.age_ms,
        "claimed_by": alert.record.view.claimed_by,
    })
}

pub fn parse_task_event(body: &str) -> Option<TaskEvent> {
    let text = body.strip_prefix("task:")?;
    serde_json::from_str(text).ok().filter(|e: &TaskEvent| e.v == 1)
}

pub fn collect_tasks_from_messages(
    messages: Vec<idboard_core::wire::StoredMessage>,
    channel: &str,
) -> Vec<TaskRecord> {
    collect_tasks_from_messages_at(messages, channel, idboard_core::now_ms())
}

#[allow(clippy::too_many_lines)]
pub fn collect_tasks_from_messages_at(
    messages: Vec<idboard_core::wire::StoredMessage>,
    channel: &str,
    now_ms: i64,
) -> Vec<TaskRecord> {
    // (view, create_cursor, created_at_ms, claimed_at_ms)
    let mut tasks: BTreeMap<String, (TaskView, i64, i64, Option<i64>)> = BTreeMap::new();
    for message in messages {
        let Some(ev) = parse_task_event(&message.envelope.body) else { continue };
        match ev.kind.as_str() {
            "create" => {
                let view = TaskView {
                    id: ev.id.clone(),
                    title: ev.title.unwrap_or_else(|| "(untitled)".to_string()),
                    created_by: message.envelope.sender_id.clone(),
                    claimed_by: None,
                    done: false,
                    lease_ms: None,
                    lease_expires_at_ms: None,
                    depends_on: Vec::new(),
                    result: None,
                    note: None,
                };
                tasks.insert(ev.id.clone(), (view, message.cursor, message.envelope.timestamp, None));
            }
            "claim" | "reclaim" => {
                if let Some((task, _, _, claimed_at)) = tasks.get_mut(&ev.id) {
                    task.claimed_by = Some(message.envelope.sender_id);
                    // Staleness uses the authoritative envelope timestamp, not the
                    // claimer's self-reported `claimed_at_ms` (used for leases).
                    *claimed_at = Some(message.envelope.timestamp);
                    match ev.lease_ms {
                        Some(lease) => {
                            let claimed_at_ev = ev.claimed_at_ms.unwrap_or(message.envelope.timestamp);
                            let expires = claimed_at_ev.saturating_add(lease as i64);
                            task.lease_ms = Some(lease);
                            task.lease_expires_at_ms = Some(expires);
                        }
                        None => {
                            task.lease_ms = None;
                            task.lease_expires_at_ms = None;
                        }
                    }
                }
            }
            "abandon" => {
                if let Some((task, _, _, claimed_at)) = tasks.get_mut(&ev.id) {
                    task.claimed_by = None;
                    task.lease_ms = None;
                    task.lease_expires_at_ms = None;
                    *claimed_at = None;
                }
            }
            "reopen" => {
                if let Some((task, _, _, claimed_at)) = tasks.get_mut(&ev.id) {
                    task.done = false;
                    task.claimed_by = None;
                    task.lease_ms = None;
                    task.lease_expires_at_ms = None;
                    task.result = None;
                    task.note = None;
                    *claimed_at = None;
                }
            }
            "link" => {
                if let Some((task, _, _, _)) = tasks.get_mut(&ev.id) {
                    if let Some(dep) = ev.depends_on {
                        if !task.depends_on.contains(&dep) {
                            task.depends_on.push(dep);
                        }
                    }
                }
            }
            "done" => {
                if let Some((task, _, _, _)) = tasks.get_mut(&ev.id) {
                    task.done = true;
                    task.result = ev.result;
                    task.note = ev.note;
                }
            }
            _ => {}
        }
    }

    // Leases expire at read time: an expired claim reads as unclaimed.
    // No daemon/store change; the claim message stays on the board.
    for (task, _, _, claimed_at) in tasks.values_mut() {
        if let Some(expires) = task.lease_expires_at_ms {
            if !task.done && task.claimed_by.is_some() && now_ms >= expires {
                task.claimed_by = None;
                *claimed_at = None;
            }
        }
    }

    let mut records: Vec<_> = tasks
        .into_values()
        .map(|(view, create_cursor, created_at_ms, claimed_at_ms)| TaskRecord {
            channel: channel.to_string(),
            view,
            create_cursor,
            created_at_ms,
            claimed_at_ms,
        })
        .collect();
    records.sort_by_key(|record| record.create_cursor);
    records
}

/// Whether this task is blocked: it names at least one prerequisite that is
/// not done. Unknown ids count as not done, so a typo blocks loudly rather
/// than silently passing.
pub fn task_is_blocked(record: &TaskRecord, done_by_id: &HashMap<String, bool>) -> bool {
    !record.view.done
        && record
            .view
            .depends_on
            .iter()
            .any(|dep| !done_by_id.get(dep).copied().unwrap_or(false))
}

/// The ready subset of already-loaded records: open and unblocked, oldest
/// first. This is what `task next` and `task ready` surface.
pub fn ready_tasks(records: &[TaskRecord]) -> Vec<&TaskRecord> {
    let done_by_id: HashMap<String, bool> =
        records.iter().map(|record| (record.view.id.clone(), record.view.done)).collect();
    let mut ready: Vec<&TaskRecord> =
        records.iter().filter(|record| !record.view.done && !task_is_blocked(record, &done_by_id)).collect();
    ready.sort_by_key(|record| record.create_cursor);
    ready
}

pub fn load_channel_tasks(client: &RelayClient, channel: &str) -> Result<Vec<TaskRecord>> {
    let res = client.read(channel, 0, 1000)?;
    Ok(collect_tasks_from_messages(res.messages, channel))
}

pub fn load_tasks(client: &RelayClient, channels: &[String]) -> Result<(String, Vec<TaskRecord>)> {
    let identity = client.whoami()?.identity;
    let mut records = Vec::new();
    for channel in channels {
        records.extend(load_channel_tasks(client, channel)?);
    }
    records.sort_by_key(|record| record.create_cursor);
    Ok((identity, records))
}

pub fn visible_readable_channels(client: &RelayClient) -> Result<Vec<String>> {
    Ok(client
        .inbox(0)?
        .channels
        .into_iter()
        .filter(|digest| digest.can_read)
        .map(|digest| digest.channel)
        .collect())
}

pub fn task_json(task: &TaskRecord) -> serde_json::Value {
    serde_json::json!({
        "channel": task.channel,
        "id": task.view.id,
        "title": task.view.title,
        "created_by": task.view.created_by,
        "claimed_by": task.view.claimed_by,
        "done": task.view.done,
        "lease_ms": task.view.lease_ms,
        "lease_expires_at_ms": task.view.lease_expires_at_ms,
        "depends_on": task.view.depends_on,
        "result": task.view.result,
        "note": task.view.note,
    })
}

/// Keep only the newest `per_channel` messages. `0` means no truncation.
/// Split out so the per-channel replay bound is unit-testable.
pub fn truncate_to_last<T>(mut messages: Vec<T>, per_channel: usize) -> Vec<T> {
    if per_channel > 0 && messages.len() > per_channel {
        messages = messages.into_iter().rev().take(per_channel).collect::<Vec<_>>().into_iter().rev().collect();
    }
    messages
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(body: &str, cursor: i64, sender: &str) -> idboard_core::wire::StoredMessage {
        use idboard_core::envelope::{Envelope, Op};
        use idboard_core::Provenance;
        idboard_core::wire::StoredMessage {
            cursor,
            envelope: Envelope {
                op: Op::Post,
                sender_id: sender.into(),
                sender_pubkey_fp: "00".into(),
                channel: "general".into(),
                body: body.into(),
                provenance: Provenance::SelfOriginated,
                seq: cursor,
                timestamp: cursor * 1000,
                nonce: String::new(),
                signature: String::new(),
            },
        }
    }

    fn linked_board(now_ms: i64) -> Vec<TaskRecord> {
        // t-a open; t-b blocked on t-a; t-c done and depended on by no one.
        let messages = vec![
            envelope(r#"task:{"v":1,"id":"t-a","kind":"create","title":"first"}"#, 1, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-b","kind":"create","title":"second"}"#, 2, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-b","kind":"link","depends_on":"t-a"}"#, 3, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-c","kind":"create","title":"third"}"#, 4, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-c","kind":"done","result":"ok"}"#, 5, "eng-01"),
        ];
        collect_tasks_from_messages_at(messages, "general", now_ms)
    }

    #[test]
    fn link_marks_only_the_named_prerequisite_as_blocking() {
        let records = linked_board(1_000_000);
        let done_by_id: HashMap<String, bool> =
            records.iter().map(|record| (record.view.id.clone(), record.view.done)).collect();
        let blocked: Vec<&str> = records
            .iter()
            .filter(|record| task_is_blocked(record, &done_by_id))
            .map(|record| record.view.id.as_str())
            .collect();
        assert_eq!(blocked, ["t-b"], "only the linked task is blocked: {blocked:?}");
    }

    #[test]
    fn ready_skips_blocked_claimed_and_done_tasks_oldest_first() {
        let records = linked_board(1_000_000);
        let ready = ready_tasks(&records);
        let ids: Vec<&str> = ready.iter().map(|record| record.view.id.as_str()).collect();
        assert_eq!(ids, ["t-a"], "ready means open, unblocked, and unclaimed: {ids:?}");
    }

    #[test]
    fn an_unknown_prerequisite_blocks_loudly_rather_than_passing() {
        let messages = vec![
            envelope(r#"task:{"v":1,"id":"t-x","kind":"create","title":"x"}"#, 1, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-x","kind":"link","depends_on":"t-ghost"}"#, 2, "eng-01"),
        ];
        let records = collect_tasks_from_messages_at(messages, "general", 1_000_000);
        assert!(ready_tasks(&records).is_empty(), "a typoed prerequisite must not read as ready");
    }

    #[test]
    fn done_tasks_are_ready_never_and_carry_result_and_note() {
        let messages = vec![
            envelope(r#"task:{"v":1,"id":"t-d","kind":"create","title":"d"}"#, 1, "eng-01"),
            envelope(
                r#"task:{"v":1,"id":"t-d","kind":"done","result":"blocked","note":"waiting on deploy"}"#,
                2,
                "eng-01",
            ),
        ];
        let records = collect_tasks_from_messages_at(messages, "general", 1_000_000);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].view.result.as_deref(), Some("blocked"));
        assert_eq!(records[0].view.note.as_deref(), Some("waiting on deploy"));
        assert!(ready_tasks(&records).is_empty());
        let json = task_json(&records[0]);
        assert_eq!(json["result"], "blocked");
        assert_eq!(json["note"], "waiting on deploy");
    }
}
