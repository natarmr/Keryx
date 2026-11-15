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
//!
//! # Ownership is enforced here, because nothing else can
//!
//! A task is not a protocol object: the daemon sees ordinary posts, so it
//! cannot know that one `task:` body is a `done` for a task another identity
//! claimed. The fold is therefore the only place ownership can be decided, and
//! every reader goes through it. The rules, applied at the envelope timestamp
//! of the event being folded (so replay is deterministic):
//!
//! - A `claim`/`reclaim` is honoured only when the task is open and unclaimed,
//!   or the claim is already held by the same sender. A live claim cannot be
//!   taken over; a lapsed lease returns the task to the pool and then anyone
//!   may take it.
//! - A `done` or `abandon` is honoured only from the identity holding the live
//!   claim, or from the task's creator while nobody holds it.
//! - A `reopen` is honoured from the creator or from the identity that last
//!   held the task.
//! - A `link` is honoured only from the creator or the current live claimer.
//!
//! An ignored event is a normal signed message that stays on the board: the
//! post succeeds, the state does not change. That is a client-side property,
//! not a daemon guarantee, and it is stated as such in `README.md`.

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

/// The task event a message is allowed to *cause*, as opposed to merely contain.
///
/// A post marked `[external]` is fetched content: it may be displayed, quoted and
/// searched, but it must never move task state or trip a trigger. Only a post the
/// wrapper marked as the agent's own reasoning is a structured event. The body is
/// still a plain signed message either way; this is a reading rule, not a
/// protocol one.
pub fn trusted_task_event(message: &idboard_core::wire::StoredMessage) -> Option<TaskEvent> {
    if matches!(message.envelope.provenance, idboard_core::Provenance::External) {
        return None;
    }
    parse_task_event(&message.envelope.body)
}

pub fn collect_tasks_from_messages(
    messages: Vec<idboard_core::wire::StoredMessage>,
    channel: &str,
) -> Vec<TaskRecord> {
    collect_tasks_from_messages_at(messages, channel, idboard_core::now_ms())
}

/// The identity holding a live claim at `at_ms`.
///
/// `None` means the task is unclaimed *or* the lease had already lapsed at that
/// moment. Ownership is evaluated against the envelope timestamp of the event
/// being folded, not against wall-clock now, so the same history always folds to
/// the same state.
fn live_claimer<'a>(view: &'a TaskView, at_ms: i64) -> Option<&'a str> {
    if view.done {
        return None;
    }
    let claimer = view.claimed_by.as_deref()?;
    match view.lease_expires_at_ms {
        Some(expires) if at_ms >= expires => None,
        _ => Some(claimer),
    }
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
        let Some(ev) = trusted_task_event(&message) else { continue };
        let sender = message.envelope.sender_id.as_str();
        let at = message.envelope.timestamp;
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
                    // Finished work is not claimable, and a live claim belongs to
                    // its holder: only that identity may refresh it.
                    if task.done {
                        continue;
                    }
                    if live_claimer(task, at).is_some_and(|holder| holder != sender) {
                        continue;
                    }
                    task.claimed_by = Some(message.envelope.sender_id.clone());
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
                    let holder = live_claimer(task, at);
                    if !owns_or_created(task, holder, sender) {
                        continue;
                    }
                    task.claimed_by = None;
                    task.lease_ms = None;
                    task.lease_expires_at_ms = None;
                    *claimed_at = None;
                }
            }
            "reopen" => {
                if let Some((task, _, _, claimed_at)) = tasks.get_mut(&ev.id) {
                    // The creator can unstick anything; the last holder can undo
                    // its own completion. Nobody else can reopen work.
                    if task.created_by != sender && task.claimed_by.as_deref() != Some(sender) {
                        continue;
                    }
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
                    let holder = live_claimer(task, at);
                    if !owns_or_created(task, holder, sender) {
                        continue;
                    }
                    if let Some(dep) = ev.depends_on {
                        if !task.depends_on.contains(&dep) {
                            task.depends_on.push(dep);
                        }
                    }
                }
            }
            "done" => {
                if let Some((task, _, _, _)) = tasks.get_mut(&ev.id) {
                    let holder = live_claimer(task, at);
                    if !owns_or_created(task, holder, sender) {
                        continue;
                    }
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

/// Whether `sender` may change a task's state: it holds the live claim, or it
/// created the task and nobody else holds it.
fn owns_or_created(task: &TaskView, holder: Option<&str>, sender: &str) -> bool {
    match holder {
        Some(holder) => holder == sender,
        None => task.created_by == sender,
    }
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

    /// The same message, but marked as fetched content.
    fn external_envelope(body: &str, cursor: i64, sender: &str) -> idboard_core::wire::StoredMessage {
        let mut message = envelope(body, cursor, sender);
        message.envelope.provenance = idboard_core::Provenance::External;
        message
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

    /// One task, one owner: the claim is eng-01's, and only eng-01 can finish or
    /// release it. A `done` from eng-02 is a signed message that changes nothing.
    #[test]
    fn a_done_from_a_non_claimant_is_ignored() {
        let messages = vec![
            envelope(r#"task:{"v":1,"id":"t-o","kind":"create","title":"owned"}"#, 1, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-o","kind":"claim"}"#, 2, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-o","kind":"done","result":"ok"}"#, 3, "eng-02"),
        ];
        let records = collect_tasks_from_messages_at(messages, "general", 1_000_000);
        assert_eq!(records.len(), 1);
        assert!(!records[0].view.done, "a non-claimant's done must be ignored");
        assert_eq!(records[0].view.claimed_by.as_deref(), Some("eng-01"));
        assert_eq!(records[0].view.result, None);
    }

    /// The claimer's own `done`, and a creator's `done` on unclaimed work, are
    /// both honoured: the guard must not break the normal path.
    #[test]
    fn the_claimer_and_the_creator_can_complete() {
        let claimed = vec![
            envelope(r#"task:{"v":1,"id":"t-c","kind":"create","title":"claimed"}"#, 1, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-c","kind":"claim"}"#, 2, "eng-02"),
            envelope(r#"task:{"v":1,"id":"t-c","kind":"done","result":"ok"}"#, 3, "eng-02"),
        ];
        let records = collect_tasks_from_messages_at(claimed, "general", 1_000_000);
        assert!(records[0].view.done, "the claimer may complete its own task");

        let unclaimed = vec![
            envelope(r#"task:{"v":1,"id":"t-u","kind":"create","title":"unclaimed"}"#, 1, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-u","kind":"done","result":"ok"}"#, 2, "eng-01"),
        ];
        let records = collect_tasks_from_messages_at(unclaimed, "general", 1_000_000);
        assert!(records[0].view.done, "the creator may complete unclaimed work");
    }

    /// `abandon` from a stranger leaves the live claim alone; the holder's own
    /// abandon releases it.
    #[test]
    fn abandon_only_works_for_the_holder() {
        let stranger = vec![
            envelope(r#"task:{"v":1,"id":"t-a","kind":"create","title":"held"}"#, 1, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-a","kind":"claim"}"#, 2, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-a","kind":"abandon"}"#, 3, "eng-02"),
        ];
        let records = collect_tasks_from_messages_at(stranger, "general", 1_000_000);
        assert_eq!(records[0].view.claimed_by.as_deref(), Some("eng-01"), "a stranger cannot release a claim");

        let holder = vec![
            envelope(r#"task:{"v":1,"id":"t-a","kind":"create","title":"held"}"#, 1, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-a","kind":"claim"}"#, 2, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-a","kind":"abandon"}"#, 3, "eng-01"),
        ];
        let records = collect_tasks_from_messages_at(holder, "general", 1_000_000);
        assert_eq!(records[0].view.claimed_by, None, "the holder can release its own claim");
    }

    /// Reclaim is a takeover only after the lease lapses. Envelope timestamps
    /// decide it, so the test needs no clock.
    #[test]
    fn reclaim_is_refused_while_live_and_allowed_after_the_lease_lapses() {
        let live = vec![
            envelope(r#"task:{"v":1,"id":"t-l","kind":"create","title":"live"}"#, 1, "eng-01"),
            envelope(
                r#"task:{"v":1,"id":"t-l","kind":"claim","lease_ms":100000,"claimed_at_ms":1000}"#,
                2,
                "eng-01",
            ),
            envelope(r#"task:{"v":1,"id":"t-l","kind":"reclaim"}"#, 3, "eng-02"),
        ];
        let records = collect_tasks_from_messages_at(live, "general", 5_000);
        assert_eq!(records[0].view.claimed_by.as_deref(), Some("eng-01"), "a live claim cannot be taken over");

        let lapsed = vec![
            envelope(r#"task:{"v":1,"id":"t-l","kind":"create","title":"lapsed"}"#, 1, "eng-01"),
            envelope(
                r#"task:{"v":1,"id":"t-l","kind":"claim","lease_ms":1000,"claimed_at_ms":1000}"#,
                2,
                "eng-01",
            ),
            envelope(r#"task:{"v":1,"id":"t-l","kind":"reclaim"}"#, 3, "eng-02"),
        ];
        let records = collect_tasks_from_messages_at(lapsed, "general", 1_000_000);
        assert_eq!(
            records[0].view.claimed_by.as_deref(),
            Some("eng-02"),
            "a lapsed lease returns the task to the pool"
        );
    }

    /// Fetched content is data. A `task:` body carried by an `[external]` post
    /// must not create, claim, complete or block anything.
    #[test]
    fn an_external_task_event_never_moves_state() {
        let messages = vec![
            envelope(r#"task:{"v":1,"id":"t-e","kind":"create","title":"real"}"#, 1, "eng-01"),
            external_envelope(r#"task:{"v":1,"id":"t-e","kind":"done","result":"ok"}"#, 2, "eng-01"),
            external_envelope(r#"task:{"v":1,"id":"t-x","kind":"create","title":"forged"}"#, 3, "eng-02"),
        ];
        let records = collect_tasks_from_messages_at(messages, "general", 1_000_000);
        assert_eq!(records.len(), 1, "an external create must not invent a task: {records:?}");
        assert!(!records[0].view.done, "an external done must not complete a task");
        assert_eq!(records[0].view.result, None);
    }

    /// Reopen is the creator's or the last holder's call, not any reader's.
    #[test]
    fn reopen_is_the_creators_or_the_last_holders_call() {
        let base = [
            r#"task:{"v":1,"id":"t-r","kind":"create","title":"r"}"#,
            r#"task:{"v":1,"id":"t-r","kind":"claim"}"#,
            r#"task:{"v":1,"id":"t-r","kind":"done","result":"failed"}"#,
        ];
        let mut stranger = Vec::new();
        for (i, body) in base.iter().enumerate() {
            stranger.push(envelope(body, i as i64 + 1, "eng-01"));
        }
        stranger.push(envelope(r#"task:{"v":1,"id":"t-r","kind":"reopen"}"#, 4, "eng-02"));
        let records = collect_tasks_from_messages_at(stranger, "general", 1_000_000);
        assert!(records[0].view.done, "a stranger cannot reopen work");

        let mut creator = Vec::new();
        for (i, body) in base.iter().enumerate() {
            creator.push(envelope(body, i as i64 + 1, "eng-01"));
        }
        creator.push(envelope(r#"task:{"v":1,"id":"t-r","kind":"reopen"}"#, 4, "eng-01"));
        let records = collect_tasks_from_messages_at(creator, "general", 1_000_000);
        assert!(!records[0].view.done, "the creator can reopen");
        assert_eq!(records[0].view.result, None, "reopen clears the outcome");
    }

    /// Only the creator (while unclaimed) or the live claimer may add a
    /// prerequisite. A `link` from a stranger is a valid signed post whose
    /// effect is ignored, like `done`/`abandon` from a non-holder.
    #[test]
    fn link_only_the_owner_may_add_a_prerequisite() {
        // t-o: created by eng-01, unclaimed. A link from eng-02 must be ignored.
        let stranger = vec![
            envelope(r#"task:{"v":1,"id":"t-o","kind":"create","title":"owned"}"#, 1, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-dep","kind":"create","title":"dep"}"#, 2, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-o","kind":"link","depends_on":"t-dep"}"#, 3, "eng-02"),
        ];
        let records = collect_tasks_from_messages_at(stranger, "general", 1_000_000);
        let t_o = records.iter().find(|r| r.view.id == "t-o").unwrap();
        assert!(t_o.view.depends_on.is_empty(), "a stranger cannot link a task it does not own");

        // Same task, link from the creator must be honoured.
        let creator = vec![
            envelope(r#"task:{"v":1,"id":"t-o","kind":"create","title":"owned"}"#, 1, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-dep","kind":"create","title":"dep"}"#, 2, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-o","kind":"link","depends_on":"t-dep"}"#, 3, "eng-01"),
        ];
        let records = collect_tasks_from_messages_at(creator, "general", 1_000_000);
        let t_o = records.iter().find(|r| r.view.id == "t-o").unwrap();
        assert_eq!(t_o.view.depends_on, vec!["t-dep"], "the creator may link unclaimed work");

        // Claimed by eng-01, a link from eng-02 (not holder, not creator) is ignored.
        let claimed_stranger = vec![
            envelope(r#"task:{"v":1,"id":"t-c","kind":"create","title":"claimed"}"#, 1, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-c","kind":"claim"}"#, 2, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-c","kind":"link","depends_on":"t-dep"}"#, 3, "eng-02"),
        ];
        let records = collect_tasks_from_messages_at(claimed_stranger, "general", 5_000);
        let t_c = records.iter().find(|r| r.view.id == "t-c").unwrap();
        assert!(t_c.view.depends_on.is_empty(), "only the live claimer may link a claimed task");

        // Same claimed task, link from the live claimer is honoured.
        let holder = vec![
            envelope(r#"task:{"v":1,"id":"t-c","kind":"create","title":"claimed"}"#, 1, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-c","kind":"claim"}"#, 2, "eng-01"),
            envelope(r#"task:{"v":1,"id":"t-c","kind":"link","depends_on":"t-dep"}"#, 3, "eng-01"),
        ];
        let records = collect_tasks_from_messages_at(holder, "general", 5_000);
        let t_c = records.iter().find(|r| r.view.id == "t-c").unwrap();
        assert_eq!(t_c.view.depends_on, vec!["t-dep"], "the live claimer may link");

        // After lease lapses the claim is dead: the creator may link again.
        let lapsed = vec![
            envelope(r#"task:{"v":1,"id":"t-l","kind":"create","title":"leased"}"#, 1, "eng-01"),
            envelope(
                r#"task:{"v":1,"id":"t-l","kind":"claim","lease_ms":1000,"claimed_at_ms":1000}"#,
                2,
                "eng-02",
            ),
            envelope(r#"task:{"v":1,"id":"t-l","kind":"link","depends_on":"t-dep"}"#, 3, "eng-01"),
        ];
        let records = collect_tasks_from_messages_at(lapsed, "general", 1_000_000);
        let t_l = records.iter().find(|r| r.view.id == "t-l").unwrap();
        assert_eq!(t_l.view.depends_on, vec!["t-dep"], "after a lease lapses the creator may link again");
    }
}
