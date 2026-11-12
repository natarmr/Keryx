#!/usr/bin/env node
// Parent-side ledger correction after the post-wave coverage critic.
// (1) Corrects a factually false exclusion reason seeded in eight units.
// (2) Records the critic's accepted missing units as deferred work for a future wave.
const fs = require("node:fs");
const path = require("node:path");
const skill = process.argv[2];
const runDir = process.argv[3];
const { canonicalCoverageId } = require(path.join(skill, "validate-coverage-ledger.cjs"));

const ledgerPath = path.join(runDir, "coverage-ledger.json");
const ledger = JSON.parse(fs.readFileSync(ledgerPath, "utf8"));

// --- (1) correct the false noBroker exclusion reason -----------------------------
const GOOD_REASON = "Source fact: the board has no external broker, no consumer group, no partition, and no dead-letter route; Store::read selects rows with an explicit channel equality predicate. The channel post/read grant lists ARE topic ACLs and the `*` grant IS a wildcard subscription scope, but those are enforced by the config and consumed by Board::authorize, and they are owned by the idboard-acl grant-matching and idboardd authorize units plus the wave-2 provenance-and-subscription-scope unit seeded below. Excluded from the units that carry it so the broker/queue domain is not double-covered; the accurate claim is narrower than the reason originally recorded.";
let fixed = 0;
for (const unit of ledger) {
  for (const entry of unit.excluded_blocks) {
    if (entry.block === "PROTOCOLS-RPC-AND-MESSAGING.md#Broker and queue isolation attack classes") {
      if (entry.reason !== GOOD_REASON) { entry.reason = GOOD_REASON; fixed += 1; }
    }
  }
}
console.log(`corrected ${fixed} exclusion reason(s)`);

// --- (2) seed the critic's accepted missing units as deferred wave-2 work --------
const NEW = [
  { surface: "crates/idboard-ipc/src/lib.rs#bind and bind_nonblocking listener creation for both pipes", boundary: "crates/idboard-ipc/src/lib.rs#bind and bind_nonblocking OS-level peer restriction on the daemon pipe and the per-invocation relay pipe", subsystem: "idboard-ipc", attack_class: "ATTACK-CLASSES.md#Access control", paths: ["crates/idboard-ipc/src/lib.rs", "crates/idboardd/src/main.rs", "crates/idboard/src/wrapper.rs", "crates/idboard/src/relay.rs", "crates/idboard-core/src/layout.rs"], companions: ["DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local IPC and exported-component attack classes", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Privileged-helper and local-file attack classes", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Universal moves", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Validation rules"], reason: "No wave-1 unit owns listener creation. bind and bind_nonblocking construct both endpoints as a bare ListenerOptions::new().name(name).create_sync() with no security descriptor on any platform, and the crate's own module doc concedes a pipe name is not a boundary. Every control the 21 wave-1 units verify is an in-band signature or token check that any local process is free to attempt, so the chain's peer restriction rests on an unreviewed decision. Three hunters raised this and it was not adopted in wave 1. Also covers cleanup_socket_file, a no-op on Windows, and the second-bind refusal." },
  { surface: "crates/idboard/src/wrapper.rs#serve_until_exit relay accept loop and serve_one", boundary: "crates/idboard/src/wrapper.rs#serve_until_exit single-threaded accept loop, synchronous serve_one, interrupt and drain lifecycle", subsystem: "idboard", attack_class: "ATTACK-CLASSES.md#Business logic", paths: ["crates/idboard/src/wrapper.rs", "crates/idboard/src/relay.rs", "crates/idboard-ipc/src/lib.rs", "crates/idboard/src/lock.rs", "crates/idboard/tests/e2e.rs"], companions: ["RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline", "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Resource accumulation attack classes", "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Quota and scheduling attack classes", "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Failure and recovery attack classes", "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Universal moves", "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Validation rules", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local IPC and exported-component attack classes", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Universal moves", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Validation rules"], reason: "serve_until_exit is owned by nobody: the wrapper unit's boundary is spawn_child env construction and the relay units' boundary is Relay::dispatch. try_accept is drained in a loop and serve_one is called synchronously, so the blocking read_frame at wrapper.rs:403 must return before the next accept, before child.try_wait at :356 and before the TICK sleep; the token gate runs inside Relay::handle, after the read; and apply_timeouts installs no deadline on Windows named pipes. A local process connecting to the enumerable relay pipe name and sending nothing therefore stops the wrapper accepting, stops the child being polled, and holds the IdentityLock taken at :177 for the life of the child, so every later idboard run for that identity fails exit 2 while the child runs. Same reusable root cause as the apply_timeouts candidate, on an unowned surface. Also covers the Ctrl-C path and the post-exit DRAIN loop." },
  { surface: "crates/idboard/src/cli.rs#cmd_subscribe poll loop and start-cursor derivation", boundary: "crates/idboard/src/cli.rs#cmd_subscribe start-cursor derivation against crates/idboardd/src/lib.rs#handle_read empty-page cursor echo", subsystem: "idboard", attack_class: "ATTACK-CLASSES.md#Business logic", paths: ["crates/idboard/src/cli.rs", "crates/idboardd/src/lib.rs", "crates/idboard-store/src/lib.rs", "crates/idboard/src/client.rs", "crates/idboard/src/relay.rs"], companions: ["PROTOCOLS-RPC-AND-MESSAGING.md#Core discipline", "PROTOCOLS-RPC-AND-MESSAGING.md#Framing, schema, and interpretation attack classes", "PROTOCOLS-RPC-AND-MESSAGING.md#Replay, ordering, and transaction attack classes", "PROTOCOLS-RPC-AND-MESSAGING.md#Universal moves", "PROTOCOLS-RPC-AND-MESSAGING.md#Validation rules"], reason: "cmd_subscribe is the only in-tree consumer of the read contract and no unit's boundary names it. It bootstraps its cursor with client.read(channel, i64::MAX, 1) and unwrap_or(0) at cli.rs:200-203; the relay forwards since.max(0); the daemon clamps; the query filters cursor > i64::MAX and returns nothing; and handle_read sets the reply cursor to unwrap_or(since) at idboardd/src/lib.rs:214, echoing i64::MAX back. Every later poll reuses it, so idboard subscribe without --since never returns a message and polls silently forever, leaving the reader acting on a permanently stale view. Store::high_water_cursor, the only function that could answer where the tail is, has no production caller." },
  { surface: "crates/idboardd/src/main.rs#run daemon startup sequence and the --check and --show-acl early returns", boundary: "crates/idboardd/src/main.rs#run config load, store open, registry reconcile, bind, and the --check and --show-acl early-return paths", subsystem: "idboardd", attack_class: "ATTACK-CLASSES.md#Business logic", paths: ["crates/idboardd/src/main.rs", "crates/idboard-acl/src/lib.rs", "crates/idboard-store/src/lib.rs", "crates/idboard-ipc/src/lib.rs", "crates/idboard-core/src/layout.rs", "crates/idboard/tests/e2e.rs"], companions: ["DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local IPC and exported-component attack classes", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Application-state and device-lifecycle attack classes", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Universal moves", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Validation rules", "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Core discipline", "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Failure and recovery attack classes", "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md#Validation rules"], reason: "A startup lifecycle mode with no owner, and its two early returns are asymmetric in a way nothing examines. --show-acl returns at main.rs:79-81 before Store::open; --check returns at :95-98 after Store::open and Board::new, so the flag documented as validate-then-exit creates the state root, opens or creates idboard.db, applies SCHEMA and reconciles the identities table, inserting and updating rows, before it can still fail at bind. Nothing rolls that back. The same ordering lets a second daemon on a different --socket with the same --db write the registry before bind refuses it, contradicting the store module's stated single-writer premise. This is the Business-logic partial-failure case: step 1 is not rolled back when step 3 fails." },
  { surface: "crates/idboardd/src/lib.rs#rejection_line operator stderr sink", boundary: "crates/idboardd/src/lib.rs#rejection_line and the serve-time eprintln, as the daemon's post-incident attribution record", subsystem: "idboardd", attack_class: "ATTACK-CLASSES.md#Injection", paths: ["crates/idboardd/src/lib.rs", "crates/idboardd/src/main.rs", "crates/idboard-core/src/envelope.rs", "crates/idboard-core/src/ids.rs"], companions: ["DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Local IPC and exported-component attack classes", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Universal moves", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Validation rules", "AI-AND-LLM.md#Core discipline", "AI-AND-LLM.md#Output and disclosure attack classes", "AI-AND-LLM.md#Validation rules"], reason: "The daemon rejection-log candidate originated in the wire-shape unit, whose declared invariant enumerates its sinks as a query, path or spawn and does not include the operator's log, yet the defect location is rejection_line, which interpolates env.sender_id and env.channel with Display into the line written for every not-ok response. The proposed fix lands in the sink, so fixing only the decode boundary would leave the sink unreviewed. This unit's first job is to establish the complete attacker-influenceable value set reaching that sink and the escaping control, not to restate the existing candidate." },
  { surface: "crates/idboard-acl/src/lib.rs#channel post and read grants and crates/idboard/src/cli.rs#subscribe as a consumer", boundary: "crates/idboard-acl/src/lib.rs#channel topic ACL, the * wildcard grant, the subscribe consumer scope, and the self-declared provenance control-plane field", subsystem: "idboard-acl", attack_class: "ATTACK-CLASSES.md#Access control", paths: ["crates/idboard-acl/src/lib.rs", "crates/idboardd/src/lib.rs", "crates/idboard-store/src/lib.rs", "crates/idboard/src/cli.rs", "crates/idboard/src/relay.rs", "crates/idboard-core/src/envelope.rs"], companions: ["PROTOCOLS-RPC-AND-MESSAGING.md#Core discipline", "PROTOCOLS-RPC-AND-MESSAGING.md#Broker and queue isolation attack classes", "PROTOCOLS-RPC-AND-MESSAGING.md#RPC identity and authorization attack classes", "PROTOCOLS-RPC-AND-MESSAGING.md#Universal moves", "PROTOCOLS-RPC-AND-MESSAGING.md#Validation rules", "AI-AND-LLM.md#Core discipline", "AI-AND-LLM.md#Context, retrieval, and memory attack classes", "AI-AND-LLM.md#Output and disclosure attack classes", "AI-AND-LLM.md#Validation rules", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Core discipline", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Universal moves", "DESKTOP-MOBILE-AND-LOCAL-IPC.md#Validation rules"], reason: "Corrects an unjustified exclusion. The wave-1 reason for excluding the broker and queue isolation domain claimed there is no topic ACL and no wildcard subscription, which is false: the channel post/read grant lists are topic ACLs enforced per request, the fixture every test and the README use is post=[\"*\"] read=[\"*\"], and idboard subscribe is a subscription re-authorised on every poll. Wave 1 did verify that no authorisation or dispatch branch reads provenance, which answers the enforcement half; what no unit states is that the label is a producer self-declaration with a permissive default and that the renderer gives the reader no indication of that." },
];

const NO_HTTP = { block: "WEB-PROTOCOL-AND-AUTH.md#When to use this file", reason: "Source fact: no HTTP, TLS, session, cookie, JWT or OAuth code path exists; transport is local named pipes and Unix domain sockets only." };
const NO_BROWSER = { block: "CLIENT-SIDE.md#When to use this file", reason: "Source fact: no browser, webview, DOM, CORS or service-worker code exists." };
const NO_CLOUD = { block: "CLOUD-AND-DEPLOYMENT.md#When to use this file", reason: "Source fact: no cloud SDK, IAM, infrastructure-as-code or container configuration exists." };
const NO_TENANT = { block: "DATA-ISOLATION-AND-LIFECYCLE.md#When to use this file", reason: "Source fact: storage is one local SQLite file per daemon process with no export, backup, migration or deletion path." };
const NO_MEM = { block: "MEMORY-SAFETY-AND-BINARY.md#When to use this file", reason: "Source fact: the workspace is safe Rust; the only unsafe blocks are edition-2024 test-helper environment mutation." };
const NO_SUP = { block: "SUPPLY-CHAIN-AND-RELEASE.md#When to use this file", reason: "Source fact: no CI workflow, build.rs, publish, release, code-signing or plugin path exists in the tree." };

const existing = new Set(ledger.map((u) => u.coverage_id));
let added = 0;
for (const n of NEW) {
  const canonical = { surface: n.surface, boundary: n.boundary, subsystem: n.subsystem, attack_class: n.attack_class };
  const id = canonicalCoverageId(canonical);
  if (existing.has(id)) { console.log(`already present, skipped: ${n.subsystem}`); continue; }
  existing.add(id);
  ledger.push({
    coverage_id: id,
    canonical_refs: canonical,
    surface: canonical.surface,
    boundary: canonical.boundary,
    subsystem: canonical.subsystem,
    attack_class: canonical.attack_class,
    starting_paths: n.paths,
    ordinary_attack_class_block: canonical.attack_class,
    selected_companion_blocks: n.companions,
    excluded_blocks: [NO_HTTP, NO_BROWSER, NO_CLOUD, NO_TENANT, NO_MEM, NO_SUP],
    parent_invariant: n.reason,
    prior_status: "none",
    attempts: [],
    wave: 2,
    status: "deferred",
    agent_id: null,
    reviewed_paths: [],
    local_checks: [],
    result_fingerprints: [],
    unresolved: ["coverage_critic_accepted_gap_seeded_this_run_but_wave_2_not_hunted_run_stopped_after_phase_5_for_resource_exhaustion"],
  });
  added += 1;
}

ledger.sort((a, b) => (a.coverage_id < b.coverage_id ? -1 : a.coverage_id > b.coverage_id ? 1 : 0));
fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2) + "\n", "utf8");
const counts = {};
for (const u of ledger) counts[u.status] = (counts[u.status] || 0) + 1;
console.log(`seeded ${added} wave-2 unit(s) as deferred; ledger now`, counts);
