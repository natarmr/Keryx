#!/usr/bin/env node
// Builds coverage-ledger.json deterministically, reusing the skill validator's own
// canonical-ID encoder so IDs cannot drift from the validator's contract.
const fs = require("node:fs");
const path = require("node:path");
const skill = process.argv[2];
const out = process.argv[3];
const { canonicalCoverageId } = require(path.join(skill, "validate-coverage-ledger.cjs"));

const PROTO = "PROTOCOLS-RPC-AND-MESSAGING.md";
const IPC = "DESKTOP-MOBILE-AND-LOCAL-IPC.md";
const RES = "RESOURCE-EXHAUSTION-AND-AVAILABILITY.md";
const AI = "AI-AND-LLM.md";

const pCore = (n) => `${PROTO}#${n}`;
const iCore = (n) => `${IPC}#${n}`;
const rCore = (n) => `${RES}#${n}`;
const aCore = (n) => `${AI}#${n}`;

const AC = "ATTACK-CLASSES.md#";

const protoSet = (sections) => [
  pCore("Core discipline"),
  ...sections.map(pCore),
  pCore("Universal moves"),
  pCore("Validation rules"),
];
const ipcSet = (sections) => [
  iCore("Core discipline"),
  ...sections.map(iCore),
  iCore("Universal moves"),
  iCore("Validation rules"),
];
const resSet = (sections) => [
  rCore("Core discipline"),
  ...sections.map(rCore),
  rCore("Universal moves"),
  rCore("Validation rules"),
];
const aiSet = (sections) => [
  aCore("Core discipline"),
  ...sections.map(aCore),
  aCore("Universal moves"),
  aCore("Validation rules"),
];

const FRAMING = "Framing, schema, and interpretation attack classes";
const RPCID = "RPC identity and authorization attack classes";
const BROKER = "Broker and queue isolation attack classes";
const REPLAY = "Replay, ordering, and transaction attack classes";
const LOCALIPC = "Local IPC and exported-component attack classes";
const PRIVFILE = "Privileged-helper and local-file attack classes";
const APPLIFE = "Application-state and device-lifecycle attack classes";
const AMPLIFY = "Computational amplification attack classes";
const ACCUM = "Resource accumulation attack classes";
const QUOTA = "Quota and scheduling attack classes";
const FAILREC = "Failure and recovery attack classes";
const CTXMEM = "Context, retrieval, and memory attack classes";
const OUTDISC = "Output and disclosure attack classes";

const SURF = {
  dpipe: "crates/idboardd/src/main.rs#serve named-pipe connection and one JSON frame",
  dreq: "crates/idboardd/src/lib.rs#Board::dispatch DaemonRequest envelope",
  wire: "crates/idboard-core/src/wire.rs#DaemonRequest and RelayRequest JSON wire shapes",
  canon: "crates/idboard-core/src/envelope.rs#Envelope::to_canonical_bytes signing input",
  envpath: "crates/idboard-core/src/layout.rs#environment-derived path resolution",
  cfg: "crates/idboard-acl/src/lib.rs#Config::load config.toml",
  relay: "crates/idboard/src/relay.rs#Relay::dispatch RelayRequest",
  wrap: "crates/idboard/src/wrapper.rs#run_child wrapper options and child process",
  keyfile: "crates/idboard/src/keystore.rs#Keystore key seed file on disk",
  lock: "crates/idboard/src/lock.rs#IdentityLock per-identity lock and pid file",
  db: "crates/idboard-store/src/lib.rs#Store::open idboard.db",
  out: "crates/idboard/src/cli.rs#render_message operator terminal output",
  tree: "workspace root#all authored source, manifests, scripts, and lockfile",
};

const BND = {
  dispatch: "crates/idboardd/src/lib.rs#Board::dispatch check order version registration signature freshness ACL",
  authz: "crates/idboardd/src/lib.rs#authorize verified identity against channel ACL",
  serve: "crates/idboardd/src/main.rs#accept loop worker pool and Board mutex",
  iodeadline: "crates/idboard-ipc/src/lib.rs#apply_timeouts platform I/O deadline support",
  frame: "crates/idboard-ipc/src/lib.rs#read_frame newline-delimited JSON framing",
  verify: "crates/idboard-core/src/keys.rs#verify_with_key verify_strict against config key",
  signed: "crates/idboard-core/src/envelope.rs#SignedFields exact signed field set",
  opinv: "crates/idboard-core/src/envelope.rs#check_op_invariants post counter versus read nonce separation",
  path: "crates/idboard-core/src/layout.rs#path derivation from environment and identity",
  grant: "crates/idboard-acl/src/lib.rs#Identity::matches_grant role and wildcard grant matching",
  reg: "crates/idboard-acl/src/lib.rs#Config::from_toml pubkey registration no trust on first use",
  replay: "crates/idboard-store/src/lib.rs#Store::append monotonic sequence advance",
  readq: "crates/idboard-store/src/lib.rs#Store::read channel scoping cursor paging and row_to_message",
  token: "crates/idboard/src/relay.rs#constant_time_eq relay bearer token comparison",
  relayfill: "crates/idboard/src/relay.rs#Relay::dispatch wrapper fills sender seq timestamp signature",
  envbuild: "crates/idboard/src/wrapper.rs#spawn_child child environment construction and stripping",
  keystore: "crates/idboard/src/keystore.rs#Keystore::load_seed and save_seed key custody",
  lockacq: "crates/idboard/src/lock.rs#IdentityLock::try_acquire_at one wrapper per identity",
  render: "crates/idboard/src/cli.rs#render_message and cmd_post text output",
  tree: "workspace root#dependency manifest, lockfile, ignore rules, and build script surface",
};

const SUB = {
  d: "crates/idboardd",
  core: "crates/idboard-core",
  acl: "crates/idboard-acl",
  store: "crates/idboard-store",
  ipc: "crates/idboard-ipc",
  cli: "crates/idboard",
  ws: "workspace root all crates",
};

const EX = {
  noHttp: { block: "WEB-PROTOCOL-AND-AUTH.md#When to use this file", reason: "Source fact: no HTTP, TLS, session, cookie, JWT, or OAuth code path exists in the tree; transport is local named pipes and Unix domain sockets only." },
  noBrowser: { block: "CLIENT-SIDE.md#When to use this file", reason: "Source fact: no browser, webview, DOM, CORS, or service-worker code exists; output is plain CLI stdout." },
  noCloud: { block: "CLOUD-AND-DEPLOYMENT.md#When to use this file", reason: "Source fact: no cloud provider SDK, IAM, infrastructure-as-code, container, or service-mesh configuration exists in the tree." },
  noTenant: { block: "DATA-ISOLATION-AND-LIFECYCLE.md#When to use this file", reason: "Source fact: storage is one local SQLite file per daemon process with no object-link, export, backup, migration, deletion, or retention path." },
  noMem: { block: "MEMORY-SAFETY-AND-BINARY.md#When to use this file", reason: "Source fact: the workspace is safe Rust; the only unsafe blocks are edition-2024 test-helper environment mutation. No FFI, custom allocator, binary loader, JIT, or plugin loader exists." },
  noSup: { block: "SUPPLY-CHAIN-AND-RELEASE.md#When to use this file", reason: "Source fact: no CI workflow, build.rs, publish, release, code-signing, or plugin path exists in the tree; dependency hygiene is covered by the ordinary Obvious things unit." },
  noBroker: { block: `${PROTO}#${BROKER}`, reason: "Source fact: there is no broker, topic ACL, wildcard subscription, consumer group, partition, or dead-letter route. The board is a single SQLite table read with an explicit channel equality predicate at crates/idboard-store/src/lib.rs:270." },
  noDeepLink: { block: `${IPC}#Deep-link, callback, and navigation attack classes`, reason: "Source fact: the target registers no URI scheme, no file association, no share intent, and no custom protocol handler." },
  noBridge: { block: `${IPC}#Webview and native-bridge attack classes`, reason: "Source fact: no webview, no JavaScript bridge, and no remote frame is hosted or consumed by any binary in the tree." },
  noRegex: { block: `${RES}#${AMPLIFY}`, reason: "Source fact: no regular expression, no recursive-descent expansion, and no superlinear algorithm is reachable from peer input; framing is a linear newline scan and JSON decode." },
  noTool: { block: `${AI}#Tool and action attack classes`, reason: "Source fact: the target dispatches no tool, no model, and no sub-agent. It is a message bus whose consumer is an external process, so no model-mediated action binding exists in this repository." },
  noMcp: { block: `${AI}#MCP and sub-agent trust classes`, reason: "Source fact: no MCP client, server, transport, or metadata surface exists in the tree." },
  noStream: { block: `${PROTO}#${RPCID}`, reason: "Source fact: no streaming, batch, or per-item authorization surface exists; every request is one frame and one operation (crates/idboard-ipc/src/lib.rs:200-241)." },
};

// Each entry: [surface, boundary, subsystem, ordinary class, paths, companions, exclusions]
const UNITS = [
  {
    id: "u-dispatch-order",
    refs: [SURF.dreq, BND.dispatch, SUB.d, AC + "Access control"],
    paths: ["crates/idboardd/src/lib.rs", "crates/idboard-core/src/keys.rs", "crates/idboard-core/src/envelope.rs", "crates/idboard-acl/src/lib.rs"],
    companions: [...protoSet([FRAMING, RPCID]), ...ipcSet([LOCALIPC])],
    excluded: [EX.noBroker, EX.noStream, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup],
    invariant: "Board::dispatch enforces version, then registration, then signature, then per-op invariants, then freshness, then ACL, and the key used for verification is always the one the config registers for the claimed name.",
  },
  {
    id: "u-authorize-verified",
    refs: [SURF.dreq, BND.authz, SUB.d, AC + "Chained vulnerabilities and trust boundaries"],
    paths: ["crates/idboardd/src/lib.rs", "crates/idboard-acl/src/lib.rs", "crates/idboard-store/src/lib.rs"],
    companions: [...protoSet([FRAMING, RPCID]), ...ipcSet([LOCALIPC])],
    excluded: [EX.noBroker, EX.noStream, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup],
    invariant: "The identity passed to the channel ACL decision and the identity persisted in the messages table are both derived from the verified config registration, never from the request.",
  },
  {
    id: "u-handshake-disclosure",
    refs: [SURF.dreq, BND.authz, SUB.d, AC + "Feature abuse and data leakage"],
    paths: ["crates/idboardd/src/lib.rs", "crates/idboard-core/src/keys.rs"],
    companions: protoSet([FRAMING, RPCID]),
    excluded: [EX.noBroker, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup],
    invariant: "The handshake op, which skips channel authorization entirely, discloses no more than the calling identity's own registered fingerprint, role, and last_seq counter.",
  },
  {
    id: "u-serve-pool",
    refs: [SURF.dpipe, BND.serve, SUB.d, AC + "Business logic"],
    paths: ["crates/idboardd/src/main.rs", "crates/idboardd/src/lib.rs", "crates/idboard-ipc/src/lib.rs"],
    companions: [...resSet([QUOTA, FAILREC]), ...ipcSet([LOCALIPC, APPLIFE])],
    excluded: [EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noDeepLink, EX.noBridge],
    invariant: "An unauthenticated local peer cannot retain a worker slot, the single Board mutex, or the bounded work queue indefinitely, and cannot stop the daemon from serving other identities.",
  },
  {
    id: "u-pipe-deadline",
    refs: [SURF.dpipe, BND.iodeadline, SUB.ipc, AC + "Business logic"],
    paths: ["crates/idboard-ipc/src/lib.rs", "crates/idboardd/src/main.rs"],
    companions: resSet([ACCUM, QUOTA, FAILREC]),
    excluded: [EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noRegex],
    invariant: "Every read of peer-controlled bytes on the primary platform terminates, so a connection that sends no newline cannot hold a worker, the board lock, or a socket handle for an unbounded time.",
  },
  {
    id: "u-framing",
    refs: [SURF.wire, BND.frame, SUB.ipc, AC + "Injection"],
    paths: ["crates/idboard-ipc/src/lib.rs", "crates/idboard-core/src/wire.rs", "crates/idboard-core/src/ids.rs"],
    companions: [...protoSet([FRAMING]), ...resSet([ACCUM])],
    excluded: [EX.noBroker, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noRegex],
    invariant: "A single frame is unambiguously delimited and size-bounded before any decode, unknown and duplicate fields cannot change the interpreted value, and no peer-controlled value reaches a query, path, or spawn.",
  },
  {
    id: "u-verify-point",
    refs: [SURF.dreq, BND.verify, SUB.core, AC + "Cryptography and secrets"],
    paths: ["crates/idboard-core/src/keys.rs", "crates/idboardd/src/lib.rs", "crates/idboard-acl/src/lib.rs", "crates/idboard-core/src/envelope.rs"],
    companions: [...protoSet([FRAMING, RPCID]), ...ipcSet([LOCALIPC])],
    excluded: [EX.noBroker, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup],
    invariant: "Signature verification happens in exactly one place, always with the config-registered key, always with strict verification, and no request-supplied key or weak low-order key can ever reach it.",
  },
  {
    id: "u-canonical-bytes",
    refs: [SURF.canon, BND.signed, SUB.core, AC + "Cryptography and secrets"],
    paths: ["crates/idboard-core/src/envelope.rs", "crates/idboard-core/src/wire.rs", "crates/idboard-core/src/keys.rs"],
    companions: protoSet([FRAMING, REPLAY]),
    excluded: [EX.noBroker, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noRegex],
    invariant: "The signed byte string is unambiguous, covers every field that carries security meaning, is domain-separated, and cannot be made to collide across field boundaries or across protocol versions.",
  },
  {
    id: "u-op-invariants",
    refs: [SURF.dreq, BND.opinv, SUB.core, AC + "Business logic"],
    paths: ["crates/idboard-core/src/envelope.rs", "crates/idboardd/src/lib.rs", "crates/idboard-store/src/lib.rs"],
    companions: protoSet([FRAMING, REPLAY]),
    excluded: [EX.noBroker, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noRegex],
    invariant: "The two authentication mechanisms cannot borrow from each other: a post cannot pass without a positive sequence number and no nonce, and a read or handshake cannot pass with a sequence number or without a nonce.",
  },
  {
    id: "u-env-paths",
    refs: [SURF.envpath, BND.path, SUB.core, AC + "Resource and file handling"],
    paths: ["crates/idboard-core/src/layout.rs", "crates/idboard-core/src/ids.rs", "crates/idboardd/src/main.rs", "crates/idboard/src/wrapper.rs"],
    companions: [...ipcSet([PRIVFILE]), ...protoSet([FRAMING])],
    excluded: [EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noDeepLink, EX.noBridge],
    invariant: "No environment value and no identity string can steer a path outside the intended state root, and every file the tree touches is reached through a validated, confined name.",
  },
  {
    id: "u-acl-grants",
    refs: [SURF.cfg, BND.grant, SUB.acl, AC + "Access control"],
    paths: ["crates/idboard-acl/src/lib.rs", "crates/idboardd/src/lib.rs"],
    companions: [...ipcSet([PRIVFILE, APPLIFE]), ...protoSet([RPCID])],
    excluded: [EX.noBroker, EX.noStream, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup],
    invariant: "A grant matches only the identity or role the operator named, a role shared by more than one identity never silently widens authority, and an unresolvable or empty grant fails closed.",
  },
  {
    id: "u-registration",
    refs: [SURF.cfg, BND.reg, SUB.acl, AC + "Cryptography and secrets"],
    paths: ["crates/idboard-acl/src/lib.rs", "crates/idboard-store/src/lib.rs", "crates/idboard-core/src/keys.rs"],
    companions: [...ipcSet([PRIVFILE]), ...protoSet([RPCID])],
    excluded: [EX.noBroker, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup],
    invariant: "No key is ever learned from a message, a missing or unusable pubkey is a hard load failure, and a changed key is surfaced without resetting the identity's counter or its authority silently.",
  },
  {
    id: "u-replay-counter",
    refs: [SURF.dreq, BND.replay, SUB.store, AC + "Business logic"],
    paths: ["crates/idboard-store/src/lib.rs", "crates/idboardd/src/lib.rs"],
    companions: protoSet([REPLAY, RPCID]),
    excluded: [EX.noBroker, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noRegex],
    invariant: "A sequence number is accepted strictly once per identity, is advanced atomically with the message insert, is never lowered by a daemon restart, a key rotation, or a rejected post, and cannot be reused through any parallel path.",
  },
  {
    id: "u-store-read",
    refs: [SURF.db, BND.readq, SUB.store, AC + "Chained vulnerabilities and trust boundaries"],
    paths: ["crates/idboard-store/src/lib.rs", "crates/idboardd/src/lib.rs", "crates/idboard-core/src/envelope.rs"],
    companions: protoSet([FRAMING, RPCID, REPLAY]),
    excluded: [EX.noBroker, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noRegex],
    invariant: "A read discloses only rows for the channel the verified identity is authorized for, and the value a reader reconstructs from storage is the same value that was authenticated on the way in.",
  },
  {
    id: "u-relay-token",
    refs: [SURF.relay, BND.token, SUB.cli, AC + "Access control"],
    paths: ["crates/idboard/src/relay.rs", "crates/idboard-core/src/layout.rs", "crates/idboard/tests/e2e.rs"],
    companions: [...ipcSet([LOCALIPC]), ...protoSet([RPCID])],
    excluded: [EX.noBroker, EX.noStream, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noDeepLink, EX.noBridge],
    invariant: "Every relay operation, including identity disclosure, requires the per-invocation token, the comparison is constant time for equal-length inputs, and the token is drawn from the system CSPRNG.",
  },
  {
    id: "u-relay-fill",
    refs: [SURF.relay, BND.relayfill, SUB.cli, AC + "Chained vulnerabilities and trust boundaries"],
    paths: ["crates/idboard/src/relay.rs", "crates/idboard-core/src/wire.rs", "crates/idboard-core/src/keys.rs", "crates/idboard/src/client.rs"],
    companions: [...ipcSet([LOCALIPC]), ...protoSet([FRAMING, RPCID])],
    excluded: [EX.noBroker, EX.noStream, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noDeepLink, EX.noBridge],
    invariant: "Every identity-bearing field on a relayed envelope is filled by the wrapper from its own signer, a peer cannot introduce or override one, and a relayed envelope is byte-for-byte the envelope the daemon authenticates.",
  },
  {
    id: "u-child-env",
    refs: [SURF.wrap, BND.envbuild, SUB.cli, AC + "Chained vulnerabilities and trust boundaries"],
    paths: ["crates/idboard/src/wrapper.rs", "crates/idboard/src/client.rs", "crates/idboard-core/src/layout.rs"],
    companions: [...ipcSet([LOCALIPC, PRIVFILE]), ...protoSet([RPCID])],
    excluded: [EX.noBroker, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noDeepLink, EX.noBridge],
    invariant: "The spawned child receives no key and no path to the daemon or the config, holds exactly the relay path and the relay token, and cannot obtain any capability beyond the identity the wrapper already had.",
  },
  {
    id: "u-key-custody",
    refs: [SURF.keyfile, BND.keystore, SUB.cli, AC + "Cryptography and secrets"],
    paths: ["crates/idboard/src/keystore.rs", "crates/idboard/src/cli.rs", "crates/idboard-core/src/layout.rs", "crates/idboard-core/src/ids.rs"],
    companions: [...ipcSet([PRIVFILE, APPLIFE]), ...protoSet([REPLAY])],
    excluded: [EX.noBroker, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noDeepLink, EX.noBridge],
    invariant: "A key file holds exactly one 32-byte seed, is never silently replaced or clobbered, is created and renamed atomically, and is readable only by the account the design intends to own it.",
  },
  {
    id: "u-identity-lock",
    refs: [SURF.lock, BND.lockacq, SUB.cli, AC + "Business logic"],
    paths: ["crates/idboard/src/lock.rs", "crates/idboard/src/wrapper.rs", "crates/idboard-core/src/layout.rs"],
    companions: ipcSet([LOCALIPC, APPLIFE, PRIVFILE]),
    excluded: [EX.noBroker, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noDeepLink, EX.noBridge],
    invariant: "At most one wrapper holds an identity's authority at a time, the lock is taken before any key is loaded or any child is spawned, and lock state plus the pid file cannot be forged into a second live holder or a permanent false denial.",
  },
  {
    id: "u-output-render",
    refs: [SURF.out, BND.render, SUB.cli, AC + "Feature abuse and data leakage"],
    paths: ["crates/idboard/src/cli.rs", "crates/idboard/src/relay.rs", "crates/idboard-core/src/ids.rs", "crates/idboard/tests/e2e.rs"],
    companions: [...aiSet([CTXMEM, OUTDISC]), ...ipcSet([LOCALIPC])],
    excluded: [EX.noBroker, EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup, EX.noDeepLink, EX.noBridge, EX.noTool, EX.noMcp],
    invariant: "A message body written by one identity cannot change the terminal state, the rendered interpretation, or the disclosed context of an operator or another agent reading it, and the signed provenance claim is never treated as a policy input.",
  },
  {
    id: "u-tree-hygiene",
    refs: [SURF.tree, BND.tree, SUB.ws, AC + "Obvious things"],
    paths: ["Cargo.toml", "Cargo.lock", ".gitignore", "scripts/test.ps1", "README.md", "AGENTS.md"],
    companions: [],
    excluded: [EX.noHttp, EX.noBrowser, EX.noCloud, EX.noTenant, EX.noMem, EX.noSup],
    invariant: "No secret, credential, debug bypass, or ungated build or test path exists in the tree, and every dependency is resolved from a pinned lockfile entry.",
  },
];

const ledger = UNITS.map((u) => {
  const canonical = {
    surface: u.refs[0],
    boundary: u.refs[1],
    subsystem: u.refs[2],
    attack_class: u.refs[3],
  };
  return {
    coverage_id: canonicalCoverageId(canonical),
    canonical_refs: canonical,
    surface: canonical.surface,
    boundary: canonical.boundary,
    subsystem: canonical.subsystem,
    attack_class: canonical.attack_class,
    starting_paths: u.paths,
    ordinary_attack_class_block: canonical.attack_class,
    selected_companion_blocks: u.companions,
    // A block cannot be both selected and excluded. Where a unit selects a companion
    // section wholesale, any exclusion entry naming that same section is dropped
    // rather than recorded as a contradiction.
    excluded_blocks: u.excluded.filter((e) => !u.companions.includes(e.block)),
    parent_invariant: u.invariant,
    prior_status: "none",
    attempts: [],
    wave: 1,
    status: "planned",
    agent_id: null,
    reviewed_paths: [],
    local_checks: [],
    result_fingerprints: [],
    unresolved: [],
  };
});

ledger.sort((a, b) => (a.coverage_id < b.coverage_id ? -1 : a.coverage_id > b.coverage_id ? 1 : 0));

const seen = new Set();
for (const unit of ledger) {
  if (seen.has(unit.coverage_id)) throw new Error(`duplicate coverage_id ${unit.coverage_id}`);
  seen.add(unit.coverage_id);
}

fs.writeFileSync(out, JSON.stringify(ledger, null, 2) + "\n", "utf8");
console.log(`wrote ${ledger.length} units to ${out}`);
