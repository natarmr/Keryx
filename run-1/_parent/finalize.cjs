#!/usr/bin/env node
// Final parent-side state update: record Phase 3/5 outcomes and the terminal run status.
const fs = require("node:fs");
const path = require("node:path");
const runDir = process.argv[2];
const ledgerPath = path.join(runDir, "coverage-ledger.json");
const findings = JSON.parse(fs.readFileSync(path.join(runDir, "findings.json"), "utf8"));
const ledger = JSON.parse(fs.readFileSync(ledgerPath, "utf8"));
const metaPath = path.join(runDir, "run-metadata.json");
const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));

const finalFingerprints = new Set(findings.map((f) => f.fingerprint));
const UNVALIDATED = [
  "idboard/cli.rs:render_message:unescaped-body-in-operator-terminal",
  "idboard/keystore.rs:save_seed:ungated-check-then-act-replace",
];
const PHASE3_VERIFIED = ["idboardd.serve.board_mutex_held_across_peer_blocking_io", "idboard-ipc.apply_timeouts.unsupported_swallow_removes_read_deadline"];

const notes = {
  "idboard/cli.rs:render_message:unescaped-body-in-operator-terminal":
    "phase3_verifier_returned_result_but_output_was_truncated_before_the_record_completed; the verifier had already re-read every cited line, confirmed the mechanism, and issued material corrections (the README agent-facing contract recommends the JSON form for read but the plain form for subscribe, and a lower-trust poster acting within its own grant is inside the design's documented boundary, so the impact is rendered-attribution integrity rather than privilege gain). NOT independently validated to completion, NOT Phase 5 verified, and therefore deliberately EXCLUDED from findings.json rather than reported on incomplete evidence.",
  "idboard/keystore.rs:save_seed:ungated-check-then-act-replace":
    "phase3_verifier_result_lost_entirely_to_output_truncation; no verifier record survives. NOT independently validated and NOT Phase 5 verified, therefore deliberately EXCLUDED from findings.json. The hunter's source trace (check-then-act in cmd_keygen with no identity lock, versus the correctly-locked run_child path, plus the ungated load_or_create before the config membership check) remains available in the ledger unit and in _parent/candidates.json for a future run.",
};

for (const unit of ledger) {
  const unvalidated = unit.result_fingerprints.filter((fp) => UNVALIDATED.includes(fp));
  if (unvalidated.length === 0) continue;
  // Archive the hunter-authored terminal state, then leave the live state as an
  // unresolved candidate owned by no one, per the incomplete-run rule.
  unit.attempts.push({
    wave: unit.wave,
    status: "candidate",
    agent_id: unit.agent_id,
    reviewed_paths: unit.reviewed_paths.slice(),
    local_checks: unit.local_checks.slice(),
    result_fingerprints: unvalidated.slice(),
    unresolved: unvalidated.map((fp) => notes[fp]),
    reassignment_reason: "phase3 validation could not be completed for this candidate within run resources, so the hunter-authored candidate state is archived and the unit is left as an unresolved candidate for a future run rather than carried into findings.json on incomplete evidence.",
  });
  unit.wave = unit.wave + 1;
  unit.status = "deferred";
  unit.agent_id = null;
  unit.reviewed_paths = [];
  unit.local_checks = [];
  unit.result_fingerprints = [];
  unit.unresolved = unvalidated.map((fp) => `validation_budget_exhausted:${notes[fp]}`);
  unit.parent_candidate_origin = unvalidated.map((fp) => ({
    fingerprint: fp,
    agents: ["h-custody"],
    origin_units: unit.coverage_id,
    state: "candidate_recorded_in__parent/candidates.json_but_not_validated",
  }));
}

ledger.sort((a, b) => (a.coverage_id < b.coverage_id ? -1 : a.coverage_id > b.coverage_id ? 1 : 0));
fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2) + "\n", "utf8");

const counts = {};
for (const u of ledger) counts[u.status] = (counts[u.status] || 0) + 1;

meta.phase3_validation = {
  candidates_hunted: 8,
  candidates_validated: 6,
  validated_by: ["v-availability (2 records: idboardd.serve.board_mutex_held_across_peer_blocking_io, idboard-ipc.apply_timeouts.unsupported_swallow_removes_read_deadline)", "v-custody (4 records: idboard-ipc.read_frame.unbounded-envelope-strings.daemon-rejection-log, idboard-acl.Config.load.trust-root-file-read-without-custody-check, idboard-store.read-projection-drops-signed-channel, idboard-store.open-creates-state-root-without-private-mode)"],
  validation_outcome_counts: { confirmed: 0, needs_validation: 6, rejected: 0 },
  no_candidate_reached_confirmed: "No candidate could reach the confirmed bar because a confirmed record requires a bounded local observed result and the audit host provides no OS-enforced sandbox. This is an execution-capability consequence, not a clean result.",
  material_corrections_made_by_validators: [
    "The write-side trigger on the board-mutex record was REFUTED: pre-authentication responses are small and absorbed by the OS pipe buffer, so write_all does not block for an unauthenticated peer. The trigger was demoted from sink to evidence and the validation plan now explicitly forbids probing it.",
    "The impact scaling on the board-mutex record was corrected: the cross-identity effect begins with the FIRST connection from another identity, not one connect stopping the accept loop. The 67-connection figure is recorded as analytic, not observed, and the plan forbids testing it.",
    "The apply_timeouts record was re-attributed: the deadline belongs to the Stream handed over by accept/try_accept/connect, not to the generic read_frame_from, and the decisive fact (whether interprocess returns Unsupported or a real 10 s deadline) is third-party behaviour absent from the repository, so it was moved from an implicit assumption into an explicit blocker.",
    "The rejection-log record was broadened: the sink is reached on every !ok response, not only the two pre-cryptography branches.",
    "The state-root custody record was bounded: on the project's primary platform the two directory helpers are behaviourally identical, so the divergence is a Unix-only hardening gap, and a fourth permissive call site at crates/idboard/src/lock.rs:60 was found by the reviewer.",
    "The read-projection record was corrected twice: envelope.rs:212 is put_u16 not put_u32, and re-verification fails at keys.rs:282 structural validation rather than at verify_strict.",
    "The config trust-root record was narrowed to the only in-scope principal, a second non-administrative local account, because the design already excludes same-user and administrator.",
  ],
  candidates_not_validated: UNVALIDATED.map((fp) => ({ fingerprint: fp, reason: notes[fp] })),
};
meta.phase5_record_verification = {
  status: "not_run",
  reason: "Run resources were exhausted after Phase 3. Zero confirmed records exist, so the absolute rule against skipping independent review of a confirmed record is not violated, but the skill's requirement to independently verify final needs_validation records was NOT satisfied. All six records in findings.json therefore carry Phase 3 independent validation only, and no Phase 5 replacement pass was performed.",
};
meta.run_status = "incomplete";
meta.incomplete_reason = "validation_budget_exhausted_then_resource_exhaustion_before_phase_5";
meta.incomplete_detail = [
  "Two of eight candidates were not validated: idboard/cli.rs:render_message:unescaped-body-in-operator-terminal and idboard/keystore.rs:save_seed:ungated-check-then-act-replace. Both are archived in the coverage ledger as deferred units with their unresolved reasons and are deliberately excluded from findings.json. They are NOT findings and are not presented as such.",
  "Phase 5 independent record verification did not run. The six retained records carry Phase 3 validation only.",
  "The post-wave coverage critic accepted six missing units. They are seeded in the ledger as deferred wave-2 work with the critic's source-backed reasons. No wave-2 hunter ran, so the final-clean coverage critic never ran either.",
  "Zero confirmed records is a consequence of the static-only execution policy the user selected, not a clean bill of health. Every candidate that survived source review required an observation that could not be made on this host.",
];
meta.agents_spent = {
  reconnaissance: 4,
  wave1_hunters: 9,
  post_wave_coverage_critic: 1,
  phase3_validators: 2,
  phase5_record_verifiers: 0,
  total: 16,
};
meta.terminal_state = "(b) incomplete: run_status recorded with an exact reason and every gap disclosed in REPORT.md";
fs.writeFileSync(metaPath, JSON.stringify(meta, null, 2) + "\n", "utf8");

console.log("ledger:", counts);
console.log(`findings.json: ${findings.length} records, all needs_validation`);
console.log("run_status:", meta.run_status, "/", meta.incomplete_reason);
