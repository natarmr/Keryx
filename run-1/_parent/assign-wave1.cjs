#!/usr/bin/env node
// Assigns wave-1 ledger units to hunters and creates each agent's scratch/ + artifacts/ roots.
// Usage: node assign-wave1.cjs <run-dir> <wave> <plan-json>
// plan-json maps agentId -> array of coverage_id array indices into the sorted ledger.
const fs = require("node:fs");
const path = require("node:path");
const runDir = process.argv[2];
const wave = Number(process.argv[3] || 1);
const plan = JSON.parse(fs.readFileSync(process.argv[4], "utf8"));

const ledgerPath = path.join(runDir, "coverage-ledger.json");
const ledger = JSON.parse(fs.readFileSync(ledgerPath, "utf8"));
const sorted = [...ledger].sort((a, b) => (a.coverage_id < b.coverage_id ? -1 : a.coverage_id > b.coverage_id ? 1 : 0));

const assigned = new Map();
for (const [agentId, indices] of Object.entries(plan)) {
  const root = path.join(runDir, "agents", agentId);
  fs.mkdirSync(path.join(root, "scratch"), { recursive: true });
  fs.mkdirSync(path.join(root, "artifacts"), { recursive: true });
  for (const index of indices) {
    const unit = sorted[index];
    if (!unit) throw new Error(`index out of range: ${index}`);
    if (assigned.has(unit.coverage_id)) throw new Error(`unit assigned twice: ${unit.coverage_id}`);
    if (unit.status !== "planned") throw new Error(`unit not planned: ${unit.coverage_id} (${unit.status})`);
    assigned.set(unit.coverage_id, agentId);
    unit.status = "in_progress";
    unit.agent_id = agentId;
    unit.wave = wave;
  }
}

for (const unit of ledger) {
  if (unit.status === "planned") throw new Error(`unit left planned and unassigned: ${unit.coverage_id}`);
}

ledger.sort((a, b) => (a.coverage_id < b.coverage_id ? -1 : a.coverage_id > b.coverage_id ? 1 : 0));
fs.writeFileSync(ledgerPath, JSON.stringify(ledger, null, 2) + "\n", "utf8");
console.log(`assigned ${assigned.size} units across ${Object.keys(plan).length} agents (wave ${wave})`);
for (const [agentId, indices] of Object.entries(plan)) {
  const ids = indices.map((i) => `[${i}] ${sorted[i].subsystem} / ${sorted[i].attack_class.replace("ATTACK-CLASSES.md#", "")}`);
  console.log(`  ${agentId}:`);
  for (const line of ids) console.log(`      ${line}`);
}
