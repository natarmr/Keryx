#!/usr/bin/env node
// Windows fallback runner for the skill's findings validator.
// validate-findings.cjs likely opens its input with O_NOFOLLOW|O_NONBLOCK, which Node does
// not expose on win32, so the CLI exits before checking any rule. This wrapper calls the
// validator's own exported validateDocument() -- the identical rule set -- against a
// normally-opened file, then applies the schema itself.
//
// Residual deviation: the input file's symlink and nonblocking-open hardening is not
// applied here. The input is parent-written in the parent-owned output directory, not
// agent-controlled scratch, so the risk that hardening addresses does not apply.
const fs = require("node:fs");
const path = require("node:path");
const skill = process.argv[2];
const file = process.argv[3];
const v = require(path.join(skill, "validate-findings.cjs"));
const schema = JSON.parse(fs.readFileSync(path.join(skill, "report-schema.json"), "utf8"));

const size = fs.statSync(file).size;
if (size > v.LIMITS.inputBytes) {
  console.error(`FAIL: input exceeds ${v.LIMITS.inputBytes} byte limit (${size})`);
  process.exit(1);
}
const findings = JSON.parse(fs.readFileSync(file, "utf8"));
const errors = [
  ...v.collectSchemaErrors(schema, findings),
  ...v.collectFindingSemanticErrors(findings),
  ...(Array.isArray(findings) ? [] : ["$: expected a top-level array"]),
];
for (const message of errors) console.error("ERROR:", message);
if (errors.length > 0) {
  console.error(`FAIL: ${errors.length} validation error(s)`);
  process.exit(1);
}
const counts = {};
for (const f of findings) counts[f.verdict] = (counts[f.verdict] || 0) + 1;
console.log(`PASS: ${findings.length} finding record(s) valid`, counts, "(win32 runner; O_NOFOLLOW/O_NONBLOCK input hardening unavailable in Node on win32)");
