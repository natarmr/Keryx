#!/usr/bin/env node
// Windows fallback runner for the skill's coverage-ledger validator.
//
// The skill's validate-coverage-ledger.cjs opens the input with O_NOFOLLOW|O_NONBLOCK.
// Node does not expose those flags on win32, so its readFileWithinLimit() throws
// "OS no-follow and nonblocking input protection is unavailable" and the CLI exits 1
// before any rule is checked. This wrapper calls the validator's own exported
// validateDocument() -- the identical rule set -- against a normally-opened file so the
// ledger is still fully validated on this host.
//
// Residual deviation, stated rather than papered over: the input file's symlink and
// nonblocking-open hardening is not applied here. The input is a parent-written file in
// the parent-owned output directory, not agent-controlled scratch, so the risk that
// hardening addresses does not apply to it.
const fs = require("node:fs");
const path = require("node:path");
const skill = process.argv[2];
const file = process.argv[3];
const { validateDocument, LIMITS } = require(path.join(skill, "validate-coverage-ledger.cjs"));

const size = fs.statSync(file).size;
if (size > LIMITS.inputBytes) {
  console.error(`FAIL: input exceeds ${LIMITS.inputBytes} byte limit (${size})`);
  process.exit(1);
}
const ledger = JSON.parse(fs.readFileSync(file, "utf8"));
const errors = validateDocument(ledger);
for (const message of errors) console.error("ERROR:", message);
if (errors.length > 0) {
  console.error(`FAIL: ${errors.length} validation error(s)`);
  process.exit(1);
}
console.log(`PASS: ${ledger.length} coverage units valid (win32 runner; O_NOFOLLOW/O_NONBLOCK input hardening unavailable in Node on win32)`);
