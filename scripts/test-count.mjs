#!/usr/bin/env node
/**
 * Family-wide test-count gate — Phase E Task 24.
 *
 * Sums `# tests ` across every workspace and exits non-zero if the total
 * drops below TARGET. Run from the repository root or via npm script.
 *
 * Per-workspace test runner is `npm test` (which each workspace defines).
 * The summed line is grepped from `node --test`'s TAP summary — we DO NOT
 * trust `npm test --workspaces --if-present` aggregation, which silently
 * drops counts.
 *
 * Usage:
 *   node scripts/test-count.mjs
 *   node scripts/test-count.mjs --json
 */

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const TARGET = 250;

const WORKSPACES = [
  "envelope",
  "apr/apr-verifier",
  "apr/apr-issuer-kit",
  "acr/acr-verifier",
  "acr/acr-issuer-kit",
  "acr/acr-profiles",
  "arr/arr-verifier",
  "arr/arr-issuer-kit",
  "arr/arr-profiles",
  "did-web-resolver",
  "meta",
  "e2e",
];

const __dirname = dirname(fileURLToPath(import.meta.url));
const ANCHORS_ROOT = resolve(__dirname, "..");

const jsonOut = process.argv.includes("--json");
const perWs = [];
let total = 0;
let totalFail = 0;

for (const ws of WORKSPACES) {
  const cwd = resolve(ANCHORS_ROOT, ws);
  let out = "";
  try {
    out = execFileSync("npm", ["test", "--silent"], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    // Test runner may exit non-zero on test failures — capture its stdout anyway.
    out = (err.stdout ?? "") + (err.stderr ?? "");
  }
  const lines = out.split(/\r?\n/);
  const tests = lines
    .filter((l) => /^# tests\s+\d+/.test(l))
    .reduce((s, l) => s + Number(l.match(/^# tests\s+(\d+)/)[1]), 0);
  const fails = lines
    .filter((l) => /^# fail\s+\d+/.test(l))
    .reduce((s, l) => s + Number(l.match(/^# fail\s+(\d+)/)[1]), 0);
  perWs.push({ workspace: ws, tests, fails });
  total += tests;
  totalFail += fails;
}

if (jsonOut) {
  process.stdout.write(
    JSON.stringify({ target: TARGET, total, fails: totalFail, workspaces: perWs }, null, 2) + "\n",
  );
} else {
  for (const { workspace, tests, fails } of perWs) {
    console.log(`${workspace.padEnd(24)} tests=${String(tests).padStart(4)} fail=${fails}`);
  }
  console.log("=".repeat(50));
  console.log(`TOTAL tests=${total} fails=${totalFail} (target ≥ ${TARGET})`);
}

if (totalFail > 0) {
  console.error(`FAIL: ${totalFail} failing test(s).`);
  process.exit(2);
}
if (total < TARGET) {
  console.error(`FAIL: ${TARGET - total} test(s) short of target.`);
  process.exit(1);
}
