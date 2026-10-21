#!/usr/bin/env node

/**
 * Fails if any source file in a publishable anchors package changed
 * but no .changeset/[name].md file exists.
 *
 * Watches: [family]/[pkg]/src/, envelope/src/, meta/src/,
 *          did-web-resolver/src/, trusted-issuers/src/
 *
 * Usage:  node scripts/changeset-check.mjs
 * Exit 0 = ok (changeset present or no source changes)
 * Exit 1 = source changed without a changeset
 */

import { execFileSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { familyDiffPaths } from "../schema/families.mjs";

const root = new URL("..", import.meta.url).pathname;

// Check for pending changeset files (exclude config.json and README.md)
const changesetDir = join(root, ".changeset");
let hasChangeset = false;
try {
  const files = readdirSync(changesetDir);
  hasChangeset = files.some((f) => f.endsWith(".md") && f !== "README.md");
} catch {
  // .changeset dir missing = no changesets
}

if (hasChangeset) {
  console.log("✓ Changeset found.");
  process.exit(0);
}

// Detect changed source files vs main (falls back to HEAD~1 if on main)
let diffBase = "main";
try {
  const branch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
    encoding: "utf-8",
  }).trim();
  if (branch === "main") diffBase = "HEAD~1";
} catch {
  // default to main
}

// Source directories to watch — all publishable package src/ dirs.
// Paths are relative to the repository root.
// The per-family globs are DERIVED from schema/families/*.anchor.json (single
// source of truth) so this list can never silently drift behind a new family —
// the old hardcoded list had already lost `action` and `quality`. Stable infra
// packages (not manifest-backed families) stay listed explicitly.
const diffPaths = [
  "envelope/src",
  "meta/src",
  "did-web-resolver/src",
  "trusted-issuers/src",
  ...familyDiffPaths(),
];

let changedFiles = "";
try {
  // Run from the repository root so the paths above resolve
  changedFiles = execFileSync(
    "git",
    ["diff", "--name-only", diffBase, "--", ...diffPaths],
    { encoding: "utf-8", cwd: root },
  ).trim();
} catch {
  console.log("⚠ Could not diff — skipping changeset check.");
  process.exit(0);
}

if (!changedFiles) {
  console.log("✓ No source changes detected — no changeset needed.");
  process.exit(0);
}

const count = changedFiles.split("\n").length;
console.error(
  `✗ ${count} source file(s) changed without a changeset:\n${changedFiles}\n\nRun \`npx changeset\` to create one.`,
);
process.exit(1);
