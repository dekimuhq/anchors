#!/usr/bin/env node --experimental-strip-types --no-warnings
/**
 * CLI wrapper for the cross-issuer handshake.
 *
 * Usage:
 *   node --experimental-strip-types scripts/run.ts did:web:competitor.com
 *
 * Fetches the issuer's manifest, verifies it, and prints a markdown report.
 * Test-vector exchange is skipped in CLI mode (no receipt verifier wired).
 */

import { runHandshake } from "../src/handshake.ts";

const iss = process.argv[2];
if (!iss || !iss.startsWith("did:web:")) {
  process.stderr.write("Usage: run.ts <did:web:domain>\n");
  process.exit(1);
}

const report = await runHandshake({ iss });

// --- Markdown report ---

const lines: string[] = [];

lines.push(`# Handshake Report: ${report.iss}`);
lines.push("");
lines.push(`- **Manifest URL:** ${report.manifest_url}`);
lines.push(`- **Started:** ${report.started_at}`);
lines.push(`- **Completed:** ${report.completed_at}`);
lines.push(`- **Overall:** ${report.overall.toUpperCase()}`);
lines.push("");

lines.push("## Steps");
lines.push("");
lines.push("| Step | Result | Detail |");
lines.push("|------|--------|--------|");
for (const s of report.steps) {
  lines.push(`| ${s.step} | ${s.ok ? "PASS" : "FAIL"} | ${s.detail} |`);
}
lines.push("");

if (report.test_vectors.length > 0) {
  lines.push("## Test Vectors");
  lines.push("");
  lines.push("| Family | Status | Detail |");
  lines.push("|--------|--------|--------|");
  for (const tv of report.test_vectors) {
    lines.push(`| ${tv.family} | ${tv.status.toUpperCase()} | ${tv.detail} |`);
  }
  lines.push("");
}

if (report.warnings.length > 0) {
  lines.push("## Warnings");
  lines.push("");
  for (const w of report.warnings) {
    lines.push(`- ${w}`);
  }
  lines.push("");
}

if (report.manifest) {
  lines.push("## Manifest Summary");
  lines.push("");
  lines.push(`- **Issuer:** ${report.manifest.iss}`);
  lines.push(`- **Operator:** ${report.manifest.operator.name} (${report.manifest.operator.jurisdiction})`);
  lines.push(`- **Key Doc:** ${report.manifest.key_doc_uri}`);
  lines.push(`- **Families:** ${report.manifest.memberships.map((m) => m.family).join(", ")}`);
  lines.push(`- **Valid until:** ${report.manifest.valid_until}`);
  lines.push("");
}

process.stdout.write(lines.join("\n") + "\n");
process.exit(report.overall === "pass" ? 0 : 1);
