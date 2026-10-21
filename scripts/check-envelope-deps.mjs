#!/usr/bin/env node

/**
 * Guards the anchors envelope dependency ranges against publish hazards.
 *
 * The trap: a family
 * that registers a new envelope claim_type must depend on an envelope version that
 * actually knows that claim_type, or `defineFamily` throws on a fresh install. With
 * 0.x semver, `^0.18.1` resolves to `>=0.18.1 <0.19.0` — it will NOT pick up 0.23.x —
 * so a stale caret silently pins a family to an old envelope.
 *
 * This linter flags the unambiguous hazards (zero false positives):
 *   1. Non-caret / floating ranges on a PUBLISHABLE package — `*`, `workspace:*`,
 *      `latest`, range operators. Publishing these ships an unpredictable range to
 *      consumers. (Private packages and templates/ scaffolds are exempt — `workspace:*`
 *      is correct there.)
 *   2. A caret whose lower-bound minor EXCEEDS the envelope's currently-published
 *      minor — i.e. it references an envelope that does not exist yet.
 *
 * It also prints the caret-minor distribution vs the current envelope as INFO, so a
 * release owner can see at a glance whether the family carets need normalizing (the
 * precise "which family needs which minor" decision stays human — it depends on which
 * envelope minor introduced each claim_type, which is not encoded in the manifests).
 *
 * Exit 0 = no hazards. Exit 1 = at least one floating range or future-minor caret.
 *
 * Usage:  node scripts/check-envelope-deps.mjs   (run from the repository root)
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const ANCHORS_ROOT = join(here, "..");
const DEP = "@dekimuhq/anchors-envelope";

const envVersion = JSON.parse(readFileSync(join(ANCHORS_ROOT, "envelope", "package.json"), "utf-8")).version;
const envMinor = Number(envVersion.split(".")[1]);

// Walk anchors/ for package.json files (skip node_modules, templates, the envelope itself).
function findPackageJsons(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "templates" || name === ".git") continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) findPackageJsons(p, acc);
    else if (name === "package.json") acc.push(p);
  }
  return acc;
}

const CARET = /^\^(\d+)\.(\d+)\.(\d+)/;
const EXACT = /^\d+\.\d+\.\d+$/;

const errors = [];
const caretMinors = new Map(); // minor -> count, for the INFO distribution

for (const pj of findPackageJsons(ANCHORS_ROOT)) {
  const json = JSON.parse(readFileSync(pj, "utf-8"));
  if (json.name === DEP) continue;
  const range = json.dependencies?.[DEP] ?? json.peerDependencies?.[DEP];
  if (!range) continue;
  const rel = pj.replace(ANCHORS_ROOT + "/", "");
  const publishable = json.private !== true;

  const caret = CARET.exec(range);
  if (caret) {
    const minor = Number(caret[2]);
    caretMinors.set(minor, (caretMinors.get(minor) ?? 0) + 1);
    if (minor > envMinor)
      errors.push(`${json.name} (${rel}): ${DEP} ${range} references envelope minor ${minor} > current published ${envVersion}`);
    continue;
  }
  if (EXACT.test(range)) continue; // exact pin is not a hazard
  if (publishable)
    errors.push(`${json.name} (${rel}): publishable package has non-caret ${DEP} range "${range}" — pin to ^${envVersion} (or the minor that introduced its claim_type)`);
}

console.log(`envelope current: ${envVersion}  (minor ${envMinor})`);
console.log("caret-minor distribution among dependents:");
for (const [minor, count] of [...caretMinors.entries()].sort((a, b) => a[0] - b[0]))
  console.log(`  ^0.${minor}.x  x${count}${minor < envMinor ? "  (behind current - verify these families do not need a newer claim_type)" : ""}`);

if (errors.length === 0) {
  console.log("\n✓ No envelope-dependency publish hazards.");
  process.exit(0);
}
console.error("\n✗ Envelope dependency hazards:\n");
for (const e of errors) console.error("  - " + e);
process.exit(1);
