#!/usr/bin/env node

/**
 * Single source of truth for the anchors family roster.
 *
 * Globs `schema/families/*.anchor.json` — the per-family manifests that already
 * declare id, acronym, chip, claim_types, envelope, and packages — and derives
 * every roster any tool needs. Replaces the hardcoded family lists that drift
 * silently each time a new `ar.*` family ships (changeset-check diffPaths, the
 * build-all/postinstall lists, the verify registry).
 *
 * The top-level workspace directory under `anchors/` is the unscoped name of the
 * family's verifier package (`@dekimuhq/action` → `action`). This is asserted to
 * exist on disk — a mismatch throws loudly rather than silently dropping a family.
 *
 * NOTE: this is a real Node ESM module (fs access).
 */

import { readdirSync, readFileSync, existsSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FAMILIES_DIR = join(__dirname, "families");
const ANCHORS_ROOT = join(__dirname, "..");

/**
 * @returns {Array<{id,acronym,dir,chip,claimTypes,verifierPkg,envelope,manifestPath}>}
 *          sorted by chip ascending.
 */
export function families() {
  const out = [];
  for (const f of readdirSync(FAMILIES_DIR)) {
    if (!f.endsWith(".anchor.json")) continue;
    const manifestPath = join(FAMILIES_DIR, f);
    const m = JSON.parse(readFileSync(manifestPath, "utf-8"));
    const verifierPkg = m.packages?.verifier ?? "";
    const dir = verifierPkg.replace(/^@dekimuhq\//, "").split("/")[0];
    if (!dir) throw new Error(`${f}: manifest has no packages.verifier — cannot derive workspace dir`);
    const abs = join(ANCHORS_ROOT, dir);
    if (!existsSync(abs) || !statSync(abs).isDirectory())
      throw new Error(`${f}: derived workspace dir "anchors/${dir}" does not exist (verifier ${verifierPkg})`);
    out.push({
      id: m.id,
      acronym: m.acronym,
      dir,
      chip: m.chip ?? null,
      claimTypes: m.claim_types ?? [],
      verifierPkg,
      envelope: m.envelope ?? null,
      manifestPath,
    });
  }
  return out.sort((a, b) => (a.chip ?? 0) - (b.chip ?? 0));
}

/** Top-level workspace dir names, e.g. ["apr","acr",...,"trace"]. */
export function familyDirs() {
  return families().map((f) => f.dir);
}

/**
 * Per-family source-glob diff paths for change detection.
 * @param {string} prefix optional path prefix (default "": repository-root-relative paths)
 * @returns {string[]} e.g. ["apr/*\/src", ...]
 */
export function familyDiffPaths(prefix = "") {
  return familyDirs().map((d) => `${prefix ? `${prefix}/` : ""}${d}/*/src`);
}

/** Acronym → dir rows ({ fam, dir }), for tooling that audits every family. */
export function invariantFamilies() {
  return families().map((f) => ({ fam: f.acronym, dir: f.dir }));
}

// CLI: `node schema/families.mjs` prints the roster.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const rows = families();
  for (const r of rows) console.log(`chip${String(r.chip).padEnd(3)} ${r.acronym.padEnd(7)} ${r.dir.padEnd(12)} ${r.id}`);
  console.log(`\n${rows.length} families`);
  console.log("\nacronym → dir rows:");
  console.log(rows.map((r) => `  { fam: '${r.acronym}', dir: '${r.dir}' },`).join("\n"));
}
