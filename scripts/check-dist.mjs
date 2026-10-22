#!/usr/bin/env node
// Every file a publishable package's manifest points at must exist: `main`,
// `module`, `types`, every `bin`, and every string target in the `exports` map. release.yml
// runs this after restoring the dist artifact built by the secretless job, so
// a partial artifact fails before anything is published.
//
//   node scripts/check-dist.mjs [<repo-root>]
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(process.argv[2] ?? path.join(path.dirname(fileURLToPath(import.meta.url)), '..'));
const targets = (v) => (typeof v === 'string' ? [v] : v && typeof v === 'object' ? Object.values(v).flatMap(targets) : []);
const workspaces = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).workspaces ?? [];
let missing = 0;
let checked = 0;
let packages = 0;
for (const ws of workspaces) {
  const pjPath = path.join(root, ws, 'package.json');
  if (!fs.existsSync(pjPath)) continue;
  const pj = JSON.parse(fs.readFileSync(pjPath, 'utf8'));
  if (pj.private) continue;
  packages++;
  const files = new Set([pj.main, pj.module, pj.types, ...targets(pj.bin), ...targets(pj.exports)].filter(Boolean));
  for (const f of files) {
    checked++;
    if (!fs.existsSync(path.join(root, ws, f))) {
      missing++;
      console.error(`::error::${pj.name}: ${f} is missing`);
    }
  }
}
if (packages === 0) throw new Error('no publishable workspaces found');
console.log(`check-dist: ${checked - missing}/${checked} manifest targets present across ${packages} packages`);
process.exit(missing ? 1 : 0);
