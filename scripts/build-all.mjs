#!/usr/bin/env node
// Build every publishable anchors package to dist in dependency (topological)
// order, so a dependent never compiles before its deps' dist exists.
//
// Why this exists: each package's `prepack` ran `build-anchor-pkg.mjs`, which
// CLEANS dist then rebuilds. During `changeset publish` that fired per package
// in publish order and raced the dependency graph — a dependent's tsc read a
// dependency's dist while that dependency's prepack had just wiped it, so ~half
// the packages failed mid-publish with "command failed: sh -c npm run build".
// Building everything once, in toposort order, up front removes the race.
// `release.mjs` runs this and then publishes with `ignore-scripts` so prepack
// does not re-run (and re-introduce the race) during the publish itself.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const rootPkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

// Resolve the workspace globs we actually use (`dir/*` and bare `dir`).
const dirs = [];
for (const ws of rootPkg.workspaces || []) {
  if (ws.endsWith('/*')) {
    const base = path.join(root, ws.slice(0, -2));
    if (!fs.existsSync(base)) continue;
    for (const e of fs.readdirSync(base, { withFileTypes: true }))
      if (e.isDirectory()) dirs.push(path.join(base, e.name));
  } else {
    dirs.push(path.join(root, ws));
  }
}

// A package is buildable iff it ships dist via tsconfig.build.json. This is the
// same gate the migration used — it excludes the root, e2e, private
// anchor-contracts, the un-migrated raw-src aar-tsl, and the templates.
const nodes = new Map(); // name -> { dir, deps:Set<string> }
for (const dir of dirs) {
  const pjPath = path.join(dir, 'package.json');
  if (!fs.existsSync(pjPath)) continue;
  if (!fs.existsSync(path.join(dir, 'tsconfig.build.json'))) continue;
  const pj = JSON.parse(fs.readFileSync(pjPath, 'utf8'));
  if (!pj.name || pj.private) continue;
  nodes.set(pj.name, { dir, deps: new Set(Object.keys(pj.dependencies || {})) });
}

// Topological sort over workspace-internal edges only (external deps ignored).
const order = [];
const done = new Set();
const onStack = new Set();
function visit(name) {
  if (done.has(name)) return;
  if (onStack.has(name)) throw new Error(`dependency cycle through ${name} — graph must be acyclic`);
  onStack.add(name);
  for (const dep of nodes.get(name).deps) if (nodes.has(dep)) visit(dep);
  onStack.delete(name);
  done.add(name);
  order.push(name);
}
for (const name of nodes.keys()) visit(name);

console.log(`build-all: ${order.length} packages in topological order`);
for (const name of order) {
  process.stdout.write(`  ${name} ... `);
  execFileSync('npm', ['run', 'build'], { cwd: nodes.get(name).dir, stdio: ['ignore', 'ignore', 'inherit'] });
  console.log('ok');
}
console.log('build-all: done');
