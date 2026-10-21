#!/usr/bin/env node
// Shared build step for every publishable anchors package.
// Run from a package dir (npm sets cwd to the package on `npm run build`).
//
// Three responsibilities the bare `tsc` emit can't cover on its own:
//   1. Clean dist first — tsc raises TS5055 ("would overwrite input file") when
//      a prior emit's .d.ts is still present on rebuild; a clean dir is deterministic.
//   2. Emit via tsconfig.build.json (declaration + rewriteRelativeImportExtensions).
//   3. Rewrite relative `.ts` import specifiers -> `.js` in the emitted .d.ts.
//      `rewriteRelativeImportExtensions` rewrites the .js output but leaves .d.ts
//      specifiers as `.ts`. Since the tarball ships only .js + .d.ts (never .ts),
//      a .d.ts that imports "./x.ts" is unresolvable for any consumer without
//      `skipLibCheck`. Normalize to ".js" so the types are correct everywhere.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

fs.rmSync('dist', { recursive: true, force: true });
// `tsc` is resolved from node_modules/.bin (npm puts it on PATH for run-scripts).
execFileSync('tsc', ['-p', 'tsconfig.build.json'], { stdio: 'inherit' });

const REL_TS = /(["'])(\.\.?\/[^"']*?)\.ts\1/g;
function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name.endsWith('.d.ts') || e.name.endsWith('.js')) {
      const src = fs.readFileSync(p, 'utf8');
      const out = src.replace(REL_TS, '$1$2.js$1');
      if (out !== src) fs.writeFileSync(p, out);
    }
  }
}
if (fs.existsSync('dist')) walk('dist');
