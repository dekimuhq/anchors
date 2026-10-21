## 0.5.3

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.
- Updated dependencies
  - @dekimuhq/anchors-envelope@0.26.2

## 0.5.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

## 0.4.2

### Patch Changes

- 57a7179: Break the verifier↔profiles dependency cycle in the 5 affected families (alr, anr,
  asr, acr, arr). The body-type leaf now lives in `<fam>-profiles` and is re-exported
  from `<fam>-verifier` via a `./body-types` subpath, so the dependency graph is one-way
  (`verifier → profiles → envelope`) and cold `build-all` no longer fails with TS2307.

  Manifest corrections surfaced by the relocation:

  - `acr-verifier` and `arr-verifier` now declare their `-profiles` package (they
    value-import it for dispatch but never declared it — a real consumer-facing missing
    dependency).
  - `acr-profiles` and `arr-profiles` now declare `@dekimuhq/anchors-envelope` directly
    (they imported its types but relied on the dropped verifier dep to pull it transitively).

  No public API change: every type/const remains importable from `@dekimuhq/<fam>-verifier`
  exactly as before. No wire-format or runtime-behaviour change — type-relocation only.

## 0.4.1

### Patch Changes

- e365570: Ship built `dist` (`*.js` + `*.d.ts`) instead of raw `src/*.ts`.

  Every publishable anchors package now publishes a compiled `dist` tree with declaration
  files, built via `tsc -p tsconfig.build.json` (`rewriteRelativeImportExtensions` rewrites
  `.ts` import specifiers to `.js`). `main`/`types`/`exports` point at `dist`; `files` drops
  `src`. The public type and runtime API is byte-identical — no source change, patch bump only.

  Fixes the `dekimu-packages` Release-CI block: consumers previously resolved these packages'
  types to raw `.ts` source, which forced `tsc` to descend into them and raised TS5097
  (`.ts` import extension) plus TS2305 (cross-version source skew). Shipping `dist`+`.d.ts`
  eliminates both — proven 2026-06-03: `dekimu-packages` workspaces typecheck goes from
  412×TS5097 + 19×TS2305 to 0 of each.

  `aar-tsl` is intentionally excluded (pre-existing `fast-xml-parser` declaration debt; nothing
  depends on it). Consumer apps keep their `transpilePackages` entries — they become harmless
  no-ops, and removing them is a separate, individually-verified pass.

- Updated dependencies [e365570]
  - @dekimuhq/anchors-envelope@0.18.1

## 0.4.0

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0

## 0.3.5

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0

## 0.3.4

### Patch Changes

- Align `@dekimuhq/anchors-envelope` dependency range to `^0.16.0` across all remaining families. These packages pinned `^0.13.0`, which cannot resolve the published envelope `0.16.0` (caret on a 0.x minor) — leaving the dependency range unsatisfiable for downstream consumers. Envelope 0.16.0 is additive (adds the mandate-aware `TsaState` type), so this is a metadata-only alignment with no behavior change.

## 0.1.1 — 2026-05-20

### Changed (dep-range only — no source changes)

- `@dekimuhq/anchors-envelope` range bumped `^0.5.0` → `^0.9.0` to align with the
  non-ASR family floor (ASR triple is on `^0.10.0` post-Phase-4; all other
  families on `^0.9.0`). Pure dep-floor refresh — profile validators consume
  only the `ProfileValidator` type contract; no 0.9.0 runtime surface
  exercised. Closes the final envelope dep-range alignment after the
  ABR/ANR/AIR sweep landed in `710c338`.

regression check: `grep -n '"@dekimuhq/anchors-envelope"' anchors/alr/alr-profiles/package.json` must report `^0.9.0`.

## 0.1.0 — 2026-05-18

### Added

- Initial skeleton (Phase 1 §A.1 of 10-spec batch).
