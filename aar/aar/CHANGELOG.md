# Changelog

## 0.4.2

### Patch Changes

- `family.meta.spec_path` now points at the public spec (https://github.com/dekimuhq/anchors-spec/tree/main/aar) instead of an unpublished internal path.

## 0.4.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [28c64ff]
  - @dekimuhq/aar-profiles@0.4.1

## 0.3.3

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
  - @dekimuhq/aar-profiles@0.3.3
  - @dekimuhq/anchors-envelope@0.18.1

## 0.3.2

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/aar-profiles@0.3.2

## 0.3.1

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/aar-profiles@0.3.1

## 0.3.0

### Minor Changes

- db75e89: Wire AAR's per-event TSA mandate into verification. `applyAarTsaMandate` (FAMILY-CONSISTENCY §2: issuance+qts MANDATORY, else RECOMMENDED) was exported but never called, so a qts-issuance receipt with no TSA block verified as valid instead of hard-failing. `verifyReceipt` now applies the body-keyed mandate post-step, mirroring ABR/AIR. Behavior change: qts issuance receipts lacking a `tsa` block now fail with `reason: "tsa_required"`; other issuance/revocation events surface `tsa_state: "tsa_recommended"`.

### Patch Changes

- Updated dependencies [db75e89]
  - @dekimuhq/anchors-envelope@0.16.0
  - @dekimuhq/aar-profiles@0.3.0

## 0.2.1

### Patch Changes

- fix(aar): use ProfileValidator adapters in family manifest instead of raw body-typed validators

## 0.2.0

### Minor Changes

- c2f423e: feat: add qts_attestation_hash cross-sibling QTS upgrade field

### Patch Changes

- @dekimuhq/aar-profiles@0.2.0
