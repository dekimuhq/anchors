# @dekimuhq/asr-profiles changelog

## 0.6.3

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.
- Updated dependencies
  - @dekimuhq/anchors-envelope@0.26.2

## 0.6.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

## 0.5.5

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

## 0.5.4

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

## 0.5.3

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0

## 0.5.2

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0

## 0.5.1

### Patch Changes

- Align `@dekimuhq/anchors-envelope` dependency range to `^0.16.0` across all remaining families. These packages pinned `^0.13.0`, which cannot resolve the published envelope `0.16.0` (caret on a 0.x minor) — leaving the dependency range unsatisfiable for downstream consumers. Envelope 0.16.0 is additive (adds the mandate-aware `TsaState` type), so this is a metadata-only alignment with no behavior change.

## 0.2.2 — 2026-05-20

### Changed — Phase 4 Step 11 (envelope ^0.10.0 range propagation)

- `@dekimuhq/anchors-envelope` dep range `^0.9.0` → `^0.10.0`. Keeps the
  family floor coherent at publish time with the Phase 4 compose-warnings
  channel landed in envelope 0.10.0 (`ComposeResult.warnings` widening +
  `FamilyVerifyOptions.findDisclosedAlrsForSubject` resolver). asr-profiles
  itself does not call into the compose surface; this is a transitive
  floor refresh only.

No surface change. Profile validators unchanged; no new tests.

## 0.2.1 — 2026-05-19

### Changed — Phase 3 Step 10 (envelope range propagation)

- `@dekimuhq/anchors-envelope` dep range `^0.7.0` → `^0.9.0`. The §G
  `composeAsr` surface in `asr-verifier@0.3.0` consumes envelope 0.9.0's
  `ComposeInput.envelope.iat` + 4-resolver `FamilyVerifyOptions`; aligning
  this kit keeps the family floor coherent at publish time even though
  asr-profiles itself does not call into the compose surface.

No surface change. Profile validators unchanged; no new tests.

## 0.2.0 — 2026-05-19

### Added — Phase 3 Step 7 (defineFamily() A.2-full plan)

Six v1 regulation profile validators (replaces the 0.1.0 skeleton). Each
ships as a pure `validate*` function plus a `*Profile` `ProfileValidator<AsrBody>`
adapter keyed by the `request.fulfilled` profile-extension semantics from
spec §5:

- **`art15.access`** (`subject_rights.art15.access`) — forbids Art. 17 / Art. 20
  cross-link fields (`arr_receipt_id`, `portability_format`,
  `portability_format_detail`, `objection_scope`, `balancing_test_hash`,
  `restriction_reason_code`) on `request.fulfilled`.
- **`art16.rectification`** (`subject_rights.art16.rectification`) — same
  cross-family forbid set as Art. 15.
- **`art17.erasure_request`** (`subject_rights.art17.erasure_request`) —
  MANDATORY `body.arr_receipt_id` on `request.fulfilled` per D10-ASR-3.
  Stale-link / subject-parity / claim_type pinning across the cited ARR
  receipt is deferred to Phase 3 §G compose.
- **`art18.restriction`** (`subject_rights.art18.restriction`) — MANDATORY
  `restriction_reason_code` closed enum (4 values, Art. 18(1)(a)–(d):
  `accuracy_contested`, `unlawful_processing`, `legal_claims`,
  `objection_pending`).
- **`art20.portability`** (`subject_rights.art20.portability`) — MANDATORY
  `portability_format` closed enum (7 values: `json`, `csv`, `xml`, `pdf`,
  `fhir`, `xbrl`, `other`); `other` requires `portability_format_detail`.
- **`art21.objection`** (`subject_rights.art21.objection`) — MANDATORY
  `objection_scope` closed enum (3 values: `direct_marketing`,
  `general_legitimate_interest`, `research`); `general_legitimate_interest`
  requires `balancing_test_hash`.

### Dependencies

- `@dekimuhq/anchors-envelope` pinned at `^0.7.0`.

### Tests

- 0 → 117. Clears the ≥99 per-package publish floor. Coverage spans all
  six profiles' positive paths, MANDATORY-field rejections, closed-enum
  rejections, cross-family-forbid rejections (Art. 15 / Art. 16), and
  conditional-field branches (Art. 20 `other`-requires-detail; Art. 21
  `general_legitimate_interest`-requires-`balancing_test_hash`).

### Deferred to Phase 3 §G compose

- ARR `arr_receipt_id` stale-link / subject-parity / claim_type pinning
  cross-walk (Art. 17 fulfilled).
- Art. 19 ALR cascade.
- Art. 20 ATR pair.
- Art. 21 APuR back-ref.

Plan: an internal design record (not published) Phase 3 Step 7.

regression check: grep -l 'validateArt' asr/asr-profiles/src/ | wc -l # → 6

## 0.1.0 — 2026-05-19

- Initial skeleton.
