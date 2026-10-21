# @dekimuhq/anr-verifier changelog

## 0.7.2

### Patch Changes

- `family.meta.spec_path` now points at the public spec (https://github.com/dekimuhq/anchors-spec/tree/main/anr) instead of an unpublished internal path.

## 0.7.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [dd49239]
- Updated dependencies [28c64ff]
  - @dekimuhq/anchors-disclosure@0.3.0
  - @dekimuhq/anr-profiles@0.7.1

## 0.6.2

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

- Updated dependencies [57a7179]
  - @dekimuhq/anr-profiles@0.6.2

## 0.6.1

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
  - @dekimuhq/anr-profiles@0.6.1

## 0.6.0

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/anr-profiles@0.6.0

## 0.5.2

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/anr-profiles@0.5.2

## 0.5.1

### Patch Changes

- Align `@dekimuhq/anchors-envelope` dependency range to `^0.16.0` across all remaining families. These packages pinned `^0.13.0`, which cannot resolve the published envelope `0.16.0` (caret on a 0.x minor) — leaving the dependency range unsatisfiable for downstream consumers. Envelope 0.16.0 is additive (adds the mandate-aware `TsaState` type), so this is a metadata-only alignment with no behavior change.
- Updated dependencies
  - @dekimuhq/anr-profiles@0.5.1

## 0.5.0

### Minor Changes

- c2f423e: feat: add qts_attestation_hash cross-sibling QTS upgrade field

## 0.4.0 — 2026-05-20

### Added

- **`composeAnr` compose-warnings channel** (Phase 4D). Reverses the Phase 2 "compose DELIBERATELY OMITTED" posture per D-anchors-8 (internal design record, not published). Two informational warnings now flow on `FamilyVerifyResult.warnings` without poisoning `signature_valid`:
  - `lang_jurisdiction_mismatch` — single-receipt. Fires when the BCP 47 region subtag of `body.lang_tag` is a 2-letter ISO 3166-1 alpha-2 code that does NOT match `body.jurisdiction` (case-insensitive). Excludes `notice.translated` events (spec §4.5 omits `jurisdiction` on translations). Silent on missing region subtag, M.49 numeric regions (e.g. `es-419`), and the `"EU"` region-level reservation. Resolves spec §9 open question 4.
  - `base_unresolvable` — chain-walk via `opts.resolveReceiptById`. Fires on `notice.translated` only: when `body.base_anr_id` does not resolve through the caller-supplied resolver. Skipped silently when the resolver is undefined or the event is not a translation. Informational because base notices may be erased per Art. 17 independently from translations.
- Re-export `composeAnr` from `index.ts` for callers that want to invoke the callback directly outside the factory pipeline (mirrors `composeAir` / `composeAbr` re-exports).

### Changed

- `anrFamily.compose` is now wired to `composeAnr`. The Phase 2 manifest left this slot intentionally absent; Phase 4D fills it per the two-abstraction split documented in D-anchors-8 §3. `composition.ts` (offline ACR↔ANR corpus roll-up) is UNTOUCHED — the new `compose.ts` answers a different question (per-receipt informational signals at verify-time) and the two modules coexist with no friction.
- Envelope dep range `^0.9.0` → `^0.11.0`. Required to access `opts.resolveReceiptById` on `ComposeInput.opts` for the W2 chain-walk warning. Mirrors AIR Phase 4B-2 + ABR Phase 4C floor.

### Not in scope (re-homed by D-anchors-8)

- `notice_staleness_warning` (spec §4.1 line 197) — fires from ACR compose at verify-time when a `consent.collect@*` receipt's `body.anr_id` resolves to a stale `notice.presented`. ANR cannot see ACR receipts at its own verify-time. Re-homed to ACR Phase 4 (B.1.a — pickup gated on ACR Phase 4 scope landing).
- `subject_erased` (spec §6.4) — needs a `resolveReceiptsBySubject` primitive on `defineFamily()` that does not yet exist. Re-homed to a future cross-family compose surface (B.1.b).

### Migration

- 0.3.x callers see byte-equal results for receipts that exercise neither warning path. Callers that explicitly poll `FamilyVerifyResult.warnings` may now see `lang_jurisdiction_mismatch` or `base_unresolvable` strings appended. No type-level breaking change — `warnings?: string[]` was already the result shape.
- W2 chain-walk warning gated on `opts.resolveReceiptById` (envelope `^0.11.0`). Callers without a chain corpus do not need to wire this; the warning skips silently.

### Tests

- +21 compose tests in `test/compose.test.ts` covering: short-circuit on null/non-object body (1); W1 positive on `notice.presented` / `notice.re_presented` / `notice.acknowledged` / `notice.withdrawn` mismatch (4); W1 SILENT on `notice.translated` (1); W1 silent on no-region (1), M.49 numeric region (1), `EU` jurisdiction (1), case-insensitive match (1); W1 script-subtag-then-region parsing (1); W2 positive on null/undefined resolver returns (2); W2 negative on resolver hit (1); W2 silent on no resolver (1), non-translated event (1), non-string base_anr_id (1); W1+W2 independence cross-cut (1); ok:true invariant sweep across all 6 event types (1); resolver-throw bubble-up (1).
- 1 family.test.ts assertion flipped: `anrFamily.compose === undefined` → `typeof anrFamily.compose === "function"`. Other 11 canary tests unchanged.
- Floor: 154/154 tests (was 133 pre-Phase-4D).

regression check: `grep -n 'compose: composeAnr' anchors/anr/anr-verifier/src/family.ts` reports 1 hit; `grep -nE 'lang_jurisdiction_mismatch|base_unresolvable' anchors/anr/anr-verifier/src/compose.ts` reports ≥4 hits; `grep -n '\^0.11.0' anchors/anr/anr-verifier/package.json` reports 1 hit.

## 0.3.0 — 2026-05-19

### Changed

- Envelope dep range `^0.7.0` → `^0.9.0`. No source changes — pulls in the cross-issuer interop Phase A Slice 2 surface (trust dispatch + cross-family resolvers) shipped via shared `family-verify-pipeline.ts`. ANR is factory-based, so `FamilyVerifyOptions.verifyIssuerTrust` + `resolveArr` / `resolveAlr` / `resolveAtr` / `resolveApur` are now passthrough-available to ANR consumers without any verifier-side code change. Default-undefined preserves byte-equal verification — the new options are opt-in only.

### Migration

- Existing 0.2.x callers see byte-equal results when not supplying the new options. No code changes required.

regression check: `grep -n '\^0.9.0' anchors/anr/anr-verifier/package.json` reports 1 hit.

## 0.2.0 — 2026-05-19

### Added

- `anrFamily` — frozen `FamilyManifest<AnrBody>` built via `@dekimuhq/anchors-envelope`'s
  `defineFamily()` factory. Carries chip 10, status_list_slot 4, the per-event
  subject-presence callback (with reasons pre-mapped to envelope-level codes
  `subject_missing` / `subject_invalid_form`), the profile-keyed TSA mandate matrix,
  all five v1 profile validators, and continuity helpers. `compose` is
  deliberately omitted — `composition.ts` is an offline corpus tool, not a
  verifier-time walker.
- `anrBodyValidator` (`src/body-validator.ts`) — pass-through `BodyValidator<AnrBody>`
  adapter. Structural body validation continues to live in `verifyAnrBody`
  (`verify-single.ts`); the manifest's validator is intentionally permissive
  so legacy `verifyV2` callers preserve their "no body validation at envelope
  level" semantics.

### Changed (internal — public API of `verifyV2` is byte-equal)

- `src/envelope-v2.ts` collapsed onto `anrFamily.verifyReceipt`. 399 → 200 LOC.
  The wrapper bypasses the factory's single-profile dispatch (which would have
  broken the `opts.profileValidators` array surface) and re-applies the per-profile
  TSA mandate matrix to restore RECOMMENDED downgrade semantics (factory
  enforces MANDATORY only). The factory's `reason: "signature_invalid"`
  shortcut is normalised away to match legacy "reason undefined on sig fail"
  behaviour.

### Dependencies

- `@dekimuhq/anchors-envelope` bumped to `^0.7.0` (consumes `defineFamily()` factory
  Phase 1 extension — verify pipeline + Ed25519 helpers + continuity helpers).
- Added runtime dep on `@dekimuhq/anr-profiles ^0.2.0` so the manifest can wire
  the 5 v1 profile validators by reference. The type-only back-reference in
  `anr-profiles` is unchanged (it was always erased at runtime).

### Tests

- 121 → 133 (+12 `family.test.ts` coverage: identity invariants, per-event
  subject-presence rule, TSA mandate matrix, profile registration, manifest
  helper surfaces).

Plan: an internal design record (not published) Phase 2.

regression check: grep -n 'anrFamily' anr/anr-verifier/src/family.ts

## 0.1.0 — 2026-05-18

- Initial skeleton.
