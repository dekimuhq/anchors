## 0.6.2

### Patch Changes

- `family.meta.spec_path` now points at the public spec (https://github.com/dekimuhq/anchors-spec/tree/main/abr) instead of an unpublished internal path.

## 0.6.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [dd49239]
- Updated dependencies [28c64ff]
  - @dekimuhq/anchors-disclosure@0.3.0
  - @dekimuhq/abr-profiles@0.6.1

## 0.5.1

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
  - @dekimuhq/abr-profiles@0.5.1
  - @dekimuhq/anchors-envelope@0.18.1

## 0.5.0

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/abr-profiles@0.5.0

## 0.4.3

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/abr-profiles@0.4.3

## 0.4.2

### Patch Changes

- Align `@dekimuhq/anchors-envelope` dependency range to `^0.16.0` across all remaining families. These packages pinned `^0.13.0`, which cannot resolve the published envelope `0.16.0` (caret on a 0.x minor) — leaving the dependency range unsatisfiable for downstream consumers. Envelope 0.16.0 is additive (adds the mandate-aware `TsaState` type), so this is a metadata-only alignment with no behavior change.
- Updated dependencies
  - @dekimuhq/abr-profiles@0.4.2

## 0.4.1

### Patch Changes

- ff64882: A.2-full Phase 4: export abrFamily from abr-verifier; collapse mintAbrV2 onto abrFamily.mintV2.

  abr-verifier: adds `export { abrFamily }` to package index.
  abr-issuer-kit: replaces hand-rolled signing pipeline with abrFamily.mintV2() delegate.
  ABR-specific field_root computation (computeFieldRoot), subject resolution, and 8-event-type
  validation guards retained. Public API unchanged.

## 0.4.0

### Minor Changes

- c2f423e: feat: add qts_attestation_hash cross-sibling QTS upgrade field

### Patch Changes

- @dekimuhq/abr-profiles@0.4.0

## 0.3.0 — 2026-05-20

### Added

- **`composeAbr` compose-warnings channel** (Phase 4C Task 3). Two informational warnings now flow on `FamilyVerifyResult.warnings` without poisoning `signature_valid`:
  - `clock_skew_warning` — single-receipt. On `breach.detected`, surfaces when `|envelope.iat − body.detected_at| > 5 minutes` (spec §3.1 row 1). Uses `envelope.iat` as the clock anchor rather than the strict TSA `genTime` because the compose surface does not currently expose the parsed TSA result; `breach.detected` MUST carry TSA per D10-ABR-2 so `iat ~ TSA.genTime` within drift tolerance.
  - `notification_overdue` — chain-walk. On `breach.dpa_notified`, surfaces when elapsed-from-detected exceeds the profile deadline (GDPR Art. 33: 72h; NIS2 Art. 23: 24h early_warning / 72h full_notification / 30d final_report). Suppressed by any prior `breach.dpa_delayed` in the chain (spec lines 232 + 363). Skipped silently when `opts.resolveReceiptById` is undefined or when the chain head is not a `breach.detected` event. Art. 34 / DORA / US-AG profiles silently skip — Art. 34 has no hard deadline ("undue delay"); DORA's 4h/72h/1mo phasing depends on a future spec amendment; US-AG deadlines require external per-state lookup.

### Changed

- `abrFamily.compose` is now wired to `composeAbr`. Phase 4C Task 1 (`06698f2`) left this slot intentionally absent; Task 3 fills it. Receipts that exercise neither warning verify byte-equal to 0.2.x — both warnings are additive.

### Migration

- 0.2.x callers see byte-equal results for receipts that exercise neither warning path. Callers that explicitly poll `FamilyVerifyResult.warnings` may now see `clock_skew_warning` or `notification_overdue` strings appended. No type-level breaking change — `warnings?: string[]` was already the result shape.
- New chain-walk warning gated on `opts.resolveReceiptById` (envelope `^0.11.0`). Callers without a chain corpus do not need to wire this; the warning skips silently.

### Tests

- +18 compose tests in `test/compose.test.ts` covering: clock_skew positive/negative/boundary/malformed/wrong-event (5), no-resolver short-circuit (1), GDPR Art. 33 deadline pass/miss (2), `breach.dpa_delayed` suppression (1), NIS2 three-phase deadlines (4), null notification_phase (1), Art. 34 / DORA / US-AG silent skip (1), dangling chain (1), event-type short-circuit (1), null body (1), resolver-throw bubble-up (1).
- 1 family.test.ts assertion flipped: `abrFamily.compose === undefined` → `typeof abrFamily.compose === "function"`. Other 12 canary tests unchanged.
- Floor: 197/197 tests (was 179 post-Task-2; 166 pre-Phase-4C).

regression check: `grep -n 'compose: composeAbr' anchors/abr/abr-verifier/src/family.ts` reports 1 hit; `grep -nE 'clock_skew_warning|notification_overdue' anchors/abr/abr-verifier/src/compose.ts` reports ≥4 hits.

## 0.2.0 — 2026-05-19

### Changed

- Envelope dep range `^0.6.2` → `^0.9.0`. No source changes — pulls in the cross-issuer interop Phase A Slice 2 surface (trust dispatch + cross-family resolvers) shipped via shared `family-verify-pipeline.ts`. ABR is factory-based, so `FamilyVerifyOptions.verifyIssuerTrust` + `resolveArr` / `resolveAlr` / `resolveAtr` / `resolveApur` are now passthrough-available to ABR consumers without any verifier-side code change. Default-undefined preserves byte-equal verification — the new options are opt-in only.

### Migration

- Existing 0.1.x callers see byte-equal results when not supplying the new options. No code changes required.

regression check: `grep -n '\^0.9.0' anchors/abr/abr-verifier/package.json` reports 1 hit.

## 0.1.2 — 2026-05-19

### Added

- §E per-event subject-presence rule (`src/subject-presence.ts`) per FAMILY-CONSISTENCY.md §3 + spec §3.1/§4.5/D10-ABR-4. `breach.subject_notified` MUST carry `subject: "sha256:<hex>"` (the Merkle batch root over affected-subject `sub_commit` leaves); every other event_type MUST carry `subject: null` (incident-level events are not subject-scoped — strictly null, not "either"). Stricter than ANR's per-event split.
- Public exports: `checkAbrSubjectPresence`, `applyAbrSubjectPresence`, `SubjectPresenceResult`, `SubjectPresenceReason`, `AbrSubjectPresenceTarget`.
- Wired into `verifyV2`: subject-presence runs after policy validation and before status reconciliation; envelope-level rejection. Reason codes (bare, no `body_invalid:` prefix): `subject_missing` (subject_notified/null), `subject_invalid_form` (subject_notified/non-sha256), `subject_present` (incident-level/non-null) — matches the bare-envelope-reason convention used by ANR + ALR siblings.
- Helper `test/_helpers/v2-receipt.ts`: `mintValidAbr()` now bakes the §E rule in by default (subject = `subject_batch_root` on `breach.subject_notified`, `null` on every other event); tests that exercise rejection paths re-sign post-mutation.
- 44 new tests in `test/subject-presence.test.ts`: 6 unit (subject_notified branch — sha256/null/empty/raw/uppercase/short), 21 unit (every incident-level event × {null OK, sha256 rejected, raw string rejected}), 2 unknown-discriminator, 1 missing-body fall-through, 5 apply-helper (subject_missing / subject_invalid_form / subject_present / no-op when failed / no-op when valid), 3 end-to-end via `verifyReceipt` (subject_notified+sha256 valid, subject_notified+null rejected, detected+sha256 rejected), 6 end-to-end across the seven incident-level events (`breach.detected` asserts the §D `tsa_required` outcome, the other 6 assert §E acceptance).

## 0.1.1 — 2026-05-19

### Added

- §D per-event TSA mandate matrix (`src/tsa-mandate.ts`). `breach.detected` is **MANDATORY** per spec D10-ABR-2 (the 72-hour clock starts at this event; no exception). All seven other events are **RECOMMENDED**. Mirrors the per-event keying shape used by ALR (vs ANR's per-profile keying).
- Public exports: `ABR_TSA_MANDATE`, `tsaMandateLevel(event_type)`, `applyAbrTsaMandate(target, body)`, `AbrTsaMandateTarget`, `TsaMandateLevel`.
- Wired into `verifyV2`: mandate runs after raw TSA dispatch and only when `signature_valid` is still true. Upgrades `tsa_absent` to `tsa_required` (poisons sig, `reason: "tsa_required"`) on `breach.detected`, and to `tsa_recommended` (warning only) on the other events. Real TSA reasons (`tsa_imprint_mismatch`, etc.) win over the matrix.
- 25 new tests in `test/tsa-integration.test.ts` covering: T1 RECOMMENDED-event upgrade × 7, T1b MANDATORY-event rejection on `breach.detected`, T3 injected-imprint no-op on both RECOMMENDED and MANDATORY events, matrix-shape assertion, 8 × `tsaMandateLevel` lookup, 6 × `applyAbrTsaMandate` unit (MANDATORY/RECOMMENDED + tsa_absent / real-reason / undefined / unknown-event branches).
- Test helper `test/_helpers/v2-receipt.ts` — mint a deterministic v=2 ABR envelope parameterised over `event_type` (all 8 variants).

## 0.1.0 — 2026-05-19

- Initial skeleton.
