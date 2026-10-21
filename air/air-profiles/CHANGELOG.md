## 0.7.3

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.
- Updated dependencies
  - @dekimuhq/anchors-envelope@0.26.2

## 0.7.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

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

## 0.6.0

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/air-verifier@0.6.0

## 0.5.3

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/air-verifier@0.5.3

## 0.5.2

### Patch Changes

- Align `@dekimuhq/anchors-envelope` dependency range to `^0.16.0` across all remaining families. These packages pinned `^0.13.0`, which cannot resolve the published envelope `0.16.0` (caret on a 0.x minor) — leaving the dependency range unsatisfiable for downstream consumers. Envelope 0.16.0 is additive (adds the mandate-aware `TsaState` type), so this is a metadata-only alignment with no behavior change.

## 0.5.0

### Patch Changes

- Updated dependencies [c2f423e]
  - @dekimuhq/air-verifier@0.5.0

## 0.2.2 — 2026-05-20

### Changed (dep-range only — no source changes)

- `@dekimuhq/anchors-envelope` range bumped `^0.9.0` → `^0.11.0` to align with
  the shipped envelope floor post Phase 4B-2. Profile validators consume only
  the `ProfileValidator` type contract; no 0.11.0 runtime surface exercised.
  Pure dep-floor refresh matching the AIR-issuer-kit / family sweep cadence.
- `@dekimuhq/air-verifier` range bumped `^0.2.0` → `^0.4.0` to match the shipped
  verifier floor after Phase 4B-2 chain-walk warnings landed.

regression check: `grep -n '"@dekimuhq/anchors-envelope"' anchors/air/air-profiles/package.json` must report `^0.11.0`.
regression check: `grep -n '"@dekimuhq/air-verifier"' anchors/air/air-profiles/package.json` must report `^0.4.0`.

## 0.2.1 — 2026-05-20

### Changed (dep-range only — no source changes)

- `@dekimuhq/anchors-envelope` range bumped `^0.7.1` → `^0.9.0` to align with the
  shipped envelope floor. Profile validators consume only the `ProfileValidator`
  type contract; no 0.9.0 runtime surface exercised. Pure dep-floor refresh
  matching the AIR-issuer-kit / family sweep cadence.
- `@dekimuhq/air-verifier` range bumped `^0.1.4` → `^0.2.0` to match the shipped
  verifier floor on GitHub Packages (no 0.1.x ever published). Without this lift,
  transitive resolution from `@dekimuhq/anchors` would 404 on `air-verifier`.

regression check: `grep -n '"@dekimuhq/anchors-envelope"' anchors/air/air-profiles/package.json` must report `^0.9.0`.
regression check: `grep -n '"@dekimuhq/air-verifier"' anchors/air/air-profiles/package.json` must report `^0.2.0`.

## 0.2.0 — 2026-05-19

§F profile validators (Phase 5 §F) — the 5 v1 spec §5 profiles.

- `src/types.ts` — shared validator surface: `ProfileValidatorInput { body, iat }` · `ProfileValidationResult { valid, errors, warnings }` · `ProfileValidator` functional shape · `AIR_PROFILE_ERROR_CODES` (HARD) + `AIR_PROFILE_WARNING_CODES` (SHOULD-grade) constants · `AIR_V1_PROFILES` closed list · `AIR_MONTH_MS` / `AIR_REVIEW_WINDOW_MONTHS_STRICT` (12) / `AIR_REVIEW_WINDOW_MONTHS_VOLUNTARY` (36) review-window calculus · `parseTimestamp` + `isNonEmptyStringArray` helpers.
- `src/art35_3_a.ts` — §5.1 `impact.art35_3_a_automated_decisions`. On `dpia.completed`: warns `art35_3a_aer_link_missing` when `body.aer_receipt_ids` null/empty (§8.1 AER linkage SHOULD); warns `review_window_long` when `review_due_at - iat > 12 months`. Other events no-op.
- `src/art35_3_b.ts` — §5.2 `impact.art35_3_b_large_scale_special_categories`. On `dpia.completed`: warns `art35_3b_alr_link_missing` when `body.alr_receipt_ids` null/empty (§8.3 ALR linkage SHOULD on special-category flows). Cross-border ATR surface is invisible to single-receipt and stays out of scope.
- `src/art35_3_c.ts` — §5.3 `impact.art35_3_c_public_monitoring`. Minimal no-op in v1: ALR is MAY-grade and the §5.3 stakeholder-consultation warning is a chain-level concern that lives in the air-verifier chain walker, not in a single-receipt validator.
- `src/art35_4.ts` — §5.4 `impact.art35_4_dpa_list`. No-op in v1: the spec reserves `body.dpa_list_reference` + early `body.dpa_jurisdiction` on `dpia.threshold_triggered`, but neither field is present in the v1 AIR body discriminated union. Deferred to a future v1.1 amendment; placeholder kept for dispatcher symmetry.
- `src/voluntary.ts` — §5.5 `impact.voluntary`. On `dpia.completed`: warns `review_window_long_voluntary` when `review_due_at - iat > 36 months` (looser cap than §5.1). The §5.5 chain-level `voluntary_high_risk_no_consultation` surface lives in the chain walker.
- `src/dispatcher.ts` — §F dispatcher: `validateAirProfile(profile, input)` looks up the validator from a closed registry and invokes it; unknown profile strings return `valid: false, errors: ["profile.unknown"], warnings: []`. `getAirProfileValidator(profile)` exposes the function reference for batched evaluation; `REGISTERED_AIR_PROFILES` is the closed list.
- `src/index.ts` — re-exports `types` (constants + helpers + types) + per-profile validators + dispatcher.
- Dep change: declares `@dekimuhq/air-verifier ^0.1.4` (validators import `AirBody` / `AirProfile` types) and bumps `@dekimuhq/anchors-envelope ^0.6.2 → ^0.7.1` to align with the air-verifier transitive range.
- `test/_helpers/bodies.ts` — minimal valid body builders for all eleven AIR event variants (`thresholdTriggeredBody`, `scopeLockedBody`, `dpoAdvisedBody`, `stakeholdersConsultedBody`, `completedBody`, `reviewedBody`, `priorConsultationInitiatedBody`, `priorConsultationResolvedBody`, `processingAuthorisedBody`, `processingBlockedBody`, `terminatedBody`) plus `allNonCompletedBodies()` enumeration.
- **111 tests across 7 files, 100% pass** — clears the family ≥99 floor:
  - `types.test.ts` (19 tests) — closed list shapes, review-window literals (12 / 36), warning-code snake_case discipline, `isNonEmptyStringArray` + `parseTimestamp` happy path + null/garbage/non-string guards + RFC 3339 offset acceptance + ISO round-trip.
  - `art35_3_a.test.ts` (24 tests) — profile-id literal, clean / null-aer / empty-aer / aer-with-empty-string / multi-aer / 13mo / 24mo / exactly-12mo / 6mo / same-day / negative / both-warnings / null-iat / garbage-iat / garbage-review_due_at / whitespace-aer-counts / all-non-completed-events-clean / mutation-isolation / low-risk-still-warns / high-risk-clean / 365-day-window / valid-flag-tracks-errors-not-warnings.
  - `art35_3_b.test.ts` (14 tests) — profile-id literal, alr present/null/empty/multi/empty-string-entry / no §5.2 window cap / no §5.1 aer surface / all-non-completed clean / null-iat accepted / high-risk-with-alr clean / aer+atr+apur-without-alr-still-warns / fresh-result-per-call / errors-always-empty / valid-tracks-errors.
  - `art35_3_c.test.ts` (9 tests) — profile-id, MAY-grade alr never warns (present/null/empty) / no §5.1 aer surface / long window no warn / all-non-completed clean / null-iat accepted / high-risk clean / fresh-objects.
  - `art35_4.test.ts` (9 tests) — profile-id, all-non-completed + completed clean / threshold_triggered v1 no-op / no aer/alr surface / no review-window surface / null-iat accepted / high-risk clean / fresh-results / errors-always-empty.
  - `voluntary.test.ts` (18 tests) — profile-id, 12mo / 24mo / ~35mo / 48mo (warns) / 10-year (warns) / no §5.1 aer surface / no §5.2 alr surface / all-non-completed clean / null-iat / garbage-iat / garbage-review_due_at / negative-window / same-day / fresh-results / high-risk-no-chain-warning / errors-always-empty / 24mo-window-doesnt-trip-§5.5.
  - `dispatcher.test.ts` (16 tests) — `REGISTERED_AIR_PROFILES` has all five ids · matches `AIR_V1_PROFILES` set-wise · dispatches each profile to its validator (3a / 3b / 3c / 4 / voluntary) · unknown / empty / typo profile → `profile.unknown` · `getAirProfileValidator` returns each registered fn · returns undefined for unknown · every registered profile validates a minimal clean completed body · result objects not shared across calls.
- **air-profiles 0.1.0 → 0.2.0** (MINOR — first public-surface release). Workspace AIR family suite: 192 (air-verifier) + 103 (air-issuer-kit) + 111 (air-profiles) = 406 tests.

regression check: `cd anchors/air/air-profiles && ls src/{art35_3_a,art35_3_b,art35_3_c,art35_4,voluntary,dispatcher,types,index}.ts | wc -l` must report 8.

## 0.1.0 — 2026-05-19

- Initial skeleton.
