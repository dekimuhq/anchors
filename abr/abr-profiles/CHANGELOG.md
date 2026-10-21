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
  - @dekimuhq/anchors-envelope@0.18.1

## 0.5.0

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/abr-verifier@0.5.0

## 0.4.3

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/abr-verifier@0.4.3

## 0.4.2

### Patch Changes

- Align `@dekimuhq/anchors-envelope` dependency range to `^0.16.0` across all remaining families. These packages pinned `^0.13.0`, which cannot resolve the published envelope `0.16.0` (caret on a 0.x minor) — leaving the dependency range unsatisfiable for downstream consumers. Envelope 0.16.0 is additive (adds the mandate-aware `TsaState` type), so this is a metadata-only alignment with no behavior change.
- Updated dependencies
  - @dekimuhq/abr-verifier@0.4.2

## 0.4.0

### Patch Changes

- Updated dependencies [c2f423e]
  - @dekimuhq/abr-verifier@0.4.0

## 0.1.3 — 2026-05-20

### Changed (dep-range only — no source changes)

- `@dekimuhq/anchors-envelope` range bumped `^0.9.0` → `^0.11.0` to align with
  the shipped envelope floor post Phase 4C. Profile validators consume only the
  `ProfileValidator` type contract; no 0.11.0 runtime surface exercised. Pure
  dep-floor refresh matching the AIR Phase 4B-2 cadence.
- `@dekimuhq/abr-verifier` range bumped `^0.2.0` → `^0.3.0` to match the shipped
  verifier floor after Phase 4C factory migration + composeAbr warnings landed.

abr-profiles 103/103 tests unchanged.

regression check: `grep -n '"@dekimuhq/anchors-envelope"' anchors/abr/abr-profiles/package.json` must report `^0.11.0`.
regression check: `grep -n '"@dekimuhq/abr-verifier"' anchors/abr/abr-profiles/package.json` must report `^0.3.0`.

## 0.1.2 — 2026-05-20

### Changed (dep-range only — no source changes)

- `@dekimuhq/anchors-envelope` range bumped `^0.6.2` → `^0.9.0` to align with the
  shipped envelope floor. Profile validators consume only the `ProfileValidator`
  type contract; no runtime call sites added in 0.9.0 are exercised. Pure
  dep-floor refresh matching the ABR-issuer-kit / family sweep cadence.
- `@dekimuhq/abr-verifier` range bumped `^0.1.2` → `^0.2.0` to match the shipped
  verifier floor on GitHub Packages (no 0.1.x ever published). Without this lift,
  transitive resolution from `@dekimuhq/anchors` would 404 on `abr-verifier`.

regression check: `grep -n '"@dekimuhq/anchors-envelope"' anchors/abr/abr-profiles/package.json` must report `^0.9.0`.
regression check: `grep -n '"@dekimuhq/abr-verifier"' anchors/abr/abr-profiles/package.json` must report `^0.2.0`.

## 0.1.1 — 2026-05-19

- Ship the 5 v1 regulation profile validators (ABR spec §5):
  `breach.gdpr.art33`, `breach.gdpr.art34`, `breach.nis2.art23`,
  `breach.dora.art19`, `breach.us_state.attorney_general`. Each exports a
  pure `validate*` function and a `validate*Profile` adapter matching the
  universal `ProfileValidator` signature from `@dekimuhq/anchors-envelope`.
- Profile-match + non-empty `incident_correlation_id` (D10-ABR-3) are
  universal invariants. Profile-specific invariants: art33 enforces
  ISO 3166-1 alpha-2 / `"EU"` jurisdiction and non-empty
  `affected_data_categories` on `breach.detected`; art34 enforces
  `subject_batch_size > 0` on `breach.subject_notified`; NIS2 requires
  `notification_phase != null` on `breach.dpa_notified` (3-phase flow);
  art33 / art34 / DORA / US-AG require `notification_phase === null` on
  `breach.dpa_notified` (single-phase).
- DORA validator forwards `ProfileValidatorCtx` (`tsa_state` / `tsa_listed`
  / `tsa_policy_oid`) to the pure validator surface for future eIDAS QTS
  policy-OID gating.
- Extension fields named in spec §5.3 / §5.4 / §5.5 (`entity_classification`,
  `sector`, `dora_classification`, `state_code`) are not yet on the v1
  `AbrBody` union; they land via §5.6 amendments in `body.<jurisdiction>_specific`
  when integrator demand surfaces.
- Add `@dekimuhq/abr-verifier ^0.1.2` to dependencies (matches the
  acr-profiles / arr-profiles pattern).

## 0.1.0 — 2026-05-19

- Initial skeleton.
