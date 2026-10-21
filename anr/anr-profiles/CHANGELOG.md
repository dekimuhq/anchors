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

## 0.5.2

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0

## 0.5.1

### Patch Changes

- Align `@dekimuhq/anchors-envelope` dependency range to `^0.16.0` across all remaining families. These packages pinned `^0.13.0`, which cannot resolve the published envelope `0.16.0` (caret on a 0.x minor) — leaving the dependency range unsatisfiable for downstream consumers. Envelope 0.16.0 is additive (adds the mandate-aware `TsaState` type), so this is a metadata-only alignment with no behavior change.

## 0.2.3 — 2026-05-20

### Changed (dep-range only — no source changes)

- `@dekimuhq/anchors-envelope` range bumped `^0.9.0` → `^0.11.0` to align with the ANR Phase 4D floor lift on `anr-verifier 0.4.0` (D-anchors-8 (internal design record, not published)). Profile validators consume only the `ProfileValidator` type contract; no 0.11.0 runtime surface exercised. Pure dep-floor refresh matching the ANR-triple sweep.

regression check: `grep -n '"@dekimuhq/anchors-envelope"' anchors/anr/anr-profiles/package.json` must report `^0.11.0`.

## 0.2.2 — 2026-05-20

### Changed (dep-range only — no source changes)

- `@dekimuhq/anchors-envelope` range bumped `^0.7.0` → `^0.9.0` to align with the
  shipped envelope floor. Profile validators consume only the `ProfileValidator`
  type contract; no 0.9.0 runtime surface exercised. Pure dep-floor refresh
  matching the ANR-issuer-kit / family sweep cadence.

regression check: `grep -n '"@dekimuhq/anchors-envelope"' anchors/anr/anr-profiles/package.json` must report `^0.9.0`.

## 0.2.1 — 2026-05-19

### Dependencies

- `@dekimuhq/anchors-envelope` dep range bumped `^0.6.1` → `^0.7.0` for
  consistency with the ANR triple (anr-verifier + anr-issuer-kit). No
  source changes; consumes the Phase 1 factory extension only via the
  ProfileValidator type contract.

## 0.2.0 — 2026-05-18

- Phase 2 §F: 5 ANR v1 profile validators landed (spec §5).
  - `notice.art13.collected_direct` — enforces GDPR Art 13 rights_surface minimum (`art15`, `art16`, `art17`, `art18`, `art20`, `art21`) on `notice.presented` / `notice.re_presented`.
  - `notice.art14.collected_indirect` — enforces required `data_source` + `collection_horizon` on `notice.presented` / `notice.re_presented`. Spec §5.2 horizon-age WARNING (`one_month` clock breach vs `iat`) deferred; the `ProfileValidator` signature has no warning channel and clock semantics are verifier-level.
  - `notice.art26.joint_controller_essence` — pins event_type to `notice.joint_controller_essence` and asserts non-empty `joint_controllers` array.
  - `notice.layered_transparency` — enforces non-empty `layer_uris` with `summary` first and at least one `full` layer on `notice.presented` / `notice.re_presented`. Policy_hash = SHA-256(concat(layer_hashes)) cross-check deferred to §C / future hardening (pre-image byte-vs-string pin unresolved in spec).
  - `notice.aiact.art50_transparency` — enforces non-null `ai_system_kind` + `ai_system_provider_did` on `notice.presented` / `notice.re_presented`. TSA-MANDATORY family-wide rule lives in verifier §D `ANR_TSA_MANDATE`, not duplicated here. Profile-side `tsa_policy_oid` eIDAS QTS pin (`0.4.0.2023.1.1`) not adopted in v1.0 — FAMILY-CONSISTENCY does not pin a QTS OID for ANR art50 (only ACR `esig.accept@qes`).
- Bumped `@dekimuhq/anchors-envelope` dep `^0.5.0` → `^0.6.1` (matches anr-verifier 0.1.0 line).
- Each validator exports both a pure `validate*(body)` function and a universal-signature `*Profile` adapter. Adapters surface `{profile_id, ok, reason?}` with `reason` = first error code.
- Tests: 5 per-profile test files + shared body-fixture helpers under `test/_helpers/bodies.ts`. 47 new test cases.

## 0.1.0 — 2026-05-18

- Initial skeleton.
