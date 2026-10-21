## 0.9.3

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.
- Updated dependencies
  - @dekimuhq/anchors-envelope@0.26.2

## 0.9.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

## 0.8.2

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

## 0.8.1

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
  - @dekimuhq/arr-verifier@0.8.1

## 0.8.0

### Patch Changes

- @dekimuhq/arr-verifier@0.8.0

## 0.7.0

### Minor Changes

- db75e89: Register the six regulated retention profiles for v=2 `opts.profile` dispatch: `arr.gdpr.art5e`, `arr.hipaa.retention`, `arr.kyc.retention`, `arr.sox.retention`, `arr.mifid2.retention`, `arr.aiact.art10`. Previously their validators shipped in `@dekimuhq/arr-profiles` but were unreachable from the verifier because the v=2 ARR body had no slot for the profile-specific fields they validate.

  Additive wire change (graceful-degradation; receipts without it stay byte-equal): a new optional `profile_attributes` object (`ArrProfileAttributes`) on the v=2 ARR single + batch body, plumbed through `mintArrV2Single`/`mintArrV2Batch` inputs and carried outside `field_root` (like `qts_attestation_hash`, covered by the envelope signature). Universal-signature adapters reconstruct the flat receipt shape the validators expect (`kind` from `claim_type`, attributes hoisted from `body.profile_attributes`). Profile validation remains advisory — a failing profile never poisons `signature_valid`.

### Patch Changes

- Updated dependencies [db75e89]
- Updated dependencies [db75e89]
  - @dekimuhq/arr-verifier@0.7.0

## 0.6.0

### Patch Changes

- Updated dependencies [c2f423e]
  - @dekimuhq/arr-verifier@0.6.0

## 0.2.1 — v1.2 envelope amendment support

### Added

- v1.2 envelope-level fields (`kind`, `cause`, `predicate`, `iat_ms`) flow through verify and mint paths per [v1.2 spec](../../envelope/spec/v1.2.md) §6 adoption matrix.
- v1.2 smoke fixtures — predicate roundtrip + v1.1 backwards-compat.

### Changed

- Envelope dep range bumped `^0.3.0` → `^0.4.0` to receive the v1.2 fields. No runtime change for callers that don't populate the new fields — v1.1 receipts remain byte-equal verifiable.

# Changelog — `@dekimuhq/arr-profiles`

This package follows SemVer relative to its own public API. The profile semantics are pinned to the ARR spec at https://github.com/dekimuhq/anchors-spec/tree/main/arr §5.

## v0.1.3 — files-field fix

- v0.1.2 (and v0.2.1 for meta) shipped without `CHANGELOG.md`, `quickstart/`, or `docs/` in the npm tarball because the `files` field in package.json only listed `["src","README.md","LICENSE"]`. Mirrors the APR pattern now: verifier/profiles ship `src + README + LICENSE + CHANGELOG`; issuer-kits also ship `quickstart + docs`.
- No code or API changes.

## v0.1.2 — internal parity polish

- Beefed up README to match the depth of the APR packages (rationale, use, API, what-it-is-not).
- Added `repository` field to package.json.
- No code or API changes.

## v0.1.1 — packaging hygiene

- Added `LICENSE` (Apache-2.0).
- Added this `CHANGELOG.md`.
- No code or API changes.

## v0.1.0 — initial private release

Initial publish alongside the ARR v1.0 spec. Seven v1.0 retention profiles:

- `gdpr.art17` — Right to erasure. Mode A (chain-authoritative).
- `gdpr.art5e` — Storage limitation / retention window. Mode B (batch-authoritative).
- `hipaa.retention` — HIPAA retention windows. Mode A.
- `kyc.retention` — KYC/AML retention windows.
- `sox.retention` — SOX records retention.
- `mifid2.retention` — MiFID II records retention.
- `aiact.art10` — EU AI Act Art. 10 training-data retention / governance.

Each profile exports a typed validator and the constants needed to bind the profile to the verifier. One runtime dep: `@dekimuhq/arr-verifier`. Node ≥22.

API is `v0.x` until v1.0.0.
