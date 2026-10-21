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

## 0.7.0

### Minor Changes

- Add the `gdpr.train` ACR profile (verifiable consent-to-train). Restricts lawful basis to the
  EDPB-Opinion-28/2024 training bases (6(1)(a)/6(1)(f)) and binds a training scope + salted
  model-family commitment via the structured `lawful_basis` field. No wire change — additive
  profile on the shipped `ar.consent.v1` family.

## 0.6.6

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

## 0.6.5

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
  - @dekimuhq/acr-verifier@0.6.5

## 0.6.0

### Patch Changes

- Updated dependencies [c2f423e]
  - @dekimuhq/acr-verifier@0.6.0

## 0.3.1 — v1.2 envelope amendment support

### Added

- v1.2 envelope-level fields (`kind`, `cause`, `predicate`, `iat_ms`) flow through verify and mint paths per [v1.2 spec](../../envelope/spec/v1.2.md) §6 adoption matrix.
- Smoke fixture demonstrating spec §5.5 Example 1 (age + purpose) predicate roundtrip on `ar.consent.v1`.

### Changed

- Envelope dep range bumped `^0.3.0` → `^0.4.0` to receive the v1.2 fields. No runtime change for callers that don't populate the new fields — v1.1 receipts remain byte-equal verifiable.

# Changelog — `@dekimuhq/acr-profiles`

This package follows SemVer relative to its own public API. The profile semantics are pinned to the ACR spec at https://github.com/dekimuhq/anchors-spec/tree/main/acr §5.

## v0.3.0 — QES policy OID confirmed (OQ-1)

- `ESIG_ACCEPT_QES_DESCRIPTOR.requires_tsa_policy_oid` updated from the placeholder `0.4.0.19422.1.1` to the confirmed ETSI EN 319 421 BTSP policy OID **`0.4.0.2023.1.1`** — the identifier qualified EU TSAs assert in `TSTInfo.policy`. The placeholder lived under the EN 319 422 _protocol_ arc, not a policy arc. Confirmed in an internal legal review (not published).
- Behavioural impact: receipts whose TSA policy field matches the old placeholder OID will now report `tsa_policy_oid_mismatch` and fail the `esig.accept@qes` mandate. Any pre-0.3.0 consumer who had pinned the placeholder must update.
- `PLACEHOLDER` markers removed from descriptor docstring and source comment.
- Comment refs in `envelope/src/tsa/verify.ts` and the three verifier `envelope-v2.ts` files updated to the new OID for documentation consistency.

## v0.2.0 — esig.accept@qes profile + dispatch adapter (undocumented at publish time)

This entry is added retroactively in v0.3.0; v0.2.0 was published as part of Phase D Task 21 + Phase E Task E.2 without a CHANGELOG entry.

- New profile descriptor `ESIG_ACCEPT_QES_DESCRIPTOR` for the eIDAS QES acceptance profile.
- New validator `validateEsigAcceptQes(receipt, ctx) → { ok, reason? }`.
- New family-dispatch adapter `validateEsigAcceptQesProfile` wrapping the validator into the universal `ProfileValidator` shape from `@dekimuhq/anchors-envelope/profile`.
- Placeholder TSA policy OID `0.4.0.19422.1.1` carried in the descriptor pending OQ-1 resolution (now resolved in v0.3.0).

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

Initial publish alongside the ACR v1.0 spec. v1.0 regulation profiles:

- `validateGdprArt7` — GDPR Art. 7 consent validation (lawful basis, purpose, withdrawability).
- `validateAiActArt14` — EU AI Act Art. 14 human-oversight validation. Decodes the pipe-delimited `oversight_action | apr_receipt_hash | reviewer_role_commit` triple packed into the `lawful_basis` slot (per spec §5.2 v1 wire encoding); a future structured `oversight` JSON revision is reserved.
- `ValidationResult` — shared shape for profile validators.
- Node ≥22.

API is `v0.x` until v1.0.0.
