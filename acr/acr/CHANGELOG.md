## 0.7.2

### Patch Changes

- `family.meta.spec_path` now points at the public spec (https://github.com/dekimuhq/anchors-spec/tree/main/acr) instead of an unpublished internal path.

## 0.7.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [28c64ff]
  - @dekimuhq/acr-profiles@0.7.1

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

- Updated dependencies [57a7179]
  - @dekimuhq/acr-profiles@0.6.6

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
  - @dekimuhq/anchors-envelope@0.18.1
  - @dekimuhq/apr-verifier@0.6.5

## 0.6.4

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/apr-verifier@0.6.4

## 0.6.3

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/apr-verifier@0.6.3

## 0.6.2

### Patch Changes

- Align `@dekimuhq/anchors-envelope` dependency range to `^0.16.0` across all remaining families. These packages pinned `^0.13.0`, which cannot resolve the published envelope `0.16.0` (caret on a 0.x minor) — leaving the dependency range unsatisfiable for downstream consumers. Envelope 0.16.0 is additive (adds the mandate-aware `TsaState` type), so this is a metadata-only alignment with no behavior change.
- Updated dependencies
  - @dekimuhq/apr-verifier@0.6.2

## 0.6.0

### Minor Changes

- c2f423e: feat: add qts_attestation_hash cross-sibling QTS upgrade field

### Patch Changes

- Updated dependencies [c2f423e]
  - @dekimuhq/apr-verifier@0.6.0

## 0.5.2 — 2026-05-20 — cross-family verifier dep-range alignment

### Changed (dep-range only — no source changes)

- `@dekimuhq/apr-verifier` range bumped `^0.4.3` → `^0.5.1` to align with the
  shipped APR verifier floor. Closes the last cross-family verifier dep-range
  drift on the ACR side after the issuer-kit + profiles + envelope alignment
  sweeps landed in `710c338`, `86ab55b`, and `5dc6241`. Pure dep-range refresh
  — zero source files touched.

No source changes. Test count unchanged (90/90).

regression check: `grep -n '"@dekimuhq/apr-verifier"' anchors/acr/acr-verifier/package.json` must report `^0.5.1`.

## 0.5.1 — 2026-05-20

### Changed (dep-range only — no source changes)

- `@dekimuhq/anchors-envelope` range bumped `^0.8.0` → `^0.9.0` to align with the
  non-ASR family floor (ASR triple is on `^0.10.0` post-Phase-4 because it emits
  compose warnings; every other family stays on `^0.9.0`). Closes the verifier
  side of the envelope dep-range alignment after the issuer-kit + profiles sweep
  landed in `710c338` and `86ab55b`.

No source changes. Test count unchanged (90/90).

Out of scope: `@dekimuhq/apr-verifier` range remains `^0.4.3` while shipped is
`0.5.x` (now `0.5.1`). Cross-family verifier dep-range alignment is a separate
sweep and is not bundled here.

regression check: `grep -n '"@dekimuhq/anchors-envelope"' anchors/acr/acr-verifier/package.json` must report `^0.9.0`.

## 0.5.0 — 2026-05-19 — cross-issuer interop Phase A Slice 2 Phase 2 — verifyIssuerTrust dispatch backport

### Added

- `EnvelopeVerifyOptions.verifyIssuerTrust?: VerifyIssuerTrust` — optional issuer-trust dispatch callback. Mirrors `FamilyVerifyOptions.verifyIssuerTrust` in `@dekimuhq/anchors-envelope` 0.8.0's shared pipeline byte-equal — when Phase 4 migrates this verifier to `buildVerifyReceipt`, the swap is a drop-in.
- `EnvelopeVerifyResult.trust_outcome?`, `.trust_reason?`, `.trusted_issuer_record?` — set iff `verifyIssuerTrust` was supplied.
- Step 5.5 dispatch fires between signature verification and the trusted-log allowlist. Maps the 5-outcome `IssuerTrustResult` from `@dekimuhq/anchors-envelope`'s type-only mirror onto `signature_valid` + trust\_\* result fields:
  - `valid_trusted` / `valid_untrusted` → continue, outcome + record surfaced
  - `valid_revoked` → HARD FAIL: `reason: "issuer_revoked"`
  - `invalid_key_doc` → HARD FAIL: `reason: "did_web_invalid_key_doc:<r>"`
  - `invalid_signature` → HARD FAIL: `reason: "did_web_invalid_signature:<r>"`
  - Thrown exception → caught: `reason: "verify_issuer_trust_threw:<msg>"`
- Envelope dep range bumped to `^0.8.0` (was `^0.7.0`).

### Backward compatibility

- `verifyIssuerTrust` defaults `undefined`. When absent, the pipeline behaves byte-equal to the prior release. No existing callers need migration.

Spec: decision (internal design record, not published) — Option B locked. See `@dekimuhq/anchors-envelope` 0.8.0 CHANGELOG for shared-pipeline detail.

regression check: `grep -n 'verifyIssuerTrust\|trust_outcome' src/envelope-v2.ts` reports >=6 hits.

## 0.4.3 — 2026-05-18 — defineFamily() adoption (Phase A.3 step 3)

### Changed

- ACR is the fourth family member (after the ALR canary at `a7ae33c` and the APR/ARR steps at Phase A.3 steps 1 + 2) to consume `defineFamily()` from `@dekimuhq/anchors-envelope` 0.6.2. Public API of both `@dekimuhq/acr-verifier` and `@dekimuhq/acr-issuer-kit` stays byte-equal; the factory is wired under the hood. New `src/family.ts` exports `acrFamily` — frozen `FamilyManifest<ACRReceipt>` with chip 2 / status_list_slot 2 / `subject must-be-present` / TSA `free` upgrade path / three owned claim_types (`ar.consent.v1`, `ar.modification.v1`, `ar.withdrawal.v1`). Per-profile MANDATORY TSA enforcement (e.g. `acr.esig.accept@qes` requires eIDAS QTS) remains in the profile validators — the manifest records only the family-wide upgrade path.
- `envelope-v2.ts` uses `acrFamily.isOwnedClaimType()` to gate the `wrong_protocol` reason in place of the hand-rolled `ACR_CLAIM_TYPE_SET`; the rejection stays byte-equal. The `AcrKind` import (used only for the `as const satisfies` check) was removed from `envelope-v2.ts` — the v=1 path still imports `AcrKind` directly from `./types.ts`.
- Envelope dep range bumped `^0.4.0` → `^0.6.2`; apr-verifier dep bumped `^0.4.0` → `^0.4.3`.

regression check: grep "ACR_CLAIM_TYPE_SET" anchors/acr/acr-verifier/src/

## 0.4.2 — v1.2 envelope amendment support

### Added

- v1.2 envelope-level fields (`kind`, `cause`, `predicate`, `iat_ms`) flow through verify and mint paths per [v1.2 spec](../../envelope/spec/v1.2.md) §6 adoption matrix.
- Surfaces full v1.2 reason-code set when verifying receipts with predicates: `iat_ms_mismatch`, `predicate_operator_not_allowed`, `predicate_var_path_invalid`, `predicate_malformed_ast`, `predicate_evaluation_false`, `predicate_division_by_zero`, `predicate_modulo_by_zero`.

### Changed

- Envelope dep range bumped `^0.3.0` → `^0.4.0` to receive the v1.2 fields. No runtime change for callers that don't populate the new fields — v1.1 receipts remain byte-equal verifiable.

# Changelog — `@dekimuhq/acr-verifier`

This package follows SemVer relative to its own public API, NOT to the spec. The ACR spec is versioned separately in https://github.com/dekimuhq/anchors-spec/tree/main/acr. A change to the spec that affects what a v1-conforming verifier does will ship here as a patch or minor; a change to this package's public API ships as a minor or major regardless of spec churn.

## 0.4.1

### Added

- `EnvelopeVerifyOptions.trustedLogs`: optional `ReadonlySet<string>` of
  trusted anchor-log URLs. When set, receipts whose `anchor.log` is not
  in the set are rejected with `reason: "untrusted_log"`. Exact-string
  match only. Cross-issuer interop Item 2.

## v0.1.3 — files-field fix

- v0.1.2 (and v0.2.1 for meta) shipped without `CHANGELOG.md`, `quickstart/`, or `docs/` in the npm tarball because the `files` field in package.json only listed `["src","README.md","LICENSE"]`. Mirrors the APR pattern now: verifier/profiles ship `src + README + LICENSE + CHANGELOG`; issuer-kits also ship `quickstart + docs`.
- No code or API changes.

## v0.1.2 — internal parity polish

- Beefed up README to match the depth of the APR packages (rationale, use, API, what-it-is-not).
- No code or API changes.

## v0.1.1 — packaging hygiene

- Added `LICENSE` (Apache-2.0).
- Added this `CHANGELOG.md`.
- No code or API changes.

## v0.1.0 — initial private release

Initial publish alongside the ACR v1.0 spec. Verifier-side primitives for Anchored Consent Receipts:

- `canonicalize`, `base64UrlEncode`, `base64UrlDecode` — re-exported from `@dekimuhq/apr-verifier` for symbol symmetry across the family.
- `commit`, `verifyCommitment`, `randomSalt` — salted commitments for `sub_commit` / `purpose_commit` style fields.
- `buildTree`, `inclusionProof`, `verifyInclusion`, `MerkleTree` — RFC 6962 Merkle tree primitives for sibling-only inclusion proofs.
- `verifyReceiptSignature` — Ed25519 signature verification over canonical receipt bytes.
- `hashReceipt`, `resolveChainState`, `ChainStatus`, `ChainState` — per-target chain walker for consent / modification / withdrawal sequences.
- `verifyDisclosureProof` — disclosure projection verifier.
- All shape types exported: `AcrKind`, `AcrProfile`, `AcrAnchor`, `ACRReceipt`, `FieldDisclosure`, `DisclosureProof`.
- Node ≥22. One runtime dep on `@dekimuhq/apr-verifier` for canonicalisation re-exports.

API is `v0.x` until v1.0.0; minor versions may add fields but should not remove or rename them.
