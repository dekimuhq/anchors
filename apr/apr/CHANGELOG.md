## 0.7.3

### Patch Changes

- `family.meta.spec_path` now points at the public spec (https://github.com/dekimuhq/anchors-spec/tree/main/apr) instead of an unpublished internal path.

## 0.7.2

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

## 0.7.1

### Patch Changes

- Extend `APRArtifactType` with four caller-driven artifact types.

  `APRArtifactType` is a closed union, and `mintAprV2` type-checks its `body`
  against `APRBody`, so a caller cannot mint a receipt for an artifact type the
  union does not name. Four real callers were blocked on exactly that:

  - `lethe.letter` — a consumer-rights letter rendered by lethe's byte-reproducible
    PDF renderer.
  - `lethe.document` — a tenant-supplied document hashed in the browser and never
    uploaded (the `document-anchor` path).
  - `hub.sign-offs.deliverable` — a deliverable signed off in the Hub `sign-offs`
    module.
  - `hub.time-clock.day` — a closed working-day record in the Hub `time-clock`
    module.

  **Additive and wire-invariant.** `claim_type` stays `ar.provenance.v1`, the
  envelope shape is untouched, and neither the mint path nor the verifier reads
  the union at runtime — it is a compile-time constraint on issuers only. No
  already-minted receipt changes meaning, and every existing receipt verifies
  byte-equal.

  `schema/families/ar.provenance.v1.anchor.json` carries the same enum as the
  manifest-level source of truth and was extended in the same commit, with its
  generated snapshot regenerated to match.

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

## 0.6.4

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0

## 0.6.3

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0

## 0.6.2

### Patch Changes

- Align `@dekimuhq/anchors-envelope` dependency range to `^0.16.0` across all remaining families. These packages pinned `^0.13.0`, which cannot resolve the published envelope `0.16.0` (caret on a 0.x minor) — leaving the dependency range unsatisfiable for downstream consumers. Envelope 0.16.0 is additive (adds the mandate-aware `TsaState` type), so this is a metadata-only alignment with no behavior change.

## 0.6.0

### Minor Changes

- c2f423e: feat: add qts_attestation_hash cross-sibling QTS upgrade field

## 0.5.1 — 2026-05-20

### Changed (dep-range only — no source changes)

- `@dekimuhq/anchors-envelope` range bumped `^0.8.0` → `^0.9.0` to align with the
  non-ASR family floor (ASR triple is on `^0.10.0` post-Phase-4 because it emits
  compose warnings; every other family stays on `^0.9.0`). Closes the verifier
  side of the envelope dep-range alignment after the issuer-kit + profiles sweep
  landed in `710c338` and `86ab55b`.

No source changes. Test count unchanged (62/62).

regression check: `grep -n '"@dekimuhq/anchors-envelope"' anchors/apr/apr-verifier/package.json` must report `^0.9.0`.

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

## 0.4.3 — 2026-05-18 — defineFamily() adoption (Phase A.3 step 1)

### Changed

- APR is the second family member (after the ALR canary at `a7ae33c`) to consume `defineFamily()` from `@dekimuhq/anchors-envelope` 0.6.2 (Phase A.1 factory). Public API of both `@dekimuhq/apr-verifier` and `@dekimuhq/apr-issuer-kit` stays byte-equal; the factory is wired under the hood. New `src/family.ts` exports `aprFamily` — frozen `FamilyManifest<APRBody>` with chip 1 / `status_list_slot: null` (APR is the canonical Status List 2021 non-consumer per FAMILY-CONSISTENCY §4) / `subject must-be-present` / TSA `free` upgrade path / single owned claim_type `ar.provenance.v1`.
- `envelope-v2.ts` uses `aprFamily.isOwnedClaimType()` to gate the `wrong_protocol` reason in place of the hand-rolled `APR_CLAIM_TYPE_SET`; the rejection stays byte-equal.
- Envelope dep range bumped `^0.4.0` → `^0.6.2` (requires the 0.6.2 `status_list_slot: number | null` widening for APR's non-consumer pattern).

regression check: grep "APR_CLAIM_TYPE_SET" anchors/apr/apr-verifier/src/

## 0.4.2 — v1.2 envelope amendment support

### Added

- v1.2 envelope-level fields (`kind`, `cause`, `predicate`, `iat_ms`) flow through verify and mint paths per [v1.2 spec](../../envelope/spec/v1.2.md) §6 adoption matrix.
- Surfaces `iat_ms_mismatch` and `predicate_forbidden_on_claim_type` reason codes when the envelope arrives with a v1.2 predicate (predicate is forbidden on `ar.provenance.v1` per L9).

### Changed

- Envelope dep range bumped `^0.3.0` → `^0.4.0` to receive the v1.2 fields. No runtime change for callers that don't populate the new fields — v1.1 receipts remain byte-equal verifiable.

# Changelog — `@dekimuhq/apr-verifier`

This package follows SemVer relative to its own public API, NOT to the spec. The spec is versioned separately in [`dekimuhq/anchors-spec`](https://github.com/dekimuhq/anchors-spec/tree/main/apr). A change to the spec that affects what a v1-conforming verifier does will ship here as a patch or minor; a change to this package's public API ships as a minor or major regardless of spec churn.

## 0.4.1

### Added

- `EnvelopeVerifyOptions.trustedLogs`: optional `ReadonlySet<string>` of
  trusted anchor-log URLs. When set, receipts whose `anchor.log` is not
  in the set are rejected with `reason: "untrusted_log"`. Exact-string
  match only; no wildcards. Cross-issuer interop Item 2.

## v0.1.0 — Phase 0 release

Initial public release alongside `dekimuhq/anchors-spec` v1.0.0.

- `verify({claim, anchor, anchorIds, claimKeyResolver, rootKeyResolver, now?})` — top-level orchestrator returning `{status, reasons}`.
- `verifyClaim`, `verifyAnchor` — phase-level entry points.
- `applyDisclosure`, `pseudonymise` — disclosure projection.
- `canonicalize` — RFC 8785-lite canonical JSON.
- `computeMerkleRoot` — reference Merkle scheme from `apr-spec` SCHEME.md.
- `base64UrlDecode`, `base64UrlEncode`.
- All shape and result types re-exported (`APRClaim`, `APRBody`, `DailyRoot`, `VerifyResult`, `VerifyReason`, …).
- Zero runtime npm dependencies. Node ≥22.
- 21 unit + conformance tests (11 canonicalize + 5 v1 conformance vectors + 5 hardening regression), all passing.

### Pre-release hardening (2026-05-11)

- Unknown top-level claim keys are now rejected as `tampered` / `schema_invalid` (spec §2.1). Verifier behaviour now matches the explicit known-key set.
- `canonicalize()` failures in claim and anchor signature paths are caught: non-finite numbers, `undefined`, `bigint`, functions, or symbols anywhere inside the signed payload now return `schema_invalid` / `root-sig-invalid` instead of propagating an unhandled `Error`. Closes a hosted-verifier DoS surface.
- Anchor signatures whose base64url decodes to anything other than 64 bytes are now rejected explicitly before reaching the Ed25519 verifier, mirroring the claim-signature path.
- `VerifyInput.anchorIds` is now `readonly string[]` to match the defensive copy made by `computeMerkleRoot`.

API is `v0.x` until v1.0.0; minor versions may add fields but should not remove or rename them. The intent is to reach v1.0.0 when the public API has accumulated real-world usage and there are no pending breaking-change ideas. There is no rush.
