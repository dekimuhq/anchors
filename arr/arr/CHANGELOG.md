## 0.9.2

### Patch Changes

- `family.meta.spec_path` now points at the public spec (https://github.com/dekimuhq/anchors-spec/tree/main/arr) instead of an unpublished internal path.
- Updated dependencies
  - @dekimuhq/acr@0.7.2

## 0.9.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [dd49239]
- Updated dependencies [28c64ff]
  - @dekimuhq/anchors-disclosure@0.3.0
  - @dekimuhq/acr@0.7.1
  - @dekimuhq/arr-profiles@0.9.1

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

- Updated dependencies [57a7179]
  - @dekimuhq/acr-verifier@0.6.6
  - @dekimuhq/arr-profiles@0.8.2

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
  - @dekimuhq/acr-verifier@0.6.5
  - @dekimuhq/anchors-envelope@0.18.1
  - @dekimuhq/apr-verifier@0.6.5

## 0.8.0

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/acr-verifier@0.6.4
  - @dekimuhq/apr-verifier@0.6.4

## 0.7.1

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/acr-verifier@0.6.3
  - @dekimuhq/apr-verifier@0.6.3

## 0.7.0

### Minor Changes

- db75e89: Surface ARR's RECOMMENDED TSA level (FAMILY-CONSISTENCY §2). The MANDATORY case (`ar.erasure.v1` under `arr.gdpr.art17.erasure-finalized`) was already enforced via the profile-keyed `tsa_mandate` map, but the doc's "all other ARR events → RECOMMENDED" rule was unimplemented — non-finalized receipts without a `tsa` block reported `tsa_state: "tsa_absent"`. `verifyReceipt` now applies a per-family post-step (`applyArrTsaMandate`) that upgrades an otherwise-valid `tsa_absent` result to `tsa_recommended`, mirroring ABR/AIR. Behavior change: ARR v=2 receipts without TSA now surface `tsa_state: "tsa_recommended"` (advisory; `signature_valid` unaffected).
- db75e89: Register the six regulated retention profiles for v=2 `opts.profile` dispatch: `arr.gdpr.art5e`, `arr.hipaa.retention`, `arr.kyc.retention`, `arr.sox.retention`, `arr.mifid2.retention`, `arr.aiact.art10`. Previously their validators shipped in `@dekimuhq/arr-profiles` but were unreachable from the verifier because the v=2 ARR body had no slot for the profile-specific fields they validate.

  Additive wire change (graceful-degradation; receipts without it stay byte-equal): a new optional `profile_attributes` object (`ArrProfileAttributes`) on the v=2 ARR single + batch body, plumbed through `mintArrV2Single`/`mintArrV2Batch` inputs and carried outside `field_root` (like `qts_attestation_hash`, covered by the envelope signature). Universal-signature adapters reconstruct the flat receipt shape the validators expect (`kind` from `claim_type`, attributes hoisted from `body.profile_attributes`). Profile validation remains advisory — a failing profile never poisons `signature_valid`.

### Patch Changes

- Updated dependencies [db75e89]
  - @dekimuhq/anchors-envelope@0.16.0

## 0.6.0

### Minor Changes

- c2f423e: feat: add qts_attestation_hash cross-sibling QTS upgrade field

### Patch Changes

- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
  - @dekimuhq/acr-verifier@0.6.0
  - @dekimuhq/apr-verifier@0.6.0

## 0.5.2 — 2026-05-20 — cross-family verifier dep-range alignment

### Changed (dep-range only — no source changes)

- `@dekimuhq/apr-verifier` range bumped `^0.4.3` → `^0.5.1` to align with the
  shipped APR verifier floor.
- `@dekimuhq/acr-verifier` range bumped `^0.4.0` → `^0.5.1` to align with the
  shipped ACR verifier floor.

Closes the last cross-family verifier dep-range drift on the ARR side after the
issuer-kit + profiles + envelope alignment sweeps landed in `710c338`,
`86ab55b`, and `5dc6241`. Pure dep-range refresh — zero source files touched.

No source changes. Test count unchanged (97/97).

regression check: `grep -nE '"@dekimuhq/(apr|acr)-verifier"' anchors/arr/arr-verifier/package.json` must report `^0.5.1` for both.

## 0.5.1 — 2026-05-20

### Changed (dep-range only — no source changes)

- `@dekimuhq/anchors-envelope` range bumped `^0.8.0` → `^0.9.0` to align with the
  non-ASR family floor (ASR triple is on `^0.10.0` post-Phase-4 because it emits
  compose warnings; every other family stays on `^0.9.0`). Closes the verifier
  side of the envelope dep-range alignment after the issuer-kit + profiles sweep
  landed in `710c338` and `86ab55b`.

No source changes. Test count unchanged (97/97).

Out of scope: `@dekimuhq/apr-verifier` range `^0.4.3` and `@dekimuhq/acr-verifier`
range `^0.4.0` remain stale relative to shipped `0.5.x` floors. Cross-family
verifier dep-range alignment is a separate sweep and is not bundled here.

regression check: `grep -n '"@dekimuhq/anchors-envelope"' anchors/arr/arr-verifier/package.json` must report `^0.9.0`.

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

## 0.4.3 — 2026-05-18 — defineFamily() adoption (Phase A.3 step 2)

### Changed

- ARR is the third family member (after the ALR canary at `a7ae33c` and the APR step at Phase A.3 step 1) to consume `defineFamily()` from `@dekimuhq/anchors-envelope` 0.6.2. Public API of both `@dekimuhq/arr-verifier` and `@dekimuhq/arr-issuer-kit` stays byte-equal; the factory is wired under the hood. New `src/family.ts` exports `arrFamily` — frozen `FamilyManifest<AnyARRReceipt>` with chip 3 / status_list_slot 3 / `subject must-be-present` / TSA `free` upgrade path / six owned claim_types (`ar.erasure.v1`, `ar.expiry.v1`, `ar.hold.v1`, `ar.anonymization.v1`, `ar.archive.v1`, `ar.batch.v1`). Per-profile MANDATORY/RECOMMENDED TSA enforcement remains in `tsa-mandate.ts` — the manifest records only the family-wide upgrade path.
- `envelope-v2.ts` uses `arrFamily.isOwnedClaimType()` to gate the `wrong_protocol` reason in place of the hand-rolled `ARR_CLAIM_TYPE_SET`; the rejection stays byte-equal.
- Envelope dep range bumped `^0.4.0` → `^0.6.2`; apr-verifier dep bumped `^0.4.0` → `^0.4.3` (in lockstep with APR's manifest export).

regression check: grep "ARR_CLAIM_TYPE_SET" anchors/arr/arr-verifier/src/

## 0.4.2 — v1.2 envelope amendment support

### Added

- v1.2 envelope-level fields (`kind`, `cause`, `predicate`, `iat_ms`) flow through verify and mint paths per [v1.2 spec](../../envelope/spec/v1.2.md) §6 adoption matrix.
- Surfaces full v1.2 reason-code set on retention receipts. `ar.batch.v1` predicates are forbidden (`predicate_forbidden_on_claim_type`).

### Changed

- Envelope dep range bumped `^0.3.0` → `^0.4.0` to receive the v1.2 fields. No runtime change for callers that don't populate the new fields — v1.1 receipts remain byte-equal verifiable.

# Changelog — `@dekimuhq/arr-verifier`

This package follows SemVer relative to its own public API, NOT to the spec. The ARR spec is versioned separately in https://github.com/dekimuhq/anchors-spec/tree/main/arr. A change to the spec that affects what a v1-conforming verifier does will ship here as a patch or minor; a change to this package's public API ships as a minor or major regardless of spec churn.

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

> **Erratum (2026-09-06).** Six symbol names in this entry were never exported by the
> package. Recorded here rather than rewritten, because the entry is a released record.
> `ArrEventKind` → `ArrSingleKind` / `ArrBatchEventKind` · `ArrDisclosureProof` → never
> existed (the disclosure shape is `BatchDisclosureInput` / `BatchDisclosureResult`) ·
> `resolveArrChainState` → `resolveTargetChain` · `hashArrReceipt` → never exported
> (internal to `chain.ts`) · `withinRetentionWindow` → `verify30DayWindow` ·
> `triggerRequiresReceiptRef` → `resolveTriggerReceipt`. `src/index.ts` is authoritative.

Initial publish alongside the ARR v1.0 spec. Verifier-side primitives for Anchored Retention Receipts (7 retention-lifecycle event kinds + batch):

- Canonical receipt types: `ARRReceipt`, `ARRBatchReceipt`, `ArrEventKind`, `ArrTrigger`, `ArrTargetKind`, `ArrAnchor`, `ArrDisclosureProof`.
- `verifySingleReceipt` — Ed25519 signature verification over a single `arr.*.v1` receipt, with Mode A / Mode B per profile.
- `resolveArrChainState`, `hashArrReceipt` — per-target chain walker for retention sequences (`erasure`, `expiry`, `hold_extension`, `hold_release`, `anonymization`, `pseudonymization`, `archive`).
- `verifyBatchReceipt` — RFC 6962 batch verifier for `ar.batch.v1` envelopes (max 65,536 targets / depth ≤ 16).
- `verifyBatchDisclosure` — disclosure-proof verifier for batch receipts.
- `triggerRequiresReceiptRef` — guard for `trigger: subject_request` requiring a `trigger_receipt` cross-reference (Art. 12(3) 30-day-demo enforcement).
- `withinRetentionWindow` — retention-window arithmetic for `gdpr.art5e` and other window-bounded profiles.
- Re-exports `canonicalize`, `commit`, `buildTree`, `inclusionProof`, `verifyInclusion` from upstream packages for symbol symmetry.
- Two runtime deps: `@dekimuhq/apr-verifier`, `@dekimuhq/acr-verifier`. Node ≥22.

API is `v0.x` until v1.0.0; minor versions may add event kinds or anchor fields but should not remove or rename them.
