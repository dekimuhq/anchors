# Changelog — `@dekimuhq/anchors-envelope`

## 0.26.2

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.

## 0.26.1

### Patch Changes

- d700da7: Type-correctness: `Envelope.subject` is now `string | null` (was `string`). Null-subject families (AActR/AQR/AGR/AGrR/AgTR/APIIR/ACBR and the event-conditional null cases of ATR/AER/ABR/AIR/APuR/ALR) carry a literal `null` subject on the wire; the type now matches runtime. Verifiers already enforce the per-family subject-presence rule (FAMILY-CONSISTENCY §3) via each family's `checkSubjectPresence`, so this is purely a type widening — no runtime change, and `tsc` is clean across all family packages. Consumers no longer need to cast (e.g. `@dekimuhq/anchors-vc` was working around this).
- 82541e7: fix(tsa): verify CMS SignerInfo signature over TSTInfo (fail-closed). `verifyTsa` previously checked status, message imprint, pinned trust anchor, chain-link signatures, and genTime drift — but never the SignerInfo signature bytes themselves, so a genuine TSA cert chain paired with a fabricated TSTInfo verified true. Now, per RFC 5652 §5.4/§5.6 + RFC 3161: when signedAttrs are present the content-type attribute must be id-ct-TSTInfo, the message-digest attribute must equal hash(eContent), and the signature is verified over the SET-OF-retagged SignedAttributes DER against the signer cert identified by SignerIdentifier (issuerAndSerialNumber matched on issuer DER + serial; subjectKeyIdentifier falls back to trying each chain cert — the crypto check is the binding). Without signedAttrs the signature is verified over the eContent directly. RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA, and Ed25519 supported via `node:crypto` only. Two additive `TsaReason` values: `tsa_signed_attrs_invalid`, `tsa_cms_signature_invalid`. Parser additions (additive): `SignerInfo.signatureAlg`/`sid`/`signedAttrsDer`, `ParsedTsr.tstInfoDer`, exported `SignerId` type.

## 0.25.1

### Patch Changes

- c8e00ba: fix(tsa): set `certReq: true` in `attachTsaBlock`'s RFC 3161 request

  RFC 3161 defaults `certReq` to FALSE, in which case TSAs (e.g. FreeTSA) return a
  TimeStampToken with **no embedded certificates**. `verifyTsa` matches the trust
  anchor against certs embedded in the token, so without `certReq` the signer chain
  is empty and every live timestamp fails as `tsa_unrecognised_anchor` — even
  against the bundled FreeTSA root. With `certReq: true` FreeTSA embeds
  `[TSA leaf, Root CA]`; the Root's SHA-256 DER matches the `freetsa-root-ca`
  anchor → `tsa_verified`. This makes TSA-MANDATORY receipts (e.g. ABR
  `breach.detected`) verifiable for every family.

## 0.18.1

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

## 0.18.0

### Minor Changes

- 7c4329d: Phase 2 Tier A: add `./merkle` + `./commit` shared primitives (lifted from acr-verifier, no API break) and the `ar.field_commit.v1` standalone attestation (`./field-commit`) that binds a receipt id to its `field_root` + signed `leaf_count`, enabling selective-disclosure verification without the body.

## 0.17.0

### Minor Changes

- a054911: add incl to signed-out + allowed-fields sets (v1.4 transparency log)
- a4aee8f: v1.3 signature-algorithm agility hook + C-1 canonicalization correction.

  **New (`sig_alg` hook):** the envelope gains an optional, SIGNED-IN `sig_alg`
  discriminator (closed enum, additive-only). Absent ≡ `"ed25519"`, so v1.1/v1.2
  receipts and Ed25519 v1.3 issuers stay byte-equal. Signature verification now
  dispatches through a `SIG_VERIFIERS` registry keyed by algorithm; an algorithm
  the verifier cannot evaluate is refused with `unsupported_sig_alg` (never
  attempted as ed25519, never silently passed). Phase 1 registers **ed25519
  only** — the post-quantum members (`ml-dsa-65`, `slh-dsa-sha2-128s`) are NOT
  committed to the wire because `node:crypto` does not surface them on the current
  Node floor (spike: negative on Node 22 / OpenSSL 3.5.5); they join the enum as a
  pure additive change once a provider is settled. New exports: `SIG_ALGS`,
  `SigAlg`, `isSupportedSigAlg`.

  **Fix (C-1, byte-equality):** `preSigCanonical` split its single signed-out list
  into `SIGNED_OUT_ZEROED` (the 4 mandatory always-present fields, zeroed to
  `null` — idempotent) and `SIGNED_OUT_EXCLUDED` (optional fields, deleted). The
  v1.4 transparency block `incl` was previously added to the unconditional
  zero-list, which injected `"incl":null` into the canonical form of every receipt
  — including the existing corpus that never carried it — silently breaking the
  signature of every pre-v1.4 receipt on re-verification. `incl` is now EXCLUDED
  (delete-if-present): old receipts canonicalize identically, and an `incl` block
  attached post-mint by the log never perturbs the signature. Caught pre-publish
  (envelope was unreleased); no production receipts were affected.

  Regression coverage: frozen-vector byte-equal tests (incl absent / attached /
  upgraded), `sig_alg` signed-in tamper detection, and `unsupported_sig_alg`
  refusal at both the primitive and pipeline layers.

## 0.16.0

### Minor Changes

- db75e89: Add a sound `TsaState` type for `FamilyVerifyResult.tsa_state`. The field was typed `"tsa_absent" | TsaReason`, but the per-family TSA-mandate post-steps (ABR/AIR/ARR/AAR/…) assign `"tsa_required"` and `"tsa_recommended"` — values outside that union. New exported `TsaState` (from `@dekimuhq/anchors-envelope/tsa`) is the mandate-aware superset (`"tsa_absent" | "tsa_required" | "tsa_recommended" | TsaReason`), and `FamilyVerifyResult.tsa_state` now uses it. Additive and non-breaking: every previously-valid value is still valid; consumers gain accurate typing for the mandate states families already emit.

## 0.15.0

### Minor Changes

- Export suspension-attach, suspension-pointer, suspension-verify, and suspension-types from the status barrel. Fixes build failures in acr-issuer-kit and arr-issuer-kit 0.6.0 consumers.

The shared envelope for the Anchored Receipts protocol family.

## 0.13.0 — 2026-05-21

### Added — `countersig_key` envelope field (countersignature verification delta)

New optional **signed-in** field on the `Envelope` interface:

```typescript
countersig_key?: `ed25519:${string}` | null;
```

- Identifies the public key of the expected countersigner. The issuer commits
  to the countersigner identity at signing time — mutating `countersig_key`
  after issuance invalidates the issuer's signature.
- When both `countersig_key` and `countersig` are present, verifiers can
  perform full Ed25519 cryptographic verification of the countersignature.
  When `countersig_key` is absent, only format checking (64-byte length) is
  possible (backward-compatible with all pre-0.13.0 receipts).
- `ALLOWED_TOP_LEVEL` grows from 22 to 23 fields; `rejectUnknownFields`
  accepts the new field.
- Algorithm-agile: the `ed25519:` prefix follows the same convention as
  `iss_key`, providing a clean upgrade path to post-quantum algorithms.
- Decision: an internal design record (not published).

## 0.11.0 — 2026-05-20

### Added — chain-walk resolver for compose callbacks (Phase 4B-2 prerequisite)

One additive optional resolver on `FamilyVerifyOptions` that lets family
compose callbacks walk the envelope-`prev` chain against an authoritative
corpus and surface chain-walk warnings.

- **`FamilyVerifyOptions.resolveReceiptById?: (id: string) => Promise<unknown> | unknown`**
  — optional "fetch receipt envelope by id" resolver. Sync or async. First
  consumer: `@dekimuhq/air-verifier 0.3.0` (`composeAir` walks the DPIA
  lifecycle chain to surface `dpia_review_overdue`, `dpo_commit_drift`,
  `dpia_post_hoc_warning`, `art36_consultation_overdue`,
  `voluntary_high_risk_no_consultation`, `re_dpia_predecessor_missing`).
  Generic surface — ANR / ABR planned consumers in Phase 4C / Phase 4D.
  When undefined, the consuming compose callback MUST skip chain-walk
  warnings silently. Matches the optional-resolver discipline of
  `resolveArr` / `findDisclosedAlrsForSubject` / `chainResolver`. Thrown
  exceptions are caught by the pipeline as `compose_threw:<msg>`.
- **`ComposeInput.envelope` carries three additional fields** — `id`, `iss`,
  and `prev`. Required by chain-walking compose callbacks to locate
  themselves in the chain and follow the `prev` pointer back to ancestors.
  Additive extension — existing compose callbacks that read only the
  pre-0.11.0 fields (`claim_type` / `body` / `subject` / `iat`) keep
  compiling and produce byte-equal output.

### Migration

No migration required — purely additive. Existing compose callbacks that
don't read `opts.resolveReceiptById` keep compiling and produce
byte-equal output.

regression check: `grep -n "resolveReceiptById" envelope/src/family-verify-pipeline.ts` reports ≥1 hit.

## 0.10.0 — 2026-05-20

### Added — compose warnings channel + art19 completeness resolver (Phase 4)

Closes the Phase 3 §G deferral. Two additive shape changes that let family `compose` callbacks emit _informational_ diagnostics without conflating them with HARD failures.

- **`ComposeResult.warnings?: readonly string[]`** — optional warnings channel on both `{ ok: true, … }` and `{ ok: false, reason, … }` branches. When non-empty, the pipeline appends each entry to `FamilyVerifyResult.warnings` via the existing `appendWarnings` helper (same pool used for status-list freshness warnings). Warnings do NOT poison `signature_valid` — they are advisory only. When omitted or empty, no warnings are added. Backward-compatible: existing compose callbacks returning bare `{ ok: true }` / `{ ok: false, reason }` keep working byte-equal.
- **`FamilyVerifyOptions.findDisclosedAlrsForSubject?: (subject: string) => Promise<readonly string[]> | readonly string[]`** — optional resolver returning the authoritative complete set of disclosed-ALR receipt ids for a subject. Sync or async. Consumed by family compose callbacks that need to detect informational incompleteness against a known universe (ASR art19 is the first consumer in `@dekimuhq/asr-verifier 0.4.0`). When undefined, the consuming compose callback MUST skip the completeness check silently — matches the optional-resolver discipline of `resolveArr` / `resolveAlr` / `resolveAtr` / `resolveApur`. Thrown exception caught by the pipeline as `compose_threw:<msg>`.

### Pipeline change

`buildVerifyReceipt` Step 14 now collects `composeR.warnings` (if present and non-empty) before checking `composeR.ok`. On HARD failure the warnings still land in `FamilyVerifyResult.warnings` — useful diagnostic alongside the failure reason.

### Migration

No migration required — both additions are fully optional. Existing compose callbacks returning bare result shapes keep compiling and produce byte-equal output.

regression check: `grep -n "composeR.warnings\|findDisclosedAlrsForSubject" envelope/src/family-verify-pipeline.ts` reports ≥2 hits.

## 0.9.0 — 2026-05-19

### Added — compose-callback surface extensions for cross-family resolution (ASR Phase 3 §G prerequisite)

First MINOR after the trust-dispatch landing in 0.8.0. Two additive surface changes for family `compose` callbacks that walk into sibling families (ASR is the first consumer — art17 ↔ ARR, art19 ↔ ALR, art20 ↔ ATR, art21 ↔ APuR).

- **`ComposeInput.envelope.iat: string`** — the receipt's `iat` is now plumbed through to the compose callback alongside `claim_type` / `body` / `subject`. ASR's art17 fulfilment ±14-day window check against the linked ARR receipt's `iat` is the load-bearing reason. Additive — existing compose callbacks that only read `claim_type` / `body` / `subject` keep working byte-equal.
- **`FamilyVerifyOptions.resolveArr?` / `.resolveAlr?` / `.resolveAtr?` / `.resolveApur?`** — four optional cross-family resolvers. Each takes a receipt id, returns the resolved envelope as `unknown` (compose callbacks duck-type the fields they need) or `null` for "not found". Sync or async. Thrown exception is caught by the pipeline and surfaces as `compose_threw:<msg>`. When undefined, consuming compose callbacks MUST skip the related cross-walk silently — matches the optional-resolver discipline of `chainResolver`, `statusListRootKey`, `fetchPolicy`. Backward-compatible: callers without resolvers wired keep passing verification.

### Migration

No migration required — `iat` is additive on the input shape (no compose callback today reads any field that conflicts), and the 4 resolvers are purely opt-in. Existing 0.8.x callers see byte-equal results.

regression check: `grep -n "resolveArr\|resolveAlr\|resolveAtr\|resolveApur" envelope/src/family-verify-pipeline.ts` reports ≥4 hits.

## 0.8.0 — 2026-05-19

### Added — issuer-trust dispatch (cross-issuer interop Phase A Slice 2 Phase 1)

Slice 2 of the cross-issuer interop plan (internal design record, not published). Locked via Option B decision (internal design record, not published) — trust outcome propagates on the verify result, not via a caller-side channel. Shared-pipeline landing (this release) automatically enables trust-aware verification for every factory-based family member (ASR / ABR / ANR / AIR + future families using `defineFamily`). Legacy `envelope-v2.ts` duplicates in APR / ACR / ARR / ALR get the same surface in Phase 2.

- **New type-only module `envelope/src/issuer-trust.ts`** — structural mirror of `@dekimuhq/did-web-resolver`'s trust types. Envelope intentionally does NOT depend on did-web-resolver at runtime (would cycle — did-web-resolver depends on `@dekimuhq/anchors-envelope` for `Envelope` typing). Any conformant resolver produces results structurally assignable to `IssuerTrustResult`. Exports: `IssuerTrustOutcome`, `IssuerTrustResult`, `IssuerTrustResultValid`, `IssuerTrustResultInvalid`, `TrustedIssuerRecord`, `VerifyIssuerTrust`.
- **`FamilyVerifyOptions.verifyIssuerTrust?: VerifyIssuerTrust`** — new optional callback. When defined, fires as Step 5.5 between Step 5 (key resolution) and Step 6 (trusted-log allowlist). When undefined, the pipeline behaves byte-equal to 0.7.x. Backward-compatible.
- **`FamilyVerifyResult.trust_outcome?` + `.trust_reason?` + `.trusted_issuer_record?`** — new optional result fields. Set iff `verifyIssuerTrust` was supplied.
- **Step 5.5 dispatch semantics:**
  - `valid_trusted` → continue pipeline, surface outcome + record
  - `valid_untrusted` → continue pipeline, surface outcome with `trusted_issuer_record: null`
  - `valid_revoked` → HARD FAIL: `signature_valid: false`, `reason: "issuer_revoked"`
  - `invalid_key_doc` → HARD FAIL: `signature_valid: false`, `reason: "did_web_invalid_key_doc:<r>"`
  - `invalid_signature` → HARD FAIL: `signature_valid: false`, `reason: "did_web_invalid_signature:<r>"`
  - Thrown exception → caught: `signature_valid: false`, `reason: "verify_issuer_trust_threw:<msg>"`
- **10 new tests in `family-verify-pipeline.test.ts §17`** covering all 5 outcomes + default-undefined legacy-preserve + throw safety + dispatch ordering (Step 5 fails before 5.5 fires; Step 5.5 fails before Step 6 runs) + downstream-still-runs (`valid_trusted` does not short-circuit profile / status / TSA). Envelope tests: **449/449** (was 439).

### Migration

No migration required — `verifyIssuerTrust` is purely opt-in. To enable, supply a callback that returns `IssuerTrustResult`. The default implementation will ship in `@dekimuhq/did-web-resolver` 0.3.0 (Phase 3) as `makeVerifyIssuerTrust({ trustedIssuers, fetcher, cache, onResolve })`.

regression check: `grep -n "verifyIssuerTrust\|trust_outcome" envelope/src/family-verify-pipeline.ts envelope/test/family-verify-pipeline.test.ts` reports ≥6 hits.

## 0.7.1 — 2026-05-19

### Fixed

- `POLICY_BOUND` now includes `ar.impact.v1` (AIR is POLICY_BOUND per spec §3.1 — `policy_uri` references the controller's published DPIA methodology under which the receipt is issued). Mirrors the `ar.lineage.v1` / `ar.notice.v1` / `ar.breach.v1` additions in 0.5.1 / 0.6.1 / earlier ABR §D: §B for AIR (`1294246`) wired the verifier surface for POLICY_BOUND semantics but never reclassified the discriminator in the envelope's policy matrix, so `validatePolicyFields` returned `"unknown_claim_type"` for otherwise-valid v=2 AIR receipts. Surfaced by the first end-to-end AIR §D dispatch test. Patch release: additive set membership only, no API change.
- Publish hold from 0.7.0 carries forward to 0.7.1 — both versions stay unpublished on GitHub Packages until the A.2-full Phase 2 consumer (ANR migration to factory) validates the new surface AND a downstream AIR-family release exercises the matrix entry end-to-end.

## 0.7.0 — 2026-05-19

### Added — `defineFamily()` A.2-full extension

The metadata-and-validators slice landed in 0.6.x (Phase A.2 + A.3). A.2-full extends the factory to a full pre-bound manifest. Every addition is additive and optional — existing `defineFamily()` callers stay byte-equal.

- `FamilyDefinition.subject_presence_check?: SubjectPresenceCheck` — per-event subject-presence override callback. When present, replaces the universal `subject_presence` rule. Used by ANR (per-event rule: `notice.acknowledged` MUST be `"sha256:<hex>"`, other events MAY be `null`). Throw-safe: callback exceptions caught → `{ ok: false, reason: "subject_check_threw:<msg>" }`. Config-time guard: non-function throws at `defineFamily()`. `FamilyManifest.checkSubjectPresence(subject, body?)` accepts new optional `body` arg.
- `FamilyDefinition.tsa_mandate?: Readonly<Record<string, "mandatory" | "recommended">>` + `FamilyManifest.tsaMandateLevel(profile_id) => "mandatory"|"recommended"|"optional"`. Per-profile TSA enforcement matrix. Construction-time guards reject: non-object, unknown profile id, invalid level.
- New module `envelope/src/ed25519.ts` — Ed25519 keypair + canonical sign/verify helpers hoisted from per-family `keys.ts` duplication. Exports `Keypair`, `generateKeypair`, `publicKeyFromSeed`, `encodeRaw`, `decodeRaw32`, `signCanonical`, `verifyCanonical`. All `Uint8Array`-based (no Node `KeyObject` in public API).
- `FamilyManifest.generateKeypair(kid)` + `FamilyManifest.signCanonical(body, privateKeySeed)` — pass-through references to the new envelope helpers.
- New module `envelope/src/family-verify-pipeline.ts` — pre-bound `verifyReceipt` builder. Returns a function that runs the 13-step verify pipeline (unknown-field rejection → global+family claim_type → status-list slot gate → key resolve + signature verify → trusted-log allowlist → iat + predicate → policy fields → body schema → subject presence → status reconciliation → TSA dispatch → TSA mandate matrix → profile dispatch). Mirrors the hand-rolled `envelope-v2.ts` pipeline that 4 shipped families currently duplicate. Pre-bound on `FamilyManifest.verifyReceipt`. Throw-safety on `resolveKey` callback (caught → `signature_valid: false`, reason prefix `resolve_key_threw:`).
- New module `envelope/src/family-mint-pipeline.ts` — pre-bound `mintV2` builder. 9-step mint pipeline (private-key length gate → body schema → subject presence pre-check → claim_type selection → unsigned envelope build → credentialStatus attach → sign → TSA attach → return). Pre-bound on `FamilyManifest.mintV2`. Round-trip with `verifyReceipt` proven via cross-orchestrator test.
- `FamilyDefinition.compose?: ComposeCallback` + `FamilyManifest.compose?` — optional verify-time composition walker. Runs as step 14 (after profile dispatch). Used by families with cross-family links (ALR↔APR parent walker, ACR↔ANR notice link). Throw-safe (`compose_threw:<msg>`). Config-time guard: non-function throws.
- `FamilyManifest.mintContinuity?` + `FamilyManifest.verifyContinuity?` — pass-through references to envelope's continuity helpers, populated iff `def.continuity === true`. Sync (not async) — match the underlying `issueContinuityAttestation` / `verifyContinuityAttestation` signatures.
- 88 new envelope tests across 4 test files (`define-family.test.ts` +7, `ed25519.test.ts` 10, `family-verify-pipeline.test.ts` 37 (30 pipeline + 7 compose), `family-mint-pipeline.test.ts` 22). Workspace runs **442/442 envelope tests** end-of-Phase-1 (was 354 at start of A.2-full work).

### Added — `@dekimuhq/anchors-envelope/continuity` subpath export

- Family-shared `ar.continuity.v1` issuer key-rotation attestation. Promoted from per-family `<family>.continuity.v1` (ALR / ARR / ANR) to the canonical `ar.<noun>.v<N>` wire form. Single source of truth for the issue + verify + cryptographic check. Each member's issuer-kit re-exports the helpers and pins its own `family` slug at issue time.
- New types: `ContinuityAttestation`, `IssueContinuityInput`, `VerifyContinuityResult`, `FamilySlug` (closed 13-member union matching the family taxonomy), `ContinuitySealedMappingAlg`.
- New functions: `issueContinuityAttestation(input)`, `verifyContinuityAttestation(att)`.
- 6 new tests in `envelope/test/continuity.test.ts` covering: round-trip across all 13 family slugs, tampered-field rejection (`sig.invalid`), missing-sig rejection (`sig.missing`), corrupt iss_key rejection (`sig.import_error`), cross-family swap rejection (signature covers `family`), and legacy `<family>.continuity.v1` rejection (`kind.invalid`).

### Notes

- Pre-launch hard-cut on continuity: no back-compat path for legacy `<family>.continuity.v1`. Verifier short-circuits on `kind !== "ar.continuity.v1"` with `kind.invalid`. `find anchors -name "*.continuity.v1.json"` returned zero hits before the cut — no production attestation has ever been minted.
- Continuity attestation is NOT a v=2 envelope. No `claim_type`, no `field_root`, no `anchor` block. Not added to the `CLAIM_TYPES` runtime constant.
- A.2-full additions are 100% backward-compatible. Pre-Phase-1 `defineFamily()` callers produce byte-equal manifests; new fields are all optional with safe defaults.
- **Publish hold:** 0.7.0 stays unpublished on GitHub Packages until Phase 2 (ANR migration to factory) validates the new surface against a real consumer. Per maintainer decision 2026-05-19.
- Bumps `@dekimuhq/anchors-envelope` minor (0.6.2 → 0.7.0): combined feature wave (A.2-full factory extension + continuity unification subpath). Downstream consumers (`alr-issuer-kit ≥ 0.2.0`, `arr-issuer-kit ≥ 0.5.0`, `anr-issuer-kit ≥ 0.2.0`, and the Phase 4 migrations of `apr-issuer-kit` / `acr-issuer-kit`) bump their envelope dep range to `^0.7.0`.

Specs:

- https://github.com/dekimuhq/anchors-spec/tree/main/envelope (A.2-full extension; see §6)
- an internal design record (not published) (implementation plan)
- https://github.com/dekimuhq/anchors-spec/tree/main/envelope (continuity subpath)

## 0.6.2 — 2026-05-18

### Changed

- `defineFamily()` now accepts `status_list_slot: number | null` (was `number`, required ≥ 1). `null` declares the family intentionally does NOT consume W3C Status List 2021 — required by APR per FAMILY-CONSISTENCY §4 (provenance receipts are non-revocable by design). Additive: existing consumers (ALR/ACR/ARR closure set) keep their integer slots and emit identical manifests. Surfaced by Phase A.3 APR migration.

## 0.6.1 — 2026-05-18

### Fixed

- `POLICY_BOUND` now includes `ar.notice.v1` (ANR is POLICY_BOUND per spec D10-ANR-3 — the notice itself is the policy artifact). Mirrors the `ar.lineage.v1` fix in 0.5.1: §B for ANR (`48bc20b`) wired the verifier surface for POLICY_BOUND semantics but never reclassified the discriminator in the envelope's policy matrix, so `validatePolicyFields` returned `"unknown_claim_type"` for otherwise-valid v=2 ANR receipts. Surfaced by the first end-to-end ANR §D dispatch test. Patch release: additive set membership only, no API change.

## 0.6.0 — 2026-05-18

### Added

- `defineFamily()` — declarative family-member factory (Phase A.1 of the design RFC at https://github.com/dekimuhq/anchors-spec/tree/main/envelope). Consumes a single `FamilyDefinition` config and returns a frozen `FamilyManifest` exposing: identity/invariants meta block, `validateBody`, `isOwnedClaimType`, `checkSubjectPresence`, profile registry helpers, and optional `walkParents`. Pure config-time validation (acronym/claim_types/chip/status_list_slot/subject_presence/tsa_upgrade_path/body_schema/profiles/composition); manifest helpers are total — `validateBody` and `walkParents` catch user-supplied function throws and surface them as result errors so a misbehaving family schema cannot crash a verifier.
- New types: `FamilyDefinition`, `FamilyManifest`, `FamilyMeta`, `FamilyCompositionConfig`, `BodyValidator`, `BodyValidateResult`, `SubjectPresence`, `SubjectPresenceResult`, `TsaUpgradePath`.
- 40 tests covering identity validation, claim_type ownership, invariants, subject-presence rules, profile registry order + `dispatchProfiles` integration, frozen-meta invariants, and walkParents fallbacks.

Phase A.1 ships the surface only — no family adopts yet. ALR canary migration lands under Phase A.2.

## 0.5.2 — 2026-05-18

### Fixed

- Added missing `LICENSE` file (Apache-2.0). 0.5.1 listed `LICENSE` in `package.json#files` but the file was absent in the package directory, so prior tarballs shipped without the license text. No code change; ships the file the manifest already advertised. Surfaced by the cohesion auditor's hygiene pass (`8844aaa`).

## 0.5.1 — 2026-05-18

### Fixed

- `POLICY_BOUND` now includes `ar.lineage.v1` (ALR is POLICY_BOUND per spec §3). Closure-set discriminators were never reclassified after Phase C Task 14 — first end-to-end v=2 ALR dispatch (alr-verifier Phase 1 §D) surfaced the gap, returning `"unknown_claim_type"` for otherwise-valid receipts. Patch release: additive set membership only, no API change. Other closure-set members will be classified as each family's Phase B lands.

## 0.5.0 — 2026-05-18

### Added

- `CLAIM_TYPES`: closure-set discriminators `ar.notice.v1`, `ar.breach.v1`, `ar.subject_rights.v1`, `ar.impact.v1` (per `anchors/meta/REGISTRY.md` "Specced Members"). Union now has 20 entries.
- `CAUSE_VALUES`: 3 additive enum values per D-anchors-7 — `"breach"`, `"review_cycle"`, `"material_change"`. Enum grows 10 → 13 entries; `Cause` type updated accordingly. No envelope version bump (L4 additive-only rule). Conformance fixtures in `test/fixtures/cause/`.

## 0.4.0 — v1.2 envelope amendment

### Added

- 4 new optional envelope fields per [v1.2 spec](spec/v1.2.md): `kind`, `cause`, `predicate`, `iat_ms`. v1.1 receipts (without these fields) remain byte-equal verifiable.
- `JSON_LOGIC_ALLOWLIST_V1_2` — pinned 27-operator subset of standard JSON Logic, exported as the canonical predicate operator set. Member specs reference by constant import, never by re-list.
- Zero-dep JSON Logic evaluator (`evaluatePredicate`) implementing the allowlist with deterministic semantics — no I/O, no async, no Date.now(). Throws typed errors for division-by-zero, modulo-by-zero, and var-path-invalid.
- AST validator (`validatePredicate`) — single-walk first-violation static check producing `predicate_operator_not_allowed`, `predicate_var_path_invalid`, `predicate_malformed_ast`.
- Composable verifier helpers (`checkIatMs`, `checkPredicate`) returning `{ ok } | { ok:false, reason }` for member-verifier composition.
- Field inventory grows 18 → 22; `ALLOWED_TOP_LEVEL` updated accordingly.

### Note

- This is a minor bump under 0.x semver — consumers using `^0.3.0` must update to `^0.4.0` to receive v1.2 surface (and to satisfy the bumped envelope dep range in apr/acr/arr packages).
