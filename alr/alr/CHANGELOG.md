## 0.5.4

### Patch Changes

- 9694901: security(tsa): a MANDATORY TSA mandate now fails closed on any `tsa_state`
  other than `"tsa_verified"`; the TSA reference time defaults to the signed
  `iat`.

  Previously a MANDATORY mandate hard-failed only when the `tsa` block was
  absent. `tsa` sits outside the envelope signature (it is zeroed out of the
  signing input), so anyone could attach a junk block to a genuine receipt —
  garbage bytes (`tsa_malformed`), a token from an unrecognised TSA, an imprint
  mismatch, drift beyond tolerance — and the receipt kept `signature_valid: true`,
  bypassing the mandate entirely.

  **Behaviour change (MANDATORY):** a present-but-unverified `tsa` block now
  returns `signature_valid: false` with the new reason `"tsa_unverified"`
  ("timestamp not confirmed" — e.g. a verifier that lacks or does not trust the
  TSA anchor), distinct from `"tsa_required"` (no timestamp at all). `tsa_state`
  keeps the real TSA reason (e.g. `"tsa_malformed"`) so callers can see why; the
  absent case is unchanged (`reason: "tsa_required"`). Enforced by the shared
  pipeline's profile-keyed mandate (`acr.esig.accept@qes`,
  `arr.gdpr.art17.erasure-finalized`, `notice.aiact.art50_transparency`) and by
  the body-keyed mandate of AAR / ABR / ANR (issuance+qts, `breach.detected`,
  art50), which now runs on every verify path — see the
  `body-keyed-tsa-mandate-hook` changeset. An earlier, more specific failure
  reason is left intact.

  **Behaviour change (all levels): default TSA reference time is the signed
  `iat`, not the verifier's clock.** `tsaReferenceTime` still overrides. The
  token's `genTime` must lie within `tsaDriftToleranceSec` (default 300 s) of
  `iat`, and the trust anchor must be valid at `iat` (long-term validation).
  Without this, fail-closed MANDATORY would have turned every genuine timestamped
  receipt invalid ~5 minutes after mint for any caller that does not pin a
  reference time. For RECOMMENDED / OPTIONAL this changes only advisory output:
  fewer spurious `tsa_drift_exceeded` on old receipts, and a token stamped far
  from its receipt's `iat` now reports `tsa_drift_exceeded`. `verifyTsa`'s expiry
  and drift checks now fail closed on an unparseable reference time, anchor
  `valid_until` or `genTime` (previously a NaN comparison passed).

  Downstream verifiers must supply trust anchors for the TSA that issued a
  token: the bundled default is FreeTSA only, so eIDAS QTSP anchors are needed
  for qualified profiles (`acr.esig.accept@qes`, `notice.aiact.art50_transparency`).
  RECOMMENDED and OPTIONAL signature behaviour is unchanged.

- Updated dependencies [52446e0]
- Updated dependencies [9694901]
  - @dekimuhq/anchors-envelope@0.26.5

## 0.5.2

### Patch Changes

- `family.meta.spec_path` now points at the public spec (https://github.com/dekimuhq/anchors-spec/tree/main/alr) instead of an unpublished internal path.

## 0.5.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [dd49239]
- Updated dependencies [28c64ff]
  - @dekimuhq/anchors-disclosure@0.3.0
  - @dekimuhq/alr-profiles@0.5.1

## 0.4.2

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
  - @dekimuhq/alr-profiles@0.4.2

## 0.4.1

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
  - @dekimuhq/alr-profiles@0.4.1
  - @dekimuhq/anchors-envelope@0.18.1

## 0.4.0

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/alr-profiles@0.4.0

## 0.3.5

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/alr-profiles@0.3.5

## 0.3.4

### Patch Changes

- Updated dependencies
  - @dekimuhq/alr-profiles@0.3.4

## 0.3.3

### Patch Changes

- 52543f5: Declare the `@dekimuhq/alr-profiles` runtime dependency. `src/family.ts` imports
  it, but `package.json` omitted it — so consumers that don't already hoist
  `alr-profiles` (e.g. `@dekimuhq/anchors-emit`'s isolated integration tests) fail
  to resolve it. The other 7 v2 verifiers (anr/atr/apur/aer/asr/abr/air) already
  declare their `*-profiles` dep; this brings alr-verifier in line.
- Updated dependencies [db75e89]
  - @dekimuhq/anchors-envelope@0.16.0

## 0.3.0

### Minor Changes

- c2f423e: feat: add qts_attestation_hash cross-sibling QTS upgrade field

## 0.2.1 — 2026-05-20

### Changed (dep-range only — no source changes)

- `@dekimuhq/anchors-envelope` range bumped `^0.8.0` → `^0.9.0` to align with the
  non-ASR family floor (ASR triple is on `^0.10.0` post-Phase-4 because it emits
  compose warnings; every other family stays on `^0.9.0`). Closes the verifier
  side of the envelope dep-range alignment after the issuer-kit + profiles sweep
  landed in `710c338` and `86ab55b`. The follow-on flagged in
  `meta/CHANGELOG.md` 0.8.3 as "alr-verifier minor bump" — landed here as PATCH
  per the `86ab55b` precedent (dep-range refresh, no source changes).

No source changes. Test count unchanged (81/81).

regression check: `grep -n '"@dekimuhq/anchors-envelope"' anchors/alr/alr-verifier/package.json` must report `^0.9.0`.

## 0.2.0 — 2026-05-19 — cross-issuer interop Phase A Slice 2 Phase 2 — verifyIssuerTrust dispatch backport

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

## 0.1.1 — 2026-05-18

### Changed

- Phase A.2 canary adoption of `defineFamily()` from `@dekimuhq/anchors-envelope`
  0.6.0. ALR is the first family member to consume the factory. Public API is
  byte-equal: no exports changed signature, no symbols removed.

### Added

- `alrFamily` — frozen `FamilyManifest<AlrBody>` exposing identity + invariants
  (chip 9, status_list_slot 1, subject must-be-null, TSA `free` upgrade path),
  the body validator (delegates to `verifyAlrBody`), and a `walkParents`
  helper that returns canonical-sorted APR refs from lineage bodies.
- 15 family-wiring tests in `test/family.test.ts`.

### Internal

- `envelope-v2.ts` claim-type allowlist now reads from `alrFamily.isOwnedClaimType()`
  instead of a hand-rolled `Set`.
- `subject-presence.ts` delegates to `alrFamily.checkSubjectPresence()`; the
  exported `checkAlrSubjectPresence` / `applyAlrSubjectPresence` signatures
  and reason codes are unchanged.

### Dependencies

- `@dekimuhq/anchors-envelope` bumped to `^0.6.0` (defineFamily surface).

regression check: grep -rn "defineFamily\|alrFamily" anchors/alr/alr-verifier/src

## 0.1.0 — 2026-05-18

### Added

- Initial skeleton (Phase 1 §A.1 of 10-spec batch).
