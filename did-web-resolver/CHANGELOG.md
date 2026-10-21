# @dekimuhq/did-web-resolver

## 0.5.1

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.

## 0.5.0

### Minor Changes

- 4c70915: v1.3 R3 issuer PQC-migration enforcement (verify-side flip).

  - envelope: `HybridVerifyResult.validAlgs` (the verified-algorithm set); `VerifyIssuerPqc`/`VerifyIssuerPqcInput`/`IssuerPqcVerdict` seam types; family-verify-pipeline Step 5.6 invokes the injected `verifyIssuerPqc` after issuer-trust resolves to a matched record, deriving `receiptSigAlg` (highest-rank VALID alg) from `validAlgs` — never the self-described `sig_alg`. Fail-closed guard: supplying `verifyIssuerPqc` without `verifyIssuerTrust` rejects with `issuer_pqc_requires_trust_dispatch` (closes a silent-non-enforcement gap; doubt-driven).
  - trusted-issuers: `makeVerifyIssuerPqc({resolveEffectiveTime?, now?})` composes the pure `satisfiesIssuerPqc` with the effectiveTime contract (`?? now` = fail-toward-rejection); `issuerPqcRequirement`/`satisfiesIssuerPqc` pure policy + `pqc-policy` exports.
  - did-web-resolver: optional `pqc_mandatory` (`PqcMandate {min_sig_alg, mandatory_from}`) on `TrustedIssuerRecord`.

  Additive; no envelope wire change; inert until a verifier supplies `verifyIssuerPqc` AND an issuer record carries `pqc_mandatory`. Phase 2b (trustworthy inclusion-proof `effectiveTime` + PQC list-signing) deferred.

## 0.4.0

### Minor Changes

- Bind the requested `iss_key` fingerprint to the served SPKI key bytes in
  `resolveDidWebKey`. A compromised issuer domain swapping an attacker key in under
  the legitimate `iss_key` now hard-fails with the new `iss_key_fingerprint_mismatch`
  error code **before caching** — a forged key is never persisted, and the mismatch is
  re-verified on every call (not negative-cached). `verifyIssuerKey` maps the code into
  its `invalid_key_doc` outcome. Scoped to the `ed25519:` prefix; other prefixes pass
  through unchecked. Additive — legitimate receipts resolve byte-equal.

## 0.3.1

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

## 0.3.0 — 2026-05-19 — Cross-issuer interop Phase A Slice 2 Phase 3 — `makeVerifyIssuerTrust` factory

### Added

- **`makeVerifyIssuerTrust(opts)`** — factory producing a `VerifyIssuerTrust` callback ready to drop into `@dekimuhq/anchors-envelope` 0.8.0's `FamilyVerifyOptions.verifyIssuerTrust` (and the matching field on each legacy `EnvelopeVerifyOptions` in apr/acr/arr/alr 0.5.0/0.2.0). Wraps `verifyIssuerKey` with a uniform `(envelope: unknown) => Promise<IssuerTrustResult>` signature, extracting `iss` + `iss_key` from the envelope and forwarding `trustedIssuers` / `fetcher` / `cache` / `now` / `onResolve`.
- **`MakeVerifyIssuerTrustOptions`** — type-only options shape (same as `VerifyIssuerKeyOptions` minus the per-call `iss` / `iss_key` arguments).
- 8 new tests (`F1`–`F8`) covering envelope shape guards (non-object, missing iss/iss_key), scheme rejection routing, `onResolve` / `trustedIssuers` / `cache` option passthrough, and per-call independence.

### Wiring

This is the canonical default for the new `verifyIssuerTrust` opt on `@dekimuhq/anchors-envelope` 0.8.0's shared pipeline AND on the 4 backported envelope-v2 verifiers. Custom implementations are still welcome — the `VerifyIssuerTrust` type is structural.

Decision: decision (internal design record, not published).

## 0.2.0

Cross-issuer interop Phase A — full verification flow.

- **`verifyIssuerKey(opts)` — new entry point.** Wraps `resolveDidWebKey` with
  trust-tier dispatch against an optional `TrustedIssuersSource`. Returns a
  discriminated `IssuerTrustResult` with 5 outcomes — `valid_trusted` /
  `valid_untrusted` / `valid_revoked` / `invalid_key_doc` / `invalid_signature`.
  Family verifiers consume the outcome to decide hard-fail vs warning vs accept.
- **`TrustedIssuersSource` interface + `TrustedIssuerRecord` type.** Pluggable
  allowlist surface. Default implementation lives in
  `@dekimuhq/anchors-trusted-issuers` (Phase B). Self-hosted deployments may
  supply their own implementation.
- **`onResolve` observability hook.** Receives `{ iss, iss_key, outcome,
durationMs, cacheHit }` per call. The single hook for tracking network-fetch
  rate during a verify pass.
- **Negative caching on `InMemoryKeyCache`.** Optional `negativeTtlMs`
  (default 0 = disabled; recommended 30_000) caches `non_200` and
  `no_matching_key` failures to prevent hot-loop fetches. `KeyCache` interface
  gains optional `getNegative` / `setNegative` methods — backward-compatible.
- **New error codes:** `iss_scheme_unsupported`, `issuer_revoked`,
  `negative_cached`.
- **No breaking changes.** `resolveDidWebKey` + `InMemoryKeyCache` retain their
  0.1.0 contracts; existing tests pass byte-equal.

Cross-family invariants reference: `meta/FAMILY-CONSISTENCY.md §5`.
Plan: an internal design record (not published).

## 0.1.0

Initial release. `resolveDidWebKey` + `InMemoryKeyCache` per
`/.well-known/dekimu-keys.json` v1 convention.
