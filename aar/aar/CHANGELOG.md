# Changelog

## 0.4.4

### Patch Changes

- 52446e0: security(tsa): the body-keyed TSA mandate now applies on every verify path.

  ABR `breach.detected`, AAR issuance with `service_type: qts` and ANR
  `notice.aiact.art50_transparency` are MANDATORY under FAMILY-CONSISTENCY §2,
  keyed on the signed body rather than on the caller's `opts.profile`. Until now
  that mandate ran only as a post-step in each package's top-level
  `verifyReceipt`. The CLI (`anchors verify`, which dispatches to
  `<family>Family.verifyReceipt`) and any direct caller of `aarFamily` /
  `abrFamily` / `anrFamily.verifyReceipt` skipped it, so such a receipt with no
  `tsa`, or with a junk one, verified as valid on those paths.

  `defineFamily()` gains an optional `body_tsa_mandate: (body) => level` hook.
  The shared verify pipeline applies it as its final step, with the same
  fail-closed rule as the profile-keyed mandate: `"mandatory"` and no block gives
  `reason: "tsa_required"`; `"mandatory"` and any `tsa_state` other than
  `"tsa_verified"` gives `reason: "tsa_unverified"` (the real TSA reason stays
  in `tsa_state`); `"recommended"` and no block gives
  `tsa_state: "tsa_recommended"`. A hook that throws fails closed with
  `tsa_mandate_threw:<msg>`. AAR, ABR, AIR and ANR declare the hook, and their
  top-level `verifyReceipt` no longer re-applies the post-step. Results on the
  package-wrapper path are unchanged. The exported `apply*TsaMandate` helpers
  are kept.

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

## 0.4.2

### Patch Changes

- `family.meta.spec_path` now points at the public spec (https://github.com/dekimuhq/anchors-spec/tree/main/aar) instead of an unpublished internal path.

## 0.4.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [28c64ff]
  - @dekimuhq/aar-profiles@0.4.1

## 0.3.3

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
  - @dekimuhq/aar-profiles@0.3.3
  - @dekimuhq/anchors-envelope@0.18.1

## 0.3.2

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/aar-profiles@0.3.2

## 0.3.1

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/aar-profiles@0.3.1

## 0.3.0

### Minor Changes

- db75e89: Wire AAR's per-event TSA mandate into verification. `applyAarTsaMandate` (FAMILY-CONSISTENCY §2: issuance+qts MANDATORY, else RECOMMENDED) was exported but never called, so a qts-issuance receipt with no TSA block verified as valid instead of hard-failing. `verifyReceipt` now applies the body-keyed mandate post-step, mirroring ABR/AIR. Behavior change: qts issuance receipts lacking a `tsa` block now fail with `reason: "tsa_required"`; other issuance/revocation events surface `tsa_state: "tsa_recommended"`.

### Patch Changes

- Updated dependencies [db75e89]
  - @dekimuhq/anchors-envelope@0.16.0
  - @dekimuhq/aar-profiles@0.3.0

## 0.2.1

### Patch Changes

- fix(aar): use ProfileValidator adapters in family manifest instead of raw body-typed validators

## 0.2.0

### Minor Changes

- c2f423e: feat: add qts_attestation_hash cross-sibling QTS upgrade field

### Patch Changes

- @dekimuhq/aar-profiles@0.2.0
