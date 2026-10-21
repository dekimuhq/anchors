# @dekimuhq/asr-verifier changelog

## 0.6.2

### Patch Changes

- `family.meta.spec_path` now points at the public spec (https://github.com/dekimuhq/anchors-spec/tree/main/asr) instead of an unpublished internal path.

## 0.6.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [28c64ff]
  - @dekimuhq/asr-profiles@0.6.1

## 0.5.5

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
  - @dekimuhq/asr-profiles@0.5.5

## 0.5.4

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
  - @dekimuhq/asr-profiles@0.5.4

## 0.5.3

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/asr-profiles@0.5.3

## 0.5.2

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/asr-profiles@0.5.2

## 0.5.1

### Patch Changes

- Align `@dekimuhq/anchors-envelope` dependency range to `^0.16.0` across all remaining families. These packages pinned `^0.13.0`, which cannot resolve the published envelope `0.16.0` (caret on a 0.x minor) — leaving the dependency range unsatisfiable for downstream consumers. Envelope 0.16.0 is additive (adds the mandate-aware `TsaState` type), so this is a metadata-only alignment with no behavior change.
- Updated dependencies
  - @dekimuhq/asr-profiles@0.5.1

## 0.5.0

### Minor Changes

- c2f423e: feat: add qts_attestation_hash cross-sibling QTS upgrade field

## 0.4.0 — 2026-05-20

### Added — Phase 4 informational warnings on composeAsr

Closes the Phase 3 §G deferral. `composeAsr` now emits two informational warnings via the new `ComposeResult.warnings` channel introduced in `@dekimuhq/anchors-envelope` 0.10.0. Warnings flow into `FamilyVerifyResult.warnings` without poisoning `signature_valid`.

- **`art20_cross_border_atr_missing`** (spec §8.3, §5.5) — emitted when the receipt anchors a subject-directed transfer (`body.portability_recipient_did` set on `subject_rights.art20.portability` + `request.fulfilled`) without pairing it with an `body.atr_receipt_id`. Conservative trigger — the verifier cannot determine EU vs non-EU recipient status from byte data alone, so issuers performing EU-only transfers may safely ignore this warning. The existing parity HARD-walks on `atr_receipt_id` (when both set + `opts.resolveAtr` wired) are unchanged.
- **`art19_recipient_set_incomplete`** (spec §4.9) — emitted when `opts.findDisclosedAlrsForSubject` is wired (new in envelope 0.10.0) AND the body's `recipient_set_alr_ids` is a strict subset of the resolver's authoritative complete set for the subject. Resolver-undefined → skip silently per the optional-resolver discipline. The existing per-ALR cascade HARD-walks (`art19_alr_link_unresolvable`, `art19_alr_wrong_claim_type`, `art19_alr_wrong_event_type`, `art19_alr_subject_mismatch`) are unchanged.

### Changed

- `@dekimuhq/anchors-envelope` dep range bumped `^0.9.0` → `^0.10.0` to reach the new `ComposeResult.warnings` field and `FamilyVerifyOptions.findDisclosedAlrsForSubject` resolver. Pre-0.10.0 envelopes do not surface `warnings` on `ComposeResult` and the new resolver opt is structurally absent.

### Migration

No source migration required — callers that don't supply `findDisclosedAlrsForSubject` see byte-equal `signature_valid` and an unchanged `reason` namespace. Callers that read `FamilyVerifyResult.warnings` will see new advisory entries when the conditions above hold.

regression check: `grep -n "art20_cross_border_atr_missing\|art19_recipient_set_incomplete" asr/asr-verifier/src/compose.ts` reports ≥2 hits.

## 0.3.0 — 2026-05-19

### Added — Phase 3 §G cross-family composition

First family to consume the v0.9.0 envelope `compose` callback surface. Wires four cross-walks onto `asrFamily.compose` and re-exports the implementation as `composeAsr` for direct use.

- **`composeAsr`** (`src/compose.ts`) — `ComposeCallback` that the orchestrator invokes as the final pipeline step after profile dispatch. Implements the four spec-mandated cross-family walks:
  - **Art. 17 ARR (MANDATORY, HARD-invalid)** — on `subject_rights.art17.erasure_request` + `request.fulfilled`:
    - `body.arr_receipt_id` MUST be a non-empty string → `art17_arr_link_missing`.
    - When `opts.resolveArr` is wired:
      - resolver returns null / non-object → `art17_arr_link_unresolvable`.
      - ARR `claim_type` ∉ {`ar.erasure.v1`, `ar.anonymization.v1`} → `art17_arr_wrong_claim_type`.
      - ARR `body.target_kind !== "subject"` OR `body.target_commit !== ASR.subject` OR ASR subject null → `art17_arr_subject_mismatch`.
      - ARR `iat` outside ±14 days of ASR `iat` (or unparseable) → `art17_arr_stale_link`.
  - **Art. 19 ALR cascade (HARD-invalid shape)** — on art16/art17/art18 + `request.recipient_notified`:
    - Each `recipient_set_alr_ids[i]` walked through `opts.resolveAlr`. Empty / non-string array entries → `art19_recipient_set_invalid`. Unresolved → `art19_alr_link_unresolvable`. Wrong `claim_type` (not `ar.lineage.v1`) → `art19_alr_wrong_claim_type`. Wrong `body.event_type` (not `"disclosed"`) → `art19_alr_wrong_event_type`. Subject mismatch → `art19_alr_subject_mismatch`. Short-circuits on first failure (does not iterate remaining recipients).
  - **Art. 20 ATR (OPTIONAL, parity-check only)** — on `subject_rights.art20.portability` + `request.fulfilled`, when `body.atr_receipt_id` is present AND `opts.resolveAtr` is wired: `art20_atr_link_unresolvable` / `art20_atr_wrong_claim_type` (`ar.transfer.v1` required) / `art20_atr_subject_mismatch`. Absence of either resolver or field is fine.
  - **Art. 21 APuR (OPTIONAL, parity-check only)** — on `subject_rights.art21.objection` + `request.fulfilled`, when `body.apur_receipt_id` is present AND `opts.resolveApur` is wired: `art21_apur_link_unresolvable` / `art21_apur_wrong_claim_type` (`ar.purpose.v1` required) / `art21_apur_wrong_event_type` (`body.event_type === "unbinding"`) / `art21_apur_subject_mismatch`. Absence is fine.
- **Resolver-undefined → skip silently.** Every cross-walk is skipped when its caller didn't wire the corresponding `opts.resolveArr` / `opts.resolveAlr` / `opts.resolveAtr` / `opts.resolveApur`. Single-receipt verifiers (`verify.dekimu.com` etc.) keep passing byte-equal to 0.2.x. Matches the optional-resolver discipline of `chainResolver`, `statusListRootKey`, `fetchPolicy`.
- **HARD-invalid only.** Compose's binary `{ok, reason}` result flips `signature_valid` to `false` on cross-walk failure. Spec §4.9's `art19_recipient_set_incomplete` informational warning and §8.3's `art20_cross_border_atr_missing` informational warning need a non-binary compose-result shape and are DEFERRED to Phase 4.

### Tests: 93 → 145 (+52)

New `test/compose.test.ts` covers six suites:

- §G generic dispatch (6 — non-ASR claim_type / body missing / profile undefined / unrelated profile / non-fulfilled event / fulfilled without recipient_notified).
- §ARR art17 ARR (16 — happy ar.erasure.v1 + ar.anonymization.v1 / resolver-undefined / link-missing / link-empty / null + non-object resolutions / wrong claim_type / target_kind + target_commit mismatch / ±14d in / out / boundary inclusive / unparseable iat / ASR subject null / resolver throw).
- §ALR art19 cascade (10 — happy single + multi / resolver-undefined / wrong claim_type + event_type + subject / null / out-of-set profile / short-circuit / throw).
- §ATR art20 (6 — happy / atr_receipt_id absent / resolver-undefined / wrong claim_type / subject mismatch / null resolution).
- §APUR art21 (7 — happy / apur_receipt_id absent / resolver-undefined / wrong claim_type + event_type + subject / null resolution).
- §INT pipeline integration (7 — through `asrFamily.verifyReceipt`: art17 happy + missing arr_receipt_id + wrong claim_type ARR / art19 short-circuit / compose_threw catch / no-resolvers byte-equal / fixture-shape sanity).

`round-trip.test.ts` §2's art17 case updated to include `arr_receipt_id` (the previously-passing missing-link case is now correctly HARD-invalid). `test/mint-v2-extra.test.ts` (formerly `asr-issuer-kit/test/mint-v2-extra.test.ts`, before the issuer-kit merged into this package's `./issue` subpath) P5 (art17 missing arr_receipt_id) was advisory-only pre-§G; updated to expect `signature_valid: false` + `reason: "art17_arr_link_missing"` to match the new HARD-invalid semantics.

### Dependencies

- `@dekimuhq/anchors-envelope` `^0.7.0` → `^0.9.0` — required by the new `ComposeCallback` / `ComposeInput.envelope.iat` / `FamilyVerifyOptions.resolveArr|Alr|Atr|Apur` surface. Pre-0.9.0 envelope releases do NOT carry these and would crash `composeAsr` at runtime if loaded.

### Migration

Existing callers without cross-family resolvers wired keep working byte-equal — every cross-walk is skipped silently when its resolver is undefined. To enable Art. 17 / Art. 19 / Art. 20 / Art. 21 cross-checks, supply the matching `resolveArr` / `resolveAlr` / `resolveAtr` / `resolveApur` callback on `asrFamily.verifyReceipt({ ... })`. Each takes a receipt id and returns the resolved envelope or `null`.

regression check: `grep -n "composeAsr\|art17_arr\|art19_alr\|art20_atr\|art21_apur" anchors/asr/asr-verifier/src/compose.ts anchors/asr/asr-verifier/test/compose.test.ts` reports ≥40 hits.

## 0.2.0 — 2026-05-19

### Added — Phase 3 Steps 1-7 (defineFamily() A.2-full plan)

- `asrFamily` — frozen `FamilyManifest<AsrBody>` built via `@dekimuhq/anchors-envelope`'s
  `defineFamily()` factory. ASR is the first family minted **factory-from-day-1**
  (no hand-rolled `envelope-v2.ts` to collapse). Manifest carries:
  - chip 12 + status_list_slot 6 + claim_type `ar.subject_rights.v1`.
  - `profileIds` covering the six v1 profile slots: `subject_rights.art15.access`,
    `subject_rights.art16.rectification`, `subject_rights.art17.erasure_request`,
    `subject_rights.art18.restriction`, `subject_rights.art20.portability`,
    `subject_rights.art21.objection`.
  - Per-event `subject_presence_check` (9 event types under 6 profiles) with
    reasons pre-mapped to envelope-level codes `subject_missing` /
    `subject_invalid_form` (D10-ASR-5).
  - All six v1 profile validators (`art15Profile`, `art16Profile`, `art17Profile`,
    `art18Profile`, `art20Profile`, `art21Profile`) wired in by reference from
    `@dekimuhq/asr-profiles`.
  - `compose` deliberately omitted at v0.2.0 — cross-family composition
    (ARR `arr_receipt_id` stale-link / subject-parity / claim_type pinning,
    Art. 19 ALR cascade, Art. 20 ATR pair, Art. 21 APuR back-ref) deferred to
    Phase 3 §G compose.
- `asrBodyValidator` (`src/body-validator.ts`) — pass-through `BodyValidator<AsrBody>`
  adapter (mirrors `anrBodyValidator`). Structural body validation continues
  to live alongside the 6 profile validators; the manifest's validator is
  intentionally permissive at the envelope level.

### Dependencies

- `@dekimuhq/anchors-envelope` pinned at `^0.7.0` (consumes `defineFamily()`
  factory Phase 1 surface — verify pipeline + Ed25519 helpers + continuity).
- Added runtime dep on `@dekimuhq/asr-profiles ^0.2.0` so the manifest can
  wire the 6 v1 profile validators by reference. Mirrors the ANR
  verifier↔profiles workspace cycle pattern.

### Tests

- 93 tests across `body-schema`, `subject-presence`, `family`, and integration
  surfaces. Below the ≥99 per-package publish floor for asr-issuer-kit only
  (since merged into `@dekimuhq/asr`'s `./issue` subpath);
  asr-verifier clears the floor. Family combined total at Phase 3 exit:
  93 (verifier) + 3 (issuer-kit) + 117 (profiles) = 213.

Plan: an internal design record (not published) Phase 3 Steps 1-7.

regression check: grep -n 'asrFamily' asr/asr-verifier/src/family.ts

## 0.1.0 — 2026-05-19

- Initial skeleton.
