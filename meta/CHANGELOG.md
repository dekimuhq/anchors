## 0.12.3

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.
- Updated dependencies
  - @dekimuhq/anchors-envelope@0.26.2
  - @dekimuhq/acr-profiles@0.7.3
  - @dekimuhq/alr-profiles@0.5.3
  - @dekimuhq/anr-profiles@0.7.3
  - @dekimuhq/abr-profiles@0.6.3
  - @dekimuhq/asr-profiles@0.6.3
  - @dekimuhq/air-profiles@0.7.3
  - @dekimuhq/arr-profiles@0.9.3
  - @dekimuhq/atokr-profiles@0.3.3
  - @dekimuhq/adr-profiles@0.4.2
  - @dekimuhq/aar-profiles@0.4.3
  - @dekimuhq/atr-profiles@0.3.3
  - @dekimuhq/apur-profiles@0.3.3
  - @dekimuhq/aer-profiles@0.3.3

## 0.12.2

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [28c64ff]
  - @dekimuhq/aar@0.4.1
  - @dekimuhq/aar-profiles@0.4.1
  - @dekimuhq/abr@0.6.1
  - @dekimuhq/abr-profiles@0.6.1
  - @dekimuhq/acr@0.7.1
  - @dekimuhq/acr-profiles@0.7.1
  - @dekimuhq/aer@0.3.1
  - @dekimuhq/aer-profiles@0.3.1
  - @dekimuhq/air@0.7.1
  - @dekimuhq/air-profiles@0.7.1
  - @dekimuhq/alr@0.5.1
  - @dekimuhq/alr-profiles@0.5.1
  - @dekimuhq/anr@0.7.1
  - @dekimuhq/anr-profiles@0.7.1
  - @dekimuhq/apr@0.7.2
  - @dekimuhq/apur@0.3.1
  - @dekimuhq/apur-profiles@0.3.1
  - @dekimuhq/arr@0.9.1
  - @dekimuhq/arr-profiles@0.9.1
  - @dekimuhq/asr@0.6.1
  - @dekimuhq/asr-profiles@0.6.1
  - @dekimuhq/atokr@0.3.1
  - @dekimuhq/atokr-profiles@0.3.1
  - @dekimuhq/atr@0.3.1
  - @dekimuhq/atr-profiles@0.3.1

## 0.12.1

### Patch Changes

- Updated dependencies [83ef364]
- Updated dependencies [0b54548]
- Updated dependencies [d700da7]
- Updated dependencies [82541e7]
  - @dekimuhq/adr-profiles@0.4.0
  - @dekimuhq/adr@0.4.0
  - @dekimuhq/anchors-envelope@0.26.1

## 0.11.5

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
  - @dekimuhq/aar-issuer-kit@0.3.3
  - @dekimuhq/aar-profiles@0.3.3
  - @dekimuhq/aar-verifier@0.3.3
  - @dekimuhq/abr-issuer-kit@0.5.1
  - @dekimuhq/abr-profiles@0.5.1
  - @dekimuhq/abr-verifier@0.5.1
  - @dekimuhq/acr-issuer-kit@0.6.5
  - @dekimuhq/acr-profiles@0.6.5
  - @dekimuhq/acr-verifier@0.6.5
  - @dekimuhq/adr-issuer-kit@0.2.4
  - @dekimuhq/adr-profiles@0.2.4
  - @dekimuhq/adr-verifier@0.2.4
  - @dekimuhq/aer-issuer-kit@0.2.4
  - @dekimuhq/aer-profiles@0.2.4
  - @dekimuhq/aer-verifier@0.2.4
  - @dekimuhq/air-issuer-kit@0.6.1
  - @dekimuhq/air-profiles@0.6.1
  - @dekimuhq/air-verifier@0.6.1
  - @dekimuhq/alr-issuer-kit@0.4.1
  - @dekimuhq/alr-profiles@0.4.1
  - @dekimuhq/alr-verifier@0.4.1
  - @dekimuhq/anchors-envelope@0.18.1
  - @dekimuhq/anr-issuer-kit@0.6.1
  - @dekimuhq/anr-profiles@0.6.1
  - @dekimuhq/anr-verifier@0.6.1
  - @dekimuhq/apr-issuer-kit@0.6.5
  - @dekimuhq/apr-verifier@0.6.5
  - @dekimuhq/apur-issuer-kit@0.2.4
  - @dekimuhq/apur-profiles@0.2.4
  - @dekimuhq/apur-verifier@0.2.4
  - @dekimuhq/arr-issuer-kit@0.8.1
  - @dekimuhq/arr-profiles@0.8.1
  - @dekimuhq/arr-verifier@0.8.1
  - @dekimuhq/asr-issuer-kit@0.5.4
  - @dekimuhq/asr-profiles@0.5.4
  - @dekimuhq/asr-verifier@0.5.4
  - @dekimuhq/atokr-issuer-kit@0.2.4
  - @dekimuhq/atokr-profiles@0.2.4
  - @dekimuhq/atokr-verifier@0.2.4
  - @dekimuhq/atr-issuer-kit@0.2.4
  - @dekimuhq/atr-profiles@0.2.4
  - @dekimuhq/atr-verifier@0.2.4

## 0.11.4

### Patch Changes

- Updated dependencies [1f05cf4]
- Updated dependencies [7c4329d]
- Updated dependencies [583818d]
- Updated dependencies [1068f13]
  - @dekimuhq/abr-issuer-kit@0.5.0
  - @dekimuhq/air-issuer-kit@0.6.0
  - @dekimuhq/alr-issuer-kit@0.4.0
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/anr-issuer-kit@0.6.0
  - @dekimuhq/arr-issuer-kit@0.8.0
  - @dekimuhq/aar-issuer-kit@0.3.2
  - @dekimuhq/aar-profiles@0.3.2
  - @dekimuhq/aar-verifier@0.3.2
  - @dekimuhq/abr-profiles@0.5.0
  - @dekimuhq/abr-verifier@0.5.0
  - @dekimuhq/acr-issuer-kit@0.6.4
  - @dekimuhq/acr-verifier@0.6.4
  - @dekimuhq/adr-issuer-kit@0.2.3
  - @dekimuhq/adr-profiles@0.2.3
  - @dekimuhq/adr-verifier@0.2.3
  - @dekimuhq/aer-issuer-kit@0.2.3
  - @dekimuhq/aer-profiles@0.2.3
  - @dekimuhq/aer-verifier@0.2.3
  - @dekimuhq/air-profiles@0.6.0
  - @dekimuhq/air-verifier@0.6.0
  - @dekimuhq/alr-profiles@0.4.0
  - @dekimuhq/alr-verifier@0.4.0
  - @dekimuhq/anr-profiles@0.6.0
  - @dekimuhq/anr-verifier@0.6.0
  - @dekimuhq/apr-issuer-kit@0.6.4
  - @dekimuhq/apr-verifier@0.6.4
  - @dekimuhq/apur-issuer-kit@0.2.3
  - @dekimuhq/apur-profiles@0.2.3
  - @dekimuhq/apur-verifier@0.2.3
  - @dekimuhq/arr-verifier@0.8.0
  - @dekimuhq/asr-issuer-kit@0.5.3
  - @dekimuhq/asr-profiles@0.5.3
  - @dekimuhq/asr-verifier@0.5.3
  - @dekimuhq/atokr-issuer-kit@0.2.3
  - @dekimuhq/atokr-profiles@0.2.3
  - @dekimuhq/atokr-verifier@0.2.3
  - @dekimuhq/atr-issuer-kit@0.2.3
  - @dekimuhq/atr-profiles@0.2.3
  - @dekimuhq/atr-verifier@0.2.3
  - @dekimuhq/arr-profiles@0.8.0

## 0.11.3

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
- Updated dependencies [b3784c0]
- Updated dependencies [b3784c0]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/arr-issuer-kit@0.7.1
  - @dekimuhq/atr-issuer-kit@0.2.2
  - @dekimuhq/aar-issuer-kit@0.3.1
  - @dekimuhq/aar-profiles@0.3.1
  - @dekimuhq/aar-verifier@0.3.1
  - @dekimuhq/abr-issuer-kit@0.4.3
  - @dekimuhq/abr-profiles@0.4.3
  - @dekimuhq/abr-verifier@0.4.3
  - @dekimuhq/acr-issuer-kit@0.6.3
  - @dekimuhq/acr-verifier@0.6.3
  - @dekimuhq/adr-issuer-kit@0.2.2
  - @dekimuhq/adr-profiles@0.2.2
  - @dekimuhq/adr-verifier@0.2.2
  - @dekimuhq/aer-issuer-kit@0.2.2
  - @dekimuhq/aer-profiles@0.2.2
  - @dekimuhq/aer-verifier@0.2.2
  - @dekimuhq/air-issuer-kit@0.5.3
  - @dekimuhq/air-profiles@0.5.3
  - @dekimuhq/air-verifier@0.5.3
  - @dekimuhq/alr-issuer-kit@0.3.5
  - @dekimuhq/alr-profiles@0.3.5
  - @dekimuhq/alr-verifier@0.3.5
  - @dekimuhq/anr-issuer-kit@0.5.2
  - @dekimuhq/anr-profiles@0.5.2
  - @dekimuhq/anr-verifier@0.5.2
  - @dekimuhq/apr-issuer-kit@0.6.3
  - @dekimuhq/apr-verifier@0.6.3
  - @dekimuhq/apur-issuer-kit@0.2.2
  - @dekimuhq/apur-profiles@0.2.2
  - @dekimuhq/apur-verifier@0.2.2
  - @dekimuhq/arr-verifier@0.7.1
  - @dekimuhq/asr-issuer-kit@0.5.2
  - @dekimuhq/asr-profiles@0.5.2
  - @dekimuhq/asr-verifier@0.5.2
  - @dekimuhq/atokr-issuer-kit@0.2.2
  - @dekimuhq/atokr-profiles@0.2.2
  - @dekimuhq/atokr-verifier@0.2.2
  - @dekimuhq/atr-profiles@0.2.2
  - @dekimuhq/atr-verifier@0.2.2

## 0.11.2

### Patch Changes

- Updated dependencies
  - @dekimuhq/abr-issuer-kit@0.4.2
  - @dekimuhq/abr-profiles@0.4.2
  - @dekimuhq/abr-verifier@0.4.2
  - @dekimuhq/acr-issuer-kit@0.6.2
  - @dekimuhq/acr-verifier@0.6.2
  - @dekimuhq/adr-issuer-kit@0.2.1
  - @dekimuhq/adr-profiles@0.2.1
  - @dekimuhq/adr-verifier@0.2.1
  - @dekimuhq/aer-issuer-kit@0.2.1
  - @dekimuhq/aer-profiles@0.2.1
  - @dekimuhq/aer-verifier@0.2.1
  - @dekimuhq/air-issuer-kit@0.5.2
  - @dekimuhq/air-profiles@0.5.2
  - @dekimuhq/alr-issuer-kit@0.3.4
  - @dekimuhq/alr-profiles@0.3.4
  - @dekimuhq/anr-issuer-kit@0.5.1
  - @dekimuhq/anr-profiles@0.5.1
  - @dekimuhq/anr-verifier@0.5.1
  - @dekimuhq/apr-issuer-kit@0.6.2
  - @dekimuhq/apr-verifier@0.6.2
  - @dekimuhq/apur-issuer-kit@0.2.1
  - @dekimuhq/apur-profiles@0.2.1
  - @dekimuhq/apur-verifier@0.2.1
  - @dekimuhq/asr-issuer-kit@0.5.1
  - @dekimuhq/asr-profiles@0.5.1
  - @dekimuhq/asr-verifier@0.5.1
  - @dekimuhq/atokr-issuer-kit@0.2.1
  - @dekimuhq/atokr-profiles@0.2.1
  - @dekimuhq/atokr-verifier@0.2.1
  - @dekimuhq/atr-issuer-kit@0.2.1
  - @dekimuhq/atr-profiles@0.2.1
  - @dekimuhq/atr-verifier@0.2.1
  - @dekimuhq/alr-verifier@0.3.4

## 0.11.1

### Patch Changes

- Updated dependencies [db75e89]
- Updated dependencies [db75e89]
- Updated dependencies [52543f5]
- Updated dependencies [db75e89]
- Updated dependencies [db75e89]
- Updated dependencies [db75e89]
  - @dekimuhq/aar-verifier@0.3.0
  - @dekimuhq/air-verifier@0.5.1
  - @dekimuhq/alr-verifier@0.3.3
  - @dekimuhq/arr-verifier@0.7.0
  - @dekimuhq/arr-issuer-kit@0.7.0
  - @dekimuhq/arr-profiles@0.7.0
  - @dekimuhq/anchors-envelope@0.16.0
  - @dekimuhq/aar-issuer-kit@0.3.0
  - @dekimuhq/aar-profiles@0.3.0

## 0.11.0

### Minor Changes

- c2f423e: feat: cross-sibling QTS upgrade — all 14 families carry qts_attestation_hash

### Patch Changes

- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
- Updated dependencies [c2f423e]
  - @dekimuhq/aar-verifier@0.2.0
  - @dekimuhq/aar-issuer-kit@0.2.0
  - @dekimuhq/abr-verifier@0.4.0
  - @dekimuhq/abr-issuer-kit@0.4.0
  - @dekimuhq/acr-verifier@0.6.0
  - @dekimuhq/acr-issuer-kit@0.6.0
  - @dekimuhq/adr-verifier@0.2.0
  - @dekimuhq/adr-issuer-kit@0.2.0
  - @dekimuhq/aer-verifier@0.2.0
  - @dekimuhq/aer-issuer-kit@0.2.0
  - @dekimuhq/air-verifier@0.5.0
  - @dekimuhq/air-issuer-kit@0.5.0
  - @dekimuhq/alr-verifier@0.3.0
  - @dekimuhq/alr-issuer-kit@0.3.0
  - @dekimuhq/anr-verifier@0.5.0
  - @dekimuhq/anr-issuer-kit@0.5.0
  - @dekimuhq/apr-verifier@0.6.0
  - @dekimuhq/apr-issuer-kit@0.6.0
  - @dekimuhq/apur-verifier@0.2.0
  - @dekimuhq/apur-issuer-kit@0.2.0
  - @dekimuhq/arr-verifier@0.6.0
  - @dekimuhq/arr-issuer-kit@0.6.0
  - @dekimuhq/asr-verifier@0.5.0
  - @dekimuhq/atokr-verifier@0.2.0
  - @dekimuhq/atokr-issuer-kit@0.2.0
  - @dekimuhq/atr-verifier@0.2.0
  - @dekimuhq/atr-issuer-kit@0.2.0
  - @dekimuhq/aar-profiles@0.2.0
  - @dekimuhq/abr-profiles@0.4.0
  - @dekimuhq/acr-profiles@0.6.0
  - @dekimuhq/adr-profiles@0.2.0
  - @dekimuhq/aer-profiles@0.2.0
  - @dekimuhq/air-profiles@0.5.0
  - @dekimuhq/apur-profiles@0.2.0
  - @dekimuhq/arr-profiles@0.6.0
  - @dekimuhq/asr-issuer-kit@0.5.0
  - @dekimuhq/atokr-profiles@0.2.0
  - @dekimuhq/atr-profiles@0.2.0

## 0.9.0 — 2026-05-21 — ATokR triple published (chip 14)

### Added

ATokR (Anchored Tokenization Receipts) triple published to GitHub Packages:

- `@dekimuhq/atokr-verifier@0.1.0` — chain walker, body validator, compose, envelope-v2 verify.
- `@dekimuhq/atokr-issuer-kit@0.1.0` — mint functions for 4 event types.
- `@dekimuhq/atokr-profiles@0.1.0` — 5 profile validators (GDPR Art. 32/Art. 4(5), PCI DSS v4, EUDI wallet ARF, sector health).

Dep ranges in `meta/package.json` already wired at `^0.1.0` during workspace integration (`709c4f1`). Subpath exports `./atokr` + `./atokrProfiles` and barrel re-exports already in place.

### Bump

- 0.8.8 → 0.9.0 (minor — new family member exports, no breaking change to existing surfaces).

regression check: `grep -nE '"@dekimuhq/atokr-(verifier|issuer-kit|profiles)"' anchors/meta/package.json` must report `^0.1.0` for all three.

## 0.8.8 — 2026-05-20 — ANR Phase 4D floor lift (anr-verifier 0.4.0 + ANR-triple alignment)

### Changed (dep-range only — no surface changes)

Floor lift after ANR Phase 4D ships `composeAnr` (D-anchors-8 (internal design record, not published)) and the ANR-triple dep-range alignment patches anr-issuer-kit + anr-profiles. ANR was holding at envelope `^0.9.0` per the 2026-05-19 four-non-chain-walking-families decision; Phase 4D requires `opts.resolveReceiptById` from envelope `^0.11.0` for the `base_unresolvable` chain-walk warning, so ANR now joins ABR/AIR/ASR at the `^0.11.0` floor.

Range bumps in `meta/package.json`:

- `@dekimuhq/anr-verifier` `^0.3.0` → `^0.4.0` (compose surface — `lang_jurisdiction_mismatch` single-receipt + `base_unresolvable` chain-walk).
- `@dekimuhq/anr-issuer-kit` `^0.2.2` → `^0.2.3` (dep-range alignment to envelope `^0.11.0` + anr-verifier `^0.4.0` + apr-verifier `^0.5.0`).
- `@dekimuhq/anr-profiles` `^0.2.2` → `^0.2.3` (dep-range alignment to envelope `^0.11.0`).

`@dekimuhq/anchors-envelope` already at `^0.11.0` from 0.8.6 (AIR Phase 4B-2); no further bump needed. Other families unchanged. APR/ACR/ARR/ALR still hold at envelope `^0.9.0` per the 2026-05-19 decision — those four have no compose surface to wire, lift gated on a real consumer-side need. `@dekimuhq/anchors` re-export surface is unaffected.

regression check: `grep -nE '"@dekimuhq/anr-(verifier|issuer-kit|profiles)"' anchors/meta/package.json` must report `^0.4.0`, `^0.2.3`, `^0.2.3` respectively.

## 0.8.7 — 2026-05-20 — ABR Phase 4C floor lift (abr-verifier 0.3.0 + ABR-triple alignment)

### Changed (dep-range only — no surface changes)

Floor lift after ABR Phase 4C factory migration + composeAbr warnings shipped
abr-verifier `0.3.0` (commit `54a920f`) and the ABR-triple dep-range alignment
patched abr-issuer-kit + abr-profiles (commit `06dbcd2`). Lifts the three ABR-side
floors so consumers installing `@dekimuhq/anchors` get the Phase 4C compose surface
without nested envelope copies. Mirrors the AIR Phase 4B-2 floor lift (0.8.6).

Range bumps in `meta/package.json`:

- `@dekimuhq/abr-verifier` `^0.2.0` → `^0.3.0` (factory migration + composeAbr
  `clock_skew_warning` + `notification_overdue` warnings).
- `@dekimuhq/abr-issuer-kit` `^0.2.2` → `^0.2.3` (dep-range alignment to envelope
  `^0.11.0` + abr-verifier `^0.3.0` + apr-verifier `^0.5.0`).
- `@dekimuhq/abr-profiles` `^0.1.2` → `^0.1.3` (dep-range alignment to envelope
  `^0.11.0` + abr-verifier `^0.3.0`).

`@dekimuhq/anchors-envelope` already at `^0.11.0` from 0.8.6 (AIR Phase 4B-2);
no further bump needed. Other families (APR/ACR/ARR/ALR/ANR/ASR) unchanged.
ANR still at envelope `^0.9.0` per the 2026-05-19 hold; will lift when Phase 4D
wires compose. `@dekimuhq/anchors` re-export surface is unaffected.

regression check: `grep -nE '"@dekimuhq/abr-(verifier|issuer-kit|profiles)"' anchors/meta/package.json` must report `^0.3.0`, `^0.2.3`, `^0.1.3` respectively.

## 0.8.6 — 2026-05-20 — AIR Phase 4B-2 floor lift (envelope 0.11.0 + air-verifier 0.4.0)

### Changed (dep-range only — no surface changes)

Floor lift after AIR Phase 4B-2 chain-walk warnings shipped envelope `0.11.0` +
air-verifier `0.4.0` (commits `441ba5f` + `e9ca0c1`). Lifts the four AIR-side
floors so consumers installing `@dekimuhq/anchors` get the Phase 4B-2 chain-walk
surface without nested envelope copies.

Range bumps in `meta/package.json`:

- `@dekimuhq/anchors-envelope` `^0.10.0` → `^0.11.0` (chain-walk `resolveReceiptById` resolver).
- `@dekimuhq/air-verifier` `^0.2.0` → `^0.4.0` (compose surfaces 6 chain-walk warnings; new `voluntary_high_risk_no_consultation` evaluator).
- `@dekimuhq/air-issuer-kit` `^0.2.2` → `^0.2.3` (dep-range alignment to envelope `^0.11.0` + air-verifier `^0.4.0`).
- `@dekimuhq/air-profiles` `^0.2.1` → `^0.2.2` (dep-range alignment to envelope `^0.11.0`).

Other families (APR/ACR/ARR/ALR/ANR/ABR/ASR) are unchanged — per the 2026-05-19
late-evening hold decision, the four non-chain-walking families stay at envelope
`^0.9.0`; ABR + ANR will reach envelope `^0.11.0` only when Phase 4C / 4D wire
compose. `@dekimuhq/anchors` re-export surface is unaffected.

regression check: `grep -nE '"@dekimuhq/(anchors-envelope|air-(verifier|issuer-kit|profiles))"' anchors/meta/package.json` must report `^0.11.0`, `^0.4.0`, `^0.2.3`, `^0.2.2` respectively.

## 0.8.5 — 2026-05-20 — cross-family verifier dep-range alignment

### Changed (dep-range only — no surface changes)

Closes the cross-family verifier peer-range drift flagged as "out of scope" in
0.8.4. After that round lifted all 4 family verifiers to envelope `^0.9.0`, two
verifiers still declared stale APR/ACR ranges (`acr-verifier` → `apr-verifier
^0.4.3`; `arr-verifier` → `apr-verifier ^0.4.3` + `acr-verifier ^0.4.0`) while
shipped floors were already `0.5.x`. This bumps both verifiers (PATCH each)
and updates the meta floors. Pure dep-range refresh — zero source files
touched in any verifier. `@dekimuhq/anchors` re-export surface is unaffected.

Range bumps in `meta/package.json` (each corresponds to a verifier PATCH bump
that only widened a cross-family peer floor):

- `@dekimuhq/acr-verifier` `^0.5.1` → `^0.5.2` (apr-verifier `^0.4.3` → `^0.5.1`).
- `@dekimuhq/arr-verifier` `^0.5.1` → `^0.5.2` (apr-verifier `^0.4.3` → `^0.5.1`; acr-verifier `^0.4.0` → `^0.5.1`).

APR verifier is a leaf in the cross-family graph (depends on no sibling
verifier) and is unchanged. ALR/ANR/ABR/ASR/AIR verifiers do not declare
cross-family verifier deps and are unchanged.

regression check: `grep -nE '"@dekimuhq/(acr|arr)-verifier"' anchors/meta/package.json` must report `^0.5.2` for both.

## 0.8.4 — 2026-05-20

### Changed (dep-range only — no surface changes)

Closes the verifier side of the cross-family envelope dep-range alignment by
lifting the 4 family verifiers stuck at envelope `^0.8.0` to `^0.9.0`. After
the issuer-kit + profiles sweeps landed in `710c338` and `86ab55b` (envelope
`^0.9.0` across non-ASR families) and ASR went to envelope `^0.10.0` in Step 11,
the verifiers were the last drift. Pure dep-range refresh — zero source files
touched in any verifier. `@dekimuhq/anchors` re-export surface is unaffected.

Range bumps in `meta/package.json` (each corresponds to a verifier PATCH bump
that only widened its envelope floor):

- `@dekimuhq/apr-verifier` `^0.5.0` → `^0.5.1` (envelope `^0.8.0` → `^0.9.0`).
- `@dekimuhq/acr-verifier` `^0.5.0` → `^0.5.1` (envelope `^0.8.0` → `^0.9.0`).
- `@dekimuhq/arr-verifier` `^0.5.0` → `^0.5.1` (envelope `^0.8.0` → `^0.9.0`).
- `@dekimuhq/alr-verifier` `^0.2.0` → `^0.2.1` (envelope `^0.8.0` → `^0.9.0`).

Out of scope: cross-family verifier deps still drift —
`acr-verifier` declares `apr-verifier ^0.4.3` and `arr-verifier` declares
`apr-verifier ^0.4.3` + `acr-verifier ^0.4.0` while shipped floors are `0.5.x`.
That alignment is a separate sweep with different semantic intent (cross-family
peer ranges, not envelope-floor).

regression check: `grep -nE '"@dekimuhq/(apr|acr|arr|alr)-verifier"' anchors/meta/package.json` must report the new floors (`^0.5.1` × 3 + `^0.2.1`).

## 0.8.3 — 2026-05-20

### Changed (dep-range only — no surface changes)

Closes the cross-family envelope dep-range alignment by lifting the ALR
issuer-kit + profiles transitive envelope floors that were stuck at `^0.7.0` /
`^0.5.0`. Each now declares `@dekimuhq/anchors-envelope ^0.9.0`, matching the
non-ASR family floor (ASR triple is on `^0.10.0` post-Phase-4 because it emits
compose warnings; all other family members stay on `^0.9.0`). No meta source
files change — `@dekimuhq/anchors` re-export surface is unaffected.

Range bumps in `meta/package.json`:

- `@dekimuhq/alr-issuer-kit` `^0.2.0` → `^0.2.1` (envelope `^0.7.0` → `^0.9.0`
  inside the kit; also fixes the `alr-verifier ^0.1.1` → `^0.2.0` drift left
  over from the post-publish verifier-range sweep `a7365b0`).
- `@dekimuhq/alr-profiles` `^0.1.0` → `^0.1.1` (envelope `^0.5.0` → `^0.9.0`).

Out of scope: `alr-verifier`'s own envelope range `^0.8.0` is still stale
relative to the shipped envelope `0.10.0` — that lift requires its own
`alr-verifier` minor bump and is a separate sweep.

regression check: `grep -nE "@dekimuhq/alr-(issuer-kit|profiles)" anchors/meta/package.json` must report the new floors.

## 0.8.2 — 2026-05-20

### Changed (dep-range only — no surface changes)

Phase 4 Step 11 follow-on to the envelope 0.10.0 + asr-verifier 0.4.0
publish round (Phase 4 compose-warnings channel). Range bumps in
`meta/package.json`:

- `@dekimuhq/anchors-envelope` `^0.9.0` → `^0.10.0` — picks up
  `ComposeResult.warnings` widening + `FamilyVerifyOptions.findDisclosedAlrsForSubject`
  resolver. Family-wide floor; every verifier/issuer-kit/profiles range
  refresh in this row hangs off this lift.
- `@dekimuhq/asr-verifier` `^0.3.0` → `^0.4.0` — picks up the two new
  informational warnings (`art20_cross_border_atr_missing`,
  `art19_recipient_set_incomplete`).
- `@dekimuhq/asr-issuer-kit` `^0.2.2` → `^0.2.3` — transitive envelope +
  asr-verifier range refresh on the kit's `dependencies` block.
- `@dekimuhq/asr-profiles` `^0.2.1` → `^0.2.2` — transitive envelope
  range refresh.

No meta source files change — `@dekimuhq/anchors` re-export surface is
unaffected. ASR triple is the only family that emits compose-warnings
today; other family verifiers stay on `^0.9.0` envelope ranges until they
opt into the warnings channel.

regression check: `grep -nE "anchors-envelope|asr-(verifier|issuer-kit|profiles)" anchors/meta/package.json` must report the new floors.

## 0.8.1 — 2026-05-20

### Changed (dep-range only — no surface changes)

Follow-on to the 0.8.0 dep-floor sweep: lift the ABR / ANR / AIR issuer-kit +
profiles transitive envelope floors that were previously stuck at `^0.6.2` /
`^0.7.0` / `^0.7.1`. Each of the 6 packages now declares
`@dekimuhq/anchors-envelope ^0.9.0`, matching the family verifiers and the ASR
triple lifted in Step 10. No meta source files change — `@dekimuhq/anchors`
re-export surface is unaffected.

Range bumps in `meta/package.json`:

- `@dekimuhq/abr-issuer-kit` `^0.2.1` → `^0.2.2`.
- `@dekimuhq/abr-profiles` `^0.1.1` → `^0.1.2`.
- `@dekimuhq/anr-issuer-kit` `^0.2.1` → `^0.2.2`.
- `@dekimuhq/anr-profiles` `^0.2.1` → `^0.2.2`.
- `@dekimuhq/air-issuer-kit` `^0.2.1` → `^0.2.2`.
- `@dekimuhq/air-profiles` `^0.2.0` → `^0.2.1`.

These 6 packages each emit a corresponding `*.*.X` PATCH bump in their own
CHANGELOG documenting the envelope range bump only — pure transitive floor
refresh, no public-API surface delta.

regression check: `grep -nE "@dekimuhq/(abr|anr|air)-(issuer-kit|profiles)" anchors/meta/package.json` must report the new floors.

## 0.8.0 — AIR namespace + subpath

### Added

- `./air` + `./airProfiles` subpath exports re-exporting
  `@dekimuhq/air-verifier` + `@dekimuhq/air-issuer-kit` + `@dekimuhq/air-profiles`.
- `air` + `airProfiles` namespace re-exports at the root.
- AIR triple added to deps (`air-verifier@^0.1.4`, `air-issuer-kit@^0.2.1`,
  `air-profiles@^0.2.0`).
- 2 new tests (`anchors/air re-exports`, `anchors/airProfiles re-exports`)
  plus expanded "all fifteen family namespaces" + `mintAirV2` +
  `validateImpactArt35_3_a` assertions. reexport.test.ts 20 → 22.

### Changed

- Description + keywords list adds AIR alongside ASR.
- ASR triple dep ranges lifted from `^0.1.0` floor to current shipped versions
  per ASR Phase 3 Step 10 propagation: `asr-verifier@^0.3.0` (§G compose
  surface), `asr-issuer-kit@^0.2.2` (envelope `^0.9.0` + asr-verifier `^0.3.0`),
  `asr-profiles@^0.2.1` (envelope `^0.9.0`). No surface change here — older
  consumers of `@dekimuhq/anchors/asr*` resolved to local 0.x via workspace
  hoisting; ranges now match what `npm install @dekimuhq/anchors` will pull
  from GitHub Packages.
- Family-wide dep-floor sweep before 0.8.0 publish — every non-ASR family
  range lifted to its current shipped floor (mirrors Step 10 across all
  members). No surface change in this meta package; consumers installing
  `@dekimuhq/anchors` from GitHub Packages now resolve to the shipped
  verifier/issuer-kit/profiles versions instead of stale `^0.1.x`/`^0.2.x`
  floors. Specifically:
  - `@dekimuhq/anchors-envelope` `^0.6.0` → `^0.9.0` (matches §G compose
    surface used transitively across the family).
  - APR: `apr-verifier@^0.4.0` → `^0.5.0`, `apr-issuer-kit@^0.2.0` → `^0.2.2`.
  - ACR: `acr-verifier@^0.4.0` → `^0.5.0`, `acr-issuer-kit@^0.3.0` → `^0.3.2`,
    `acr-profiles@^0.3.0` → `^0.3.1`.
  - ARR: `arr-verifier@^0.4.0` → `^0.5.0`, `arr-issuer-kit@^0.4.0` → `^0.5.0`,
    `arr-profiles@^0.2.0` → `^0.2.1`.
  - ALR: `alr-verifier@^0.1.0` → `^0.2.0`, `alr-issuer-kit@^0.1.0` → `^0.2.0`
    (alr-profiles already at `^0.1.0` shipped floor).
  - ANR: `anr-verifier@^0.1.0` → `^0.3.0`, `anr-issuer-kit@^0.1.0` → `^0.2.1`,
    `anr-profiles@^0.2.0` → `^0.2.1`.
  - ABR: `abr-verifier@^0.1.2` → `^0.2.0`, `abr-issuer-kit@^0.2.0` → `^0.2.1`
    (abr-profiles already at `^0.1.1` shipped floor).
  - AIR: `air-verifier@^0.1.4` → `^0.2.0` (air-issuer-kit + air-profiles
    already at shipped floor).

### Bump

- 0.7.0 → 0.8.0 (minor — new exports, no breaking change to existing surfaces).

## 0.6.0 — ABR namespace + subpath

### Added

- `./abr` + `./abrProfiles` subpath exports re-exporting
  `@dekimuhq/abr-verifier` + `@dekimuhq/abr-issuer-kit` + `@dekimuhq/abr-profiles`.
- `abr` + `abrProfiles` namespace re-exports at the root.
- ABR triple added to deps (`abr-verifier@^0.1.2`, `abr-issuer-kit@^0.2.0`,
  `abr-profiles@^0.1.1`).
- 2 new tests (`anchors/abr re-exports`, `anchors/abrProfiles re-exports`)
  plus expanded "all eleven family namespaces" + `mintDetected` +
  `validateBreachGdprArt33` assertions. reexport.test.ts 16 → 18.

### Changed

- Description + keywords list adds ABR alongside ANR.

### Bump

- 0.5.0 → 0.6.0 (minor — new exports, no breaking change to existing surfaces).

## 0.5.0 — ANR namespace + subpath

### Added

- `./anr` + `./anrProfiles` subpath exports re-exporting
  `@dekimuhq/anr-verifier` + `@dekimuhq/anr-issuer-kit` + `@dekimuhq/anr-profiles`.
- `anr` + `anrProfiles` namespace re-exports at the root.
- ANR triple added to deps (`anr-verifier@^0.1.0`, `anr-issuer-kit@^0.1.0`,
  `anr-profiles@^0.2.0`).
- 2 new tests (`anchors/anr re-exports`, `anchors/anrProfiles re-exports`)
  plus expanded "all nine family namespaces" + mintPresented + validateArt13
  assertions. reexport.test.ts 14 → 16.

### Changed

- Description + keywords list adds ANR alongside ALR.
- Envelope dep range `^0.5.0` → `^0.6.0` to match the post-A.3-wave family floor.

### Bump

- 0.4.0 → 0.5.0 (minor — new exports, no breaking change to existing surfaces).

## 0.3.3 — v1.2 envelope amendment surface re-export

### Added

- Meta-package transitively re-exports the v1.2 envelope surface via the existing `export * from "@dekimuhq/anchors-envelope"` barrel: `JSON_LOGIC_ALLOWLIST_V1_2`, `validatePredicate`, `evaluatePredicate`, `checkIatMs`, `checkPredicate`, `Kind`, `Cause`, `JsonLogicAst`, `PredicateReasonCode`.
- Per-member-package dep ranges absorb the patch bumps automatically via `^` semver.

### Changed

- Envelope dep range `^0.3.0` → `^0.4.0` to receive the v1.2 fields on the underlying `@dekimuhq/anchors-envelope`.

# Changelog — `@dekimuhq/anchors` (meta)

Meta-package re-exporting the Anchored Receipts family under namespaced + surgical subpaths. Versioning is independent of the constituent packages; a version bump here usually reflects a new namespace, a new subpath export, or a packaging-hygiene change.

## 0.3.2

### Added

- Re-exports the new `trustedLogs` option from apr/acr/arr verifiers via
  their respective `EnvelopeVerifyOptions` surfaces (cross-issuer interop
  Item 2). Existing caret-pinned dep ranges `^0.4.0` cover the underlying
  0.4.1 verifier bumps — no dep edits required.

## v0.3.1 — acr-profiles dep range bump

- Lifted `@dekimuhq/acr-profiles` dep range `^0.2.0` → `^0.3.0` so consumers of `@dekimuhq/anchors/acrProfiles` resolve to acr-profiles@0.3.0 (with the confirmed ETSI EN 319 421 BTSP policy OID `0.4.0.2023.1.1` for the `esig.accept@qes` mandate). No surface change here.

## v0.3.0 — Phase E subpath exports (undocumented at publish time)

This entry is added retroactively in v0.3.1; v0.3.0 was published as part of Phase E Task 22 without a CHANGELOG entry.

- New subpath exports: `./envelope`, `./tsa`, `./status`, `./profile` — re-export the corresponding modules from `@dekimuhq/anchors-envelope`.
- Cross-package dep ranges lifted from `^0.1.0` floor to current major-minor (`@dekimuhq/anchors-envelope` 0.3.0, the three verifiers 0.4.0, issuer-kits 0.2.0/0.3.0/0.4.0, profiles 0.2.0).

## v0.2.2 — files-field fix

- v0.1.2 (and v0.2.1 for meta) shipped without `CHANGELOG.md`, `quickstart/`, or `docs/` in the npm tarball because the `files` field in package.json only listed `["src","README.md","LICENSE"]`. Mirrors the APR pattern now: verifier/profiles ship `src + README + LICENSE + CHANGELOG`; issuer-kits also ship `quickstart + docs`.
- No code or API changes.

## v0.2.1 — packaging hygiene

- Added `LICENSE` (Apache-2.0).
- Added this `CHANGELOG.md`.
- No code or API changes. Picks up family-package patch bumps to `0.1.1` via the existing `^0.1.0` ranges.

## v0.2.0 — `acrProfiles` subpath added

- New subpath export: `@dekimuhq/anchors/acrProfiles` re-exports `@dekimuhq/acr-profiles`. Adds symmetry with `arrProfiles`.
- Bumped namespace count from 4 to 5; namespace-count test bumped accordingly.
- Dependencies: 8 family packages (added `@dekimuhq/acr-profiles@^0.1.0`).

## v0.1.x — initial private releases

ARR namespace + `arrProfiles` subpath landed during the ARR v1.0 implementation. ACR + APR namespaces were the original two. The historical patch chain pre-dates publish; full surface as of v0.2.0:

- Namespaced re-exports: `apr`, `acr`, `arr`.
- Subpath re-exports: `./apr`, `./acr`, `./acrProfiles`, `./arr`, `./arrProfiles`.

Node ≥22.
