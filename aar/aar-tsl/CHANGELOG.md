# @dekimuhq/aar-tsl

## 0.3.1

### Patch Changes

- 8190d2d: Skip PDF pointers in the LOTL (only machine-readable TSLs are parsed) and isolate per-country parse failures, so one national list can no longer fail the whole snapshot. Before this, `buildTslSnapshot()` threw on the human-readable PDF pointers the LOTL lists beside the XML ones for 11 countries.

## 0.3.0

### Minor Changes

- 996dec7: Snapshot entries now carry what a CA/QC service is listed FOR and since when. `parseTsl` reads the `AdditionalServiceInformation` URIs (`ForeSignatures`, `ForeSeals`, `ForWebSiteAuthentication`) and the `Qualifications` qualifier URIs of each service, and keeps each `ServiceHistoryInstance` with its own status, start time and extensions. New `TslServiceEntry` fields: `additional_service_info`, `qualifiers`, `status_history` (always present, empty when the list has none).

  Why: a relying party that only has "granted CA/QC" cannot tell a website-certificate CA from a signature CA, and cannot ask whether a service was listed, and for what, at the time something was signed. Entry hashes change, so a snapshot built with this version has a different Merkle root from one built before it; a consumer should treat a snapshot whose entries lack the new fields as predating them.

## 0.2.9

### Patch Changes

- Updated dependencies [0d50794]
  - @dekimuhq/anchors-envelope@0.27.0
  - @dekimuhq/aar@0.4.5

## 0.2.8

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.
- Updated dependencies
  - @dekimuhq/anchors-envelope@0.26.2

## 0.2.7

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [28c64ff]
  - @dekimuhq/aar@0.4.1

## 0.2.6

### Patch Changes

- a097caa: Migrate `@dekimuhq/aar-tsl` to built `dist` publishing — the last anchors package still on raw `src/*.ts`. Flips `main`/`types`/`exports` to `dist`, adds `tsconfig.build.json` + the shared `build`/`prepack` scripts, and `files: ["dist", …]`. The original exclusion (a `fast-xml-parser` declaration-emit gap) no longer applies: `fast-xml-parser@4.5.6` ships `typings`, so `tsc -p tsconfig.build.json` emits clean (51/51 tests, 0 raw `.ts` specifiers in the emitted `.d.ts`). Aligns the `aar-verifier`/`anchors-envelope` dep ranges with the dist-published versions.

## 0.2.5

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
  - @dekimuhq/aar-verifier@0.3.2

## 0.2.4

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0
  - @dekimuhq/aar-verifier@0.3.1

## 0.2.3

### Patch Changes

- Updated dependencies [db75e89]
- Updated dependencies [db75e89]
  - @dekimuhq/aar-verifier@0.3.0
  - @dekimuhq/anchors-envelope@0.16.0

## 0.2.2

### Patch Changes

- Updated dependencies
  - @dekimuhq/anchors-envelope@0.15.0

## 0.2.1

### Patch Changes

- Updated dependencies [c2f423e]
  - @dekimuhq/aar-verifier@0.2.0

## 0.2.0

### Minor Changes

- Initial release. EU Trust List snapshot tooling for AAR — LOTL/national TSL fetching, JCS canonicalization, RFC 6962 Merkle tree, inclusion proof generation, standalone proof verification.

## 0.1.0

Initial release. EU Trust List snapshot tooling for AAR.
