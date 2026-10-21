# @dekimuhq/aar-tsl

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
