# @dekimuhq/anchors-transparency

## 0.3.3

### Patch Changes

- 858a2d8: The published tarball now includes CONTRIBUTING.md, SECURITY.md and CHANGELOG.md, like every other package in the repository.

## 0.3.2

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.
- Updated dependencies
  - @dekimuhq/anchors-envelope@0.26.2

## 0.3.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

## 0.2.0

### Minor Changes

- 4c269a6: Phase 1.5 — witness co-signing (C2SP cosignature/v1). Add `signCosignature` / `verifyCosignature` / `cosignatureMessage` / `decodeCosignatureBlob` for witness cosignatures over the timestamped C2SP `cosignature/v1` message, `gatherCosignatures` for the operator-side gather step, and `verifyCheckpointCosigned` with an opt-in `requireWitnessCosignatures: N` policy. Below threshold yields a `checkpoint_undercosigned` warning, never a HARD-fail (verification never bricks during witness recruitment). The operator signature line is unchanged, so all Phase 1 checkpoints verify byte-equal. No envelope/attestation wire change.

  Cosignature lines are byte-compatible with the C2SP signed-note framing: the base64url blob is `4-byte key id ‖ 8-byte BE timestamp ‖ 64-byte signature` (76 bytes). The key id is `SHA-256(name ‖ 0x0A ‖ 0x04 ‖ rawPubkey)[:4]` — algorithm byte `0x04` (timestamped checkpoint cosignature), NOT plain Ed25519 `0x01` — so off-the-shelf C2SP witnesses/verifiers route by the same id we emit. New exports `c2spKeyHash` + `decodeCosignatureLineId`; `verifyCheckpointCosigned` rejects a witness line whose embedded key id does not bind its name to the allowlisted key. (Resolves the "line framing" open item from the v1.5 decision doc.)

  Verifier-policy gated on maintainer ratification of the decision doc; the `verify.dekimu.com` operator-gather + witness allowlist wiring stays held until ≥1 independent witness is recruited.

## 0.1.3

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

## 0.1.2

### Patch Changes

- e87db71: Re-export `verifyInclusionProof` and `verifyConsistencyProof` from the package root. Independent transparency-log monitors can now verify RFC 6962 inclusion and consistency proofs from the published package without reaching into `src/rfc6962.ts`.
- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0

## 0.1.1

### Patch Changes

- Re-export `verifyInclusionProof` and `verifyConsistencyProof` from the package index. Monitors that audit the log independently (recompute roots from leaf + audit path, check consistency between two checkpoints) need these RFC 6962 primitives on the public surface; previously only the higher-level `verifyInclusion` was exported.
