# Changelog

## 0.1.6

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.
- Updated dependencies
  - @dekimuhq/anchors-envelope@0.26.2
  - @dekimuhq/did-web-resolver@0.5.1

## 0.1.5

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

## 0.1.4

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
  - @dekimuhq/did-web-resolver@0.3.1

## 0.1.3

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0

## 0.1.2

### Patch Changes

- Updated dependencies [a054911]
- Updated dependencies [a4aee8f]
  - @dekimuhq/anchors-envelope@0.17.0

## 0.1.1

### Patch Changes

- Align `@dekimuhq/anchors-envelope` dependency range to `^0.16.0` across all remaining families. These packages pinned `^0.13.0`, which cannot resolve the published envelope `0.16.0` (caret on a 0.x minor) — leaving the dependency range unsatisfiable for downstream consumers. Envelope 0.16.0 is additive (adds the mandate-aware `TsaState` type), so this is a metadata-only alignment with no behavior change.

## 0.1.0

Initial release. Cross-issuer interop Phase C per
plan §3 (internal design record, not published).

- `IssuerManifestV1` wire-format types for `ar.issuer_manifest.v1`.
- `parseIssuerManifest` — hand-rolled structural validator (14-member family taxonomy, `ar.<noun>.v<N>` claim_type regex, ≤90-day `valid_until` bound).
- `fetchIssuerManifest` / `manifestUrlFromDid` — HTTP fetch + parse with 1MB cap, 5s timeout, injectable fetcher.
- `verifyIssuerManifest` — Ed25519 signature verification via did:web key resolution; `valid_stale` outcome for expired-but-valid manifests.
- `runHandshake` — 4-step handshake orchestrator (discovery → verification → test-vector exchange → endorsement); returns `HandshakeReport`.
- `ManifestCache` — TTL + LRU cache for parsed manifests; positive/negative TTL split.
- CLI wrapper at `scripts/run.ts` for markdown handshake reports.

Test floor: 118 passing.
