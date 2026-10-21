# @dekimuhq/quality

## 0.1.2

### Patch Changes

- `family.meta.spec_path` now points at the public spec (https://github.com/dekimuhq/anchors-spec/tree/main/quality) instead of an unpublished internal path.

## 0.1.1

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

- Updated dependencies [28c64ff]
  - @dekimuhq/quality-profiles@0.1.1

## 0.1.0

Initial release — Anchored Quality Receipts (AQR), the 16th anchors family (chip 16, `ar.quality.v1`).

- Null-subject, non-revocable quality-evaluation receipt: "output (or version) O was scored against suite S by scorer K at time T, producing score X vs threshold Th → verdict V."
- Reuses the `@dekimuhq/anchors-envelope` v=2 Ed25519 core verbatim — no new cryptographic primitive.
- Non-consumer of Status List 2021 (evaluations are non-revocable events); TSA OPTIONAL.
- Two profiles: `quality.output` (per-output score) + `quality.release` (release-gate verdict).
- Evaluation **provenance**, not truth: the verifier records the issuer's asserted verdict and never cross-checks verdict against score. Distinct from AER (`ar.evaluation.v1`).
- `verifyReceipt()` + standalone `verifyQualityBody()` (default export). Issuer kit ships in a later unit.
