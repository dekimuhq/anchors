# @dekimuhq/anchors-disclosure

## 0.3.1

### Patch Changes

- First release from the public `dekimuhq/anchors` repository: package metadata now points at it (`repository`, `homepage`, `bugs`), `publishConfig.access` is `public`, `engines.node` is declared as `>=24.6.0`, and every tarball ships a README and the Apache-2.0 LICENSE. No API changes.
- Updated dependencies
  - @dekimuhq/anchors-envelope@0.26.2

## 0.3.0

### Minor Changes

- dd49239: Holder-side selective-disclosure reveal-bundle kit.

  Adds the transportable holder half of the disclosure handshake for the legacy
  positional commitment scheme shipped by ACR / ARR / ALR (Merkle root over
  per-field `commit(salt, value)` leaves):

  - `buildRevealBundle({ claimId, layout, openings, reveal })` → `RevealBundle`
    (`kind: "ar.reveal.v1"`, `field_root`, `leaf_count`, `reveals[{ path, value,
salt, merkleProof, leaf_index }]`). Each opening is re-committed and checked
    against the on-wire commitment before a proof is emitted.
  - `verifyRevealBundle(bundle, expectations)` — total function. **The verifier
    contract is now the strengthened, safe-only signature**: it requires
    `{ expectedFieldRoot, expectedLeafCount, expectedPaths }` derived from the
    SIGNED receipt body (there is no "trust the bundle" mode). It (1) rejects a
    `field_root` mismatch, (2) rejects a self-declared `leaf_count` that differs
    from the signed arity BEFORE any Merkle check — closing the RFC-6962
    leaf-count / second-preimage ambiguity (CVE-2012-2459 class), (3) binds each
    reveal's `path` to `expectedPaths[leaf_index]` and rejects out-of-range
    indices — so an attacker-chosen `path` can never relabel a valid opening for
    a different field (e.g. present a `/purposes/0` opening as a `/sub` reveal),
    then (4) recomputes each leaf and verifies RFC-6962 inclusion. Input bounds
    (reveal count, proof depth, leaf/value/path/claimId lengths, salt + hash
    charsets) reject malformed bundles up front. `verifyRevealBundle` and the
    verify.dekimu.com `?reveal=` handler now enforce the identical predicate.
  - `layoutExpectations(layout)` — derives `{ expectedFieldRoot, expectedLeafCount,
expectedPaths }` from a signed-body field layout for `verifyRevealBundle`.
  - `encodeRevealToken` / `decodeRevealToken` — compact URL-safe (base64url,
    unpadded) token codec for `?reveal=<token>` links.
  - `acrFieldLayout(body)` — derives the ACR field layout (`[sub_commit,
...purposes, policy_hash]`, paths `/sub` · `/purposes/{i}` · `/policy`).

  Scheme is byte-identical to the family issuer kits: golden-vector tests mint a
  real ACR receipt via `@dekimuhq/acr/issue` and assert every bundle proof
  verifies unchanged under ACR's own `verifyDisclosureProof`. Additive — no
  existing export changed.

### Patch Changes

- 28c64ff: Re-sync internal dependency ranges so npm links the workspace instead of fetching stale published copies.

  Five internal 0.x carets could not admit their own workspace version (`^0.6.6` cannot match `0.7.0`), so npm resolved those packages from the registry, and those older tarballs pinned `@dekimuhq/anchors-envelope@^0.18.1` — materialising envelope 0.18.x in nested `node_modules` where `cli` then compiled against it. Every `anchors-envelope` range is now `^0.26.1` (the published version, matching the workspace source), and the five broken internal pins admit their workspace versions.

  This removes the root cause of the nesting, so the root `postinstall` rm -rf and the explicit `npm run postinstall` step in `anchors-ci.yml` are both deleted — the workaround was masking the drift that created it.

## 0.2.1

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

## 0.2.0

### Minor Changes

- 1f05cf4: ABR, AIR, and ALR adopt Tier A selective disclosure (following ANR). Each kit gains a `mintXxxV2Disclosable()` opt-in mint that builds `field_root` from the per-field tree over the family `DisclosureSchema` and emits `ar.field_commit.v1` + the holder seed. Additive — every `mintXxxV2` and all shipped flat receipts are byte-identical and untouched. Adds `ABR_DISCLOSURE_SCHEMA` (`/profile /incident_correlation_id /event_type /jurisdiction`), `AIR_DISCLOSURE_SCHEMA` (`/air_receipt_id /processing_activity_id /event_type` — AIR carries no `profile` in body), and `ALR_DISCLOSURE_SCHEMA` (`/profile /artifact_hash /event_at /event_type`) to `@dekimuhq/anchors-disclosure`. TSA + disclosable rejected in v0 (re-signing voids the timestamp); ABR `breach.detected` therefore cannot be both disclosable and fully verified (TSA-mandatory event).
- 583818d: ANR is the first flat-`field_root` family to adopt Tier A selective disclosure. New `mintAnrV2Disclosable()` opt-in mint builds `field_root` from the per-field tree over `ANR_DISCLOSURE_SCHEMA` and emits `ar.field_commit.v1` + the holder seed. Additive — `mintAnrV2` and all shipped flat receipts are byte-identical and untouched. Adds `ANR_DISCLOSURE_SCHEMA` to `@dekimuhq/anchors-disclosure`.
- 1068f13: ARR adopts Tier A selective disclosure — the special flat-family case. ARR's native `field_root` is a flat SHA-256 over a fixed field _subset_ (not a per-field tree) and it has two entry points (`mintArrV2Single` over 5 single claim_types, `mintArrV2Batch` over `ar.batch.v1`), so two sibling mints ship: `mintArrV2SingleDisclosable` and `mintArrV2BatchDisclosable`. Each discards ARR's subset-hash field_root, rebuilds a per-field Merkle tree from its schema, re-signs, and emits `ar.field_commit.v1` + the holder seed. Additive — `mintArrV2Single`/`mintArrV2Batch` and shipped flat receipts byte-identical. Adds `ARR_SINGLE_DISCLOSURE_SCHEMA` (`/profile /target_kind /trigger /event_at`) and `ARR_BATCH_DISCLOSURE_SCHEMA` (`/profile /batch_event_kind /target_kind /event_at`) to `@dekimuhq/anchors-disclosure`. One seed per mint call (a batch is one receipt → L20 unlinkability holds without per-target seeds). TSA rejected in v0. This completes the flat-family migration (ANR/ABR/AIR/ALR/ARR all adopted).

### Patch Changes

- Updated dependencies [7c4329d]
  - @dekimuhq/anchors-envelope@0.18.0
