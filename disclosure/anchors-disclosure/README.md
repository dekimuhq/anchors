# `@dekimuhq/anchors-disclosure`

Tier A **selective field disclosure** for the Anchored Receipts family. A holder produces an
`ar.disclosure.v1` presentation that reveals only chosen fields of a receipt; a relying party
verifies it against the receipt's signed `field_root` **without ever seeing the hidden body**.

- **Licence:** Apache 2.0.
- **Status:** Tier A. ACR (committed `field_root`) + the flat-`field_root` families
  (ANR, ABR, AIR, ALR, ARR) are adopters.
- **Crypto:** `node:crypto` only — path-bound salted-commitment Merkle leaves (RFC 6962 prefixing,
  RFC 8785 canonicalisation).
- **Pairs with:** [`@dekimuhq/anchors-envelope`](../../envelope) `./field-commit` (the
  `ar.field_commit.v1` attestation that binds a receipt id to its `field_root` + signed `leaf_count`).

## Install

```bash
npm install @dekimuhq/anchors-disclosure
```

Requires Node ≥24.6. Published under the `@dekimuhq` npm scope.

## Security model

- **Path-bound leaves.** Each leaf commits `commit(salt, canonicalize({ path, value }))`, so a hidden
  field cannot be relabelled to a different path.
- **Signed leaf count.** `leaf_count` is signed into the issuer's `ar.field_commit.v1`; verification
  uses the signed count, defeating leaf-count inflation.
- **Total-function verify.** `verifyPresentation` is deny-by-default and never throws — it returns one
  of a closed set of reasons.
- TSA + disclosable are mutually exclusive in v0 (re-signing to build the per-field tree voids the
  timestamp).

## API

```ts
import {
  buildPresentation, assemblePresentation,   // holder side
  verifyPresentation,                          // relying-party side
  buildFieldTree, leafCommit, resolveLayout,   // tree primitives
  seedSaltSource, bundleSaltSource,            // salt sources
  // per-family schemas:
  ACR_DISCLOSURE_SCHEMA, ANR_DISCLOSURE_SCHEMA, ALR_DISCLOSURE_SCHEMA,
  ABR_DISCLOSURE_SCHEMA, AIR_DISCLOSURE_SCHEMA,
  ARR_SINGLE_DISCLOSURE_SCHEMA, ARR_BATCH_DISCLOSURE_SCHEMA,
} from "@dekimuhq/anchors-disclosure";
```

See `test/*.test.ts` for end-to-end holder→verifier flows per family.

## Reveal bundles (legacy positional scheme — ACR / ARR / ALR)

The families that carry an on-wire `field_root` over per-field `commit(salt, value)`
leaves (ACR / ARR / ALR) use a positional commitment scheme, distinct from the
path-bound `ar.disclosure.v1` presentation above. The **reveal bundle** is the
transportable holder half for that scheme — what a "share this receipt" surface emits.

```ts
import {
  buildRevealBundle, verifyRevealBundle,       // holder + relying-party
  layoutExpectations,                          // signed layout → verifier expectations
  encodeRevealToken, decodeRevealToken,        // URL-safe ?reveal=<token> codec
  acrFieldLayout,                              // ACR body → FieldLayout
} from "@dekimuhq/anchors-disclosure";

// Holder persists (value, salt) per field at mint time.
const layout = acrFieldLayout(receiptBody);   // { field_root, commitments[], paths[] }
const bundle = buildRevealBundle({
  claimId, layout, openings, reveal: ["/purposes/0"],
});
const token = encodeRevealToken(bundle);       // → verify.dekimu.com/v/<claimId>?reveal=<token>

// Relying party — ALL expectations derive from the SIGNED receipt body, never
// the bundle: field_root, leaf_count (arity), and the canonical path per leaf.
// The verifier rejects a leaf_count mismatch before any Merkle check and binds
// each reveal's path to expectedPaths[leaf_index] (no field relabeling).
verifyRevealBundle(bundle, layoutExpectations(layout));
```

A bundle entry (`{ path, value, salt, merkleProof, leaf_index }`) maps 1:1 onto a
family `DisclosureProof` and verifies unchanged under the family's own verifier
(e.g. `@dekimuhq/acr`'s `verifyDisclosureProof`) — see `test/bundle.test.ts`.
