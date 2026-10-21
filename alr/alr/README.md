# `@dekimuhq/alr`

Reference verifier for **ALR (Anchored Lineage Receipts) v1**. Stateless. Edge-runtime compatible. Verifies cryptographic receipts for lineage events — `derived_from`, `forked_from`, `superseded_by`, and `disclosed` — including DAG-walk cycle detection and W3C Status List 2021 tombstone propagation.

- **Licence:** Apache 2.0.
- **Version:** 0.5.0
- **Status:** Shipped — published; v=2 envelope default; defineFamily factory pattern.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/alr.
- **Pairs with:** this package's own `./issue` subpath (`@dekimuhq/alr/issue`, the consolidated issuer-kit) for the mint side and [`@dekimuhq/alr-profiles`](../alr-profiles) for regulator-fit validators.

## Install

```bash
npm install @dekimuhq/alr
```

Requires Node ≥24.6 (built-in Ed25519 in `node:crypto`). Published under the `@dekimuhq` npm scope.

## Shipped surface (§A–§G)

- Single-receipt verification: signature + structural rules + subject presence check (§E — `subject` MUST be null on ALR per FAMILY-CONSISTENCY §3).
- All-5 profile validators wired through `@dekimuhq/alr-profiles`.
- Composition helpers: `extractAprComposition`, `buildAprReverseIndex`, `buildAprCoverageReport` (`composition.ts` — §G standalone APR parent walker).
- 66 passing tests.

## Spec conformance

The ALR v1 spec lives at https://github.com/dekimuhq/anchors-spec/tree/main/alr.
4 event types: `derived_from`, `forked_from`, `superseded_by`, `disclosed`.
First family deployment of W3C Bitstring Status List 2021 (§4.5 reference impl).
