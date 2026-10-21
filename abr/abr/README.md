# `@dekimuhq/abr`

Reference verifier for **ABR (Anchored Breach Receipts) v1**. Stateless. Edge-runtime compatible. Verifies cryptographic receipts for breach lifecycle events (`ar.breach.v1`).

- **Licence:** Apache 2.0.
- **Version:** 0.6.0
- **Status:** Shipped — published; v=2 envelope default; defineFamily factory pattern.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/abr.
- **Pairs with:** this package's own `./issue` subpath (`@dekimuhq/abr/issue`, the consolidated issuer-kit) for the mint side and [`@dekimuhq/abr-profiles`](../abr-profiles) for regulator-fit validators.

## Install

```bash
npm install @dekimuhq/abr
```

Requires Node ≥24.6 (built-in Ed25519 in `node:crypto`). Published under the `@dekimuhq` npm scope.

## Spec conformance

The ABR v1 spec lives at https://github.com/dekimuhq/anchors-spec/tree/main/abr.
Claim type: `ar.breach.v1`.
