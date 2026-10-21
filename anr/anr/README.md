# `@dekimuhq/anr`

Reference verifier for **ANR (Anchored Notice Receipts) v1**. Stateless. Edge-runtime compatible. Verifies cryptographic receipts for notice events (`ar.notice.v1`).

- **Licence:** Apache 2.0.
- **Version:** 0.7.0
- **Status:** Shipped — published; v=2 envelope default; defineFamily factory pattern.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/anr.
- **Pairs with:** this package's own `./issue` subpath (`@dekimuhq/anr/issue`, the consolidated issuer-kit) for the mint side and [`@dekimuhq/anr-profiles`](../anr-profiles) for regulator-fit validators.

## Install

```bash
npm install @dekimuhq/anr
```

Requires Node ≥24.6 (built-in Ed25519 in `node:crypto`). Published under the `@dekimuhq` npm scope.

## Spec conformance

The ANR v1 spec lives at https://github.com/dekimuhq/anchors-spec/tree/main/anr.
Claim type: `ar.notice.v1`.
