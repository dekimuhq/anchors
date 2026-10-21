# `@dekimuhq/air`

Reference verifier for **AIR (Anchored Impact-Assessment Receipts) v1**. Stateless. Edge-runtime compatible. Verifies cryptographic receipts for GDPR Art. 35 / AI Act Art. 27 data-protection / fundamental-rights impact-assessment lifecycle events (`ar.impact.v1`).

- **Licence:** Apache 2.0.
- **Version:** 0.7.0
- **Status:** Shipped — published; v=2 envelope default; defineFamily factory pattern.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/air.
- **Pairs with:** this package's own `./issue` subpath (`@dekimuhq/air/issue`, the consolidated issuer-kit) for the mint side and [`@dekimuhq/air-profiles`](../air-profiles) for regulator-fit validators.

## Install

```bash
npm install @dekimuhq/air
```

Requires Node ≥24.6 (built-in Ed25519 in `node:crypto`). Published under the `@dekimuhq` npm scope.

## Spec conformance

The AIR v1 spec lives at https://github.com/dekimuhq/anchors-spec/tree/main/air.
Claim type: `ar.impact.v1`.
