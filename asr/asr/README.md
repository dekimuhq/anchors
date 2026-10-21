# `@dekimuhq/asr`

Reference verifier for **ASR (Anchored Subject-Rights Receipts) v1**. Stateless. Edge-runtime compatible. Verifies cryptographic receipts for GDPR Art. 15–21 subject-rights request lifecycle events (`ar.subject_rights.v1`).

- **Licence:** Apache 2.0.
- **Version:** 0.6.0
- **Status:** Shipped — published; v=2 envelope default; defineFamily factory pattern.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/asr.
- **Pairs with:** this package's own `./issue` subpath (`@dekimuhq/asr/issue`, the consolidated issuer-kit) for the mint side and [`@dekimuhq/asr-profiles`](../asr-profiles) for regulator-fit validators.

## Install

```bash
npm install @dekimuhq/asr
```

Requires Node ≥24.6 (built-in Ed25519 in `node:crypto`). Published under the `@dekimuhq` npm scope.

## Spec conformance

The ASR v1 spec lives at https://github.com/dekimuhq/anchors-spec/tree/main/asr.
Claim type: `ar.subject_rights.v1`.
