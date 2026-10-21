# `@dekimuhq/asr-profiles`

Regulation profile validators for **ASR (Anchored Subject-Rights Receipts) v1** (`ar.subject_rights.v1`).

- **Licence:** Apache 2.0.
- **Version:** 0.5.5
- **Status:** Shipped — published.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/asr.
- **Pairs with:** [`@dekimuhq/asr`](../asr) — the consolidated family package: verify side at the root export, mint side at its `./issue` subpath.

## Install

```bash
npm install @dekimuhq/asr-profiles
```

Requires Node ≥24.6 (built-in Ed25519 in `node:crypto`). Published under the `@dekimuhq` npm scope.

## Spec conformance

The ASR v1 spec lives at https://github.com/dekimuhq/anchors-spec/tree/main/asr.
Claim type: `ar.subject_rights.v1`.
