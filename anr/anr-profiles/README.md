# `@dekimuhq/anr-profiles`

Regulation profile validators for **ANR (Anchored Notice Receipts) v1** (`ar.notice.v1`).

- **Licence:** Apache 2.0.
- **Version:** 0.6.2
- **Status:** Shipped — published.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/anr.
- **Pairs with:** [`@dekimuhq/anr`](../anr) — the consolidated family package: verify side at the root export, mint side at its `./issue` subpath.

## Install

```bash
npm install @dekimuhq/anr-profiles
```

Requires Node ≥24.6 (built-in Ed25519 in `node:crypto`). Published under the `@dekimuhq` npm scope.

## Spec conformance

The ANR v1 spec lives at https://github.com/dekimuhq/anchors-spec/tree/main/anr.
Claim type: `ar.notice.v1`.
