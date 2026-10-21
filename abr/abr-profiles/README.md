# `@dekimuhq/abr-profiles`

Regulation profile validators for **ABR (Anchored Breach Receipts) v1** (`ar.breach.v1`).

- **Licence:** Apache 2.0.
- **Version:** 0.5.1
- **Status:** Shipped — published.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/abr.
- **Pairs with:** [`@dekimuhq/abr`](../abr) — the consolidated family package: verify side at the root export, mint side at its `./issue` subpath.

## Install

```bash
npm install @dekimuhq/abr-profiles
```

Requires Node ≥24.6 (built-in Ed25519 in `node:crypto`). Published under the `@dekimuhq` npm scope.

## Spec conformance

The ABR v1 spec lives at https://github.com/dekimuhq/anchors-spec/tree/main/abr.
Claim type: `ar.breach.v1`.
