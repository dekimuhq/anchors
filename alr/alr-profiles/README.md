# `@dekimuhq/alr-profiles`

Regulation profile validators for **ALR (Anchored Lineage Receipts) v1**.

- **Licence:** Apache 2.0.
- **Version:** 0.4.2
- **Status:** Shipped — published. All 5 profiles live.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/alr.
- **Pairs with:** [`@dekimuhq/alr`](../alr) — the consolidated family package: verify side at the root export, mint side at its `./issue` subpath.

## Install

```bash
npm install @dekimuhq/alr-profiles
```

Requires Node ≥24.6. Published under the `@dekimuhq` npm scope.

## Shipped profiles

| Profile | Regulation |
|---------|-----------|
| `gdpr.art13` | GDPR Art. 13 — transparency on data collection |
| `aiact.art13` | AI Act Art. 13 — transparency for high-risk AI systems |
| `aiact.art53.gpai-training` | AI Act Art. 53 — GPAI model training data transparency |
| `c2pa.non-media` | C2PA provenance for non-media artifacts |
| `disclosure.recipients` | Generic third-party disclosure record |

`aiact.art53` carries an internal TSA upgrade per FAMILY-CONSISTENCY §2 split.

## Spec conformance

The ALR v1 spec lives at https://github.com/dekimuhq/anchors-spec/tree/main/alr.
