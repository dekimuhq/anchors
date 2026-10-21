# ARR — Anchored Retention Receipts

Reference implementation of ARR v1.0, sibling of APR + ACR in the Anchored Receipts protocol family.

**Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/arr
**License (code):** Apache-2.0
**License (spec):** CC0

## Packages

- `@dekimuhq/arr` — verification primitives (single + batch + chain + cross-protocol) on the package root (`.`), plus issuance helpers (single + batch mint, keys, salt-epoch rotation, continuity) on the `./issue` subpath
- `@dekimuhq/arr-profiles` — regulation profile validators: `gdpr.art17`, `gdpr.art5e`, `hipaa.retention`, `kyc.retention`, `sox.retention`, `mifid2.retention`, `aiact.art10`

## Conventions

- Node 22+, TypeScript strict mode with `exactOptionalPropertyTypes`
- Tests run via `node --experimental-strip-types --test`
- No third-party crypto dependencies — `node:crypto` only
- Canonicalisation: RFC 8785 (JCS), reused from `@dekimuhq/apr`
- Merkle trees: RFC 6962 leaf/node prefixing, reused from `@dekimuhq/acr`
- Cross-protocol resolution: ARR `trigger_receipt` resolves against `@dekimuhq/acr`
