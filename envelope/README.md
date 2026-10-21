# @dekimuhq/anchors-envelope

Shared receipt envelope for the [Anchored Receipts](https://github.com/dekimuhq) protocol family.

**Version:** 0.5.1 (v=2 envelope — published)

## Purpose

Owns the canonical v=2 envelope shape, `ClaimType` discriminator union, canonicalize/sign/verify
primitives, TSA (RFC 3161 + EUTL) opt-in, W3C Status List 2021 `credentialStatus` block, and
JSON Logic policy opt-in. Member packages supply only their member-specific `body` schema.

## Consumers

All three shipped members consume this package:

- `@dekimuhq/apr` (verify `.` + issuer-kit `./issue`)
- `@dekimuhq/acr` (verify `.` + issuer-kit `./issue`) + `@dekimuhq/acr-profiles`
- `@dekimuhq/arr` (verify `.` + issuer-kit `./issue`) + `@dekimuhq/arr-profiles`
- `@dekimuhq/alr` (verify `.` + issuer-kit `./issue`) + `@dekimuhq/alr-profiles`

Pending members (specced, not yet impl): ATR, APuR, AER, AAR, ADR, ANR, ASR, ABR, AIR.

## Envelope versions

- **v=1** — legacy single-protocol shape. All existing receipts verify byte-equal.
- **v=2** — this package. `claim_type`-discriminated. Carries `tsa` / `credentialStatus` / `policy` top-level blocks. Default for `mint*()` in all family members from v1.1.

Verifiers auto-dispatch on the `v` field. Callers do not need to specify a version.

## v1.2 amendment (draft, gated on v1.1 hardening)

Adds 4 envelope fields: `kind`, `cause`, `predicate`, `iat_ms`. Field count 18 → 22.
`cause` enum additive: `breach` / `review_cycle` / `material_change` (D-anchors-7).
`JSON_LOGIC_ALLOWLIST_V1_2` export.
Gate: v1.1 ≥1w soak (waived pre-public-launch).

## Canonical envelope shape

See [`src/envelope-types.ts`](src/envelope-types.ts).
Cross-family invariants: [`../meta/FAMILY-CONSISTENCY.md`](../meta/FAMILY-CONSISTENCY.md).

## License

Apache-2.0.
