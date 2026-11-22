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

## Verifier hardening notes

**Status lists (publisher contract).** The signed status-list body carries no
sequence number, so `validFrom` is the only signed ordering signal. A list
publisher MUST sign `validFrom` = the signing time of each re-sign, strictly
increasing per re-sign — never a constant such as the start of a time bucket.
Rollback defence depends on it: with a persistent `cacheConfig.storage` the
verifier remembers the newest verified `validFrom` and rejects older lists
(`list_mismatch`/`list_rollback`). `maxListAgeSec` / `minListValidFrom` bound
the time since the publisher's LAST SIGNING, not liveness: a publisher that
re-signs only when bits change has `validFrom` = last flip, so a genuine list
with no flips for longer than the bound is rejected. Set `maxListAgeSec` above
the publisher's maximum no-flip interval, or leave it unset and rely on the
cache high-water mark. If consumers want a real freshness bound, the publisher
MAY need to re-sign periodically even with unchanged bits. If `validFrom` is constant, the only residual signal is
for `revocation` lists: at an equal `validFrom`, a list that clears a bit the
cache already saw set is rejected as `list_rollback` (revocation is permanent);
this works only after the cache has seen the post-revocation list. The list
`id` must equal the pointer's `statusListCredential` URL.

**Gating on status.** Step 11 is advisory: `signature_valid` is unchanged. Gate
on `signature_valid && !status_blocking`; every state except `active*`,
`not_attempted` and `no_status_pointer` blocks (allowlist). Supply
`statusListRootKey` or no check runs.

**PQC mandate and `resolveSig2Key`.** For an issuer with `pqc_mandatory`, a
`sig2` only counts when its key is bound by `resolveSig2Key` from the issuer's
published material. Never write `resolveSig2Key: (e) => keyBytesFromKeyRef(e.sig2_key)`
(resolving the key from the receipt itself) — that is the self-certifying
default and reopens the PQC downgrade.

## License

Apache-2.0.
