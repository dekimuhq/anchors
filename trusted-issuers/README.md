# @dekimuhq/anchors-trusted-issuers

Signed allowlist + hash-chain governance for the Anchored Receipts protocol family.

> **Pre-B6 status:** This package ships a PLACEHOLDER `BOOTSTRAP_PUBLISHER_KEY` until the bootstrap-key ceremony (Phase B6) lands the real value. No production verifier should consume this package until version 0.1.0 stable with the real key is published.

## What this is

`@dekimuhq/anchors-trusted-issuers` is the default `TrustedIssuersSource` implementation for `@dekimuhq/did-web-resolver` 0.3.0+'s `verifyIssuerKey`. The allowlist is a signed `ar.trusted_issuers.v1` document published at `verify.dekimu.com/.well-known/dekimu-trusted-issuers.json` and mirrored append-only at `dekimuhq/anchors-trusted-issuers-chain`. Full governance model is described in the cross-issuer interop master plan §2 (internal design record, not published).

## What this is not

- Not a CA. This package does not issue certificates or manage PKI hierarchies.
- Not a general-purpose trust framework outside Anchored Receipts.
- Does NOT auto-add issuers to the allowlist. Governance is maintainer-approved PRs on the chain repo per master plan §2.5; this package implements that flow, it does not bypass it.
- Does NOT decide policy on `valid_untrusted` / `valid_revoked` outcomes. The caller decides whether to fail-closed or warn-and-accept — this package only provides the lookup.

## Install

```bash
npm install @dekimuhq/anchors-trusted-issuers
```

## Surface preview

```ts
// B0 (ships now):
export type { TrustedIssuerListV1, TrustedIssuerListUnsignedV1, TrustedIssuerRecord, FamilySlug } from "./types.ts";

// B1+ (placeholder until those tasks land):
// export { fetchTrustedIssuers } from "./fetch.ts";
// export { verifyTrustedIssuersList } from "./verify.ts";
// export { TrustedIssuersSourceFromList } from "./source.ts";
// export { verifyHashChain } from "./chain.ts";
// export { BOOTSTRAP_PUBLISHER_KEY } from "./bootstrap.ts";
// export { makeDefaultTrustedIssuersSource } from "./default-source.ts";
```

## Security model

See [`SECURITY.md`](./SECURITY.md) for the per-package security policy and bootstrap key handling rules. Full governance table — including trust decisions, publisher key rotation, and allowlist approval flow — is in master plan §2.5 (internal design record, not published).

Rotation cadence: 1 year / 90-day overlap window / MAJOR version bump per rotation. Any change to `BOOTSTRAP_PUBLISHER_KEY` requires a published rotation decision doc and a coordinated 90-day migration window.

## Versioning

Pre-1.0; minor versions may break the public API. Lockfile pinning (`@dekimuhq/anchors-trusted-issuers@0.1.0`) is required until 1.0.0 stable is published.

## License

Apache-2.0.
