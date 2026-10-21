# Contributing to `@dekimuhq/acr-profiles`

Thanks for considering a contribution. `acr-profiles` carries the profile descriptors and validators that bind ACR receipts to specific regulatory mandates — currently `esig.accept@qes` (eIDAS Qualified Electronic Signatures via ETSI EN 319 421 BTSP TSA policy).

## What kind of changes land

- **New profile descriptors** that bind ACR receipts to a regulatory mandate — yes, but coordinate with the spec repo first ([`dekimuhq/anchors-spec`](https://github.com/dekimuhq/anchors-spec/tree/main/acr)) AND a legal reviewer to confirm any cited OIDs, regulation cites, or trust-list assertions.
- **Bug fixes** to existing validators (`validateEsigAcceptQes`, the adapter shim) — yes, with a regression test.
- **Better mandate coverage** in the validator (additional checks the spec mandates but the validator omits) — yes, with a citation.
- **Tests, docs, error-message improvements** — always welcome.

What we are unlikely to merge:

- Validators that paraphrase a regulation. We need the cited normative text and the OID/identifier we are checking against. Vagueness is a security hole.
- New runtime dependencies beyond `@dekimuhq/anchors-envelope` and `@dekimuhq/acr`.
- Profile descriptors that overlap with existing ones — open a Discussion to merge.

## OID confirmation

Any descriptor that asserts an OID (TSA policy, certificate policy, trust-list identifier) MUST cite the issuing standard (ETSI EN 319 421, ETSI EN 319 411-2, eIDAS Implementing Decision (EU) 2015/1505, etc.) and SHOULD be reviewed by a legal reviewer before landing. See an internal design record (not published) for the precedent.

## Setup

From the Anchors workspace root:

```bash
npm install
npm test --workspace @dekimuhq/acr-profiles
npm run typecheck --workspace @dekimuhq/acr-profiles
```

Node ≥22 required.

## DCO

All contributions are made under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). Sign off every commit:

```bash
git commit --signoff -m "profiles: tighten esig.accept@qes OID match"
```

CI rejects unsigned commits. **There is no CLA.** Full DCO text in [`dekimuhq/anchors-spec` CONTRIBUTING.md](https://github.com/dekimuhq/anchors-spec/blob/main/CONTRIBUTING.md).

## Code style

- TypeScript strict mode (`exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`).
- Each validator returns a `{ ok: boolean; reason?: string }` discriminated union; no exceptions for normal mandate failures.
- Validator adapters wrap their profile-specific validator into the universal `ProfileValidator` shape from `@dekimuhq/anchors-envelope/profile`.

## Code of conduct

This project follows the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Reports go to **conduct@dekimu.com**.

## Trademark notice

See [`README.md`](./README.md).
