# Contributing to `@dekimuhq/arr-profiles`

Thanks for considering a contribution. `arr-profiles` carries the profile descriptors and validators that bind ARR receipts to specific regulatory mandates — currently `gdpr.art17.erasure-finalized` (GDPR Article 17 erasure, with a TSA-witnessed finalisation requirement).

## What kind of changes land

- **New profile descriptors** that bind ARR receipts to a regulatory mandate — yes, but coordinate with the spec repo first AND a legal reviewer to confirm any cited regulation references, OIDs, or trust-list assertions.
- **Bug fixes** to existing validators (`validateGdprArt17ErasureFinalized`, the adapter shim) — yes, with a regression test.
- **Better mandate coverage** in the validator (additional checks the spec mandates but the validator omits) — yes, with a citation.
- **Tests, docs, error-message improvements** — always welcome.

What we are unlikely to merge:

- Validators that paraphrase a regulation. We need the cited normative article (GDPR Art. 17, Implementing Decision X, etc.) and the identifier we are checking against. Vagueness is a security hole.
- New runtime dependencies beyond `@dekimuhq/anchors-envelope` and `@dekimuhq/arr`.
- Profile descriptors that overlap with existing ones — open a Discussion to merge.

## Regulatory citation

Any descriptor that asserts a regulatory binding MUST cite:

- The regulation article (e.g. GDPR Art. 17(1)(a–f)).
- Any OID or identifier checked at verify time, with its issuing standard.
- The expected receipt shape (event types, field constraints) it enforces.


## Setup

From the Anchors workspace root:

```bash
npm install
npm test --workspace @dekimuhq/arr-profiles
npm run typecheck --workspace @dekimuhq/arr-profiles
```

Node ≥22 required.

## DCO

All contributions are made under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). Sign off every commit:

```bash
git commit --signoff -m "profiles: enforce TSA presence on erasure finalized"
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
