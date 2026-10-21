# Contributing to `@dekimuhq/anchors-transparency`

Thanks for considering a contribution. `anchors-transparency` provides verifier-side transparency-log primitives for the Anchored Receipts family: leaf hashing, RFC 6962 Merkle inclusion/consistency proofs, C2SP checkpoint notes, and inclusion-promise verification.

## What kind of changes land

- **Bug fixes** to RFC 6962 primitives, checkpoint parsing, or proof verification — yes, with a regression test.
- **Performance improvements** that preserve the public API — yes.
- **Tests, docs, error-message improvements** — always welcome.
- **New primitives** that are part of the C2SP / RFC 6962 transparency-log spec — yes, with a spec reference.

What we are unlikely to merge:

- Third-party crypto dependencies. This package is `node:crypto` only — no exceptions.
- API changes that break existing callers without a SemVer-major bump and a deprecation story.
- Features not related to verifiable transparency-log primitives.

## Setup

This package lives in the Anchors workspace. From the workspace root:

```bash
npm install
npm test --workspace @dekimuhq/anchors-transparency
npm run typecheck --workspace @dekimuhq/anchors-transparency
```

Node ≥20 required (for `--experimental-strip-types`). Tests run via the built-in `node:test` runner.

## DCO

All contributions are made under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). Sign off every commit:

```bash
git commit --signoff -m "anchors-transparency: fix consistency-proof edge case"
```

CI rejects unsigned commits. **There is no CLA.**

## Code style

- TypeScript strict mode is on, including `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`. Don't soften these.
- No runtime npm dependencies beyond `@dekimuhq/anchors-envelope`. Type-only devDependencies are fine.
- Default-export-free: all exports named.
- No `console.log` in `src/`.

## Code of conduct

This project follows the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Reports go to **conduct@dekimu.com**.

## Trademark notice

See [`README.md`](./README.md).
