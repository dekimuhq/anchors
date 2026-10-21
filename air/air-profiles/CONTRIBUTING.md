# Contributing to `@dekimuhq/air-profiles`

Thanks for considering a contribution. `air-profiles` is the regulator-fit profile validator set for AIR v1 (Anchored Impact-Assessment Receipts). The bar is correctness over features: every change must keep the published conformance vectors passing byte-for-byte.

## What kind of changes land

- **Bug fixes** to profile validators or dispatch — yes, with a regression test.
- **New profiles** that map to specific regulatory regimes — yes, but coordinate with the spec repo first.
- **Better tests, better docs, better error messages** — always welcome.
- **Public-API additions** — open a Discussion first. The surface in `src/index.ts` is intentionally narrow.

What we are unlikely to merge:

- New runtime dependencies beyond `@dekimuhq/anchors-envelope`.
- API changes that break existing callers without a SemVer-major bump and a deprecation story.
- Profile logic that deviates from the AIR spec even if the deviation is "obviously better." Take that conversation to the spec repo first.

## Setup

From the Anchors workspace root:

```bash
npm install
npm test --workspace @dekimuhq/air-profiles
npm run typecheck --workspace @dekimuhq/air-profiles
```

You need Node ≥22 (for `--experimental-strip-types`). Tests run via the built-in `node:test` runner.

## Conformance

The cross-family `e2e/` suite at the workspace root pulls in vectors from every member spec. AIR vectors must continue to pass.

## DCO

All contributions are made under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). Sign off every commit:

```bash
git commit --signoff -m "profiles: handle impact-assessment edge case"
```

CI rejects unsigned commits. **There is no CLA.** Full DCO text in [`dekimuhq/anchors-spec` CONTRIBUTING.md](https://github.com/dekimuhq/anchors-spec/blob/main/CONTRIBUTING.md).

## Code style

- TypeScript strict mode is on, including `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`. Don't soften these.
- Runtime dependencies are limited to `@dekimuhq/anchors-envelope`.
- Default-export-free: all exports named.
- No `console.log` in `src/`. Use thrown errors or returned result objects.

## Code of conduct

This project follows the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Reports go to **conduct@dekimu.com**.

## Trademark notice

See [`README.md`](./README.md).
