# Contributing to `@dekimuhq/anchors`

Thanks for considering a contribution. `@dekimuhq/anchors` is the umbrella meta-package for the Anchors family. It contains no source logic — only namespace re-exports and subpath exports (`./envelope`, `./tsa`, `./status`, `./profile`) that route consumers to `@dekimuhq/anchors-envelope` and any future shared module.

## What kind of changes land

- **New subpath exports** that route to existing shared packages — yes, with a one-line test asserting the import resolves.
- **README clarifications** on how to consume the family — yes.
- **Dependency-range alignment fixes** when a member package version bumps and the meta dep range falls out of sync — yes.

What we are unlikely to merge:

- New logic. If you have implementation code, it belongs in the relevant member or in `@dekimuhq/anchors-envelope`.
- New runtime dependencies beyond the Anchors-family packages we are intentionally re-exporting.
- Subpath exports that fan out to non-Anchors packages.

## Setup

From the Anchors workspace root:

```bash
npm install
npm test --workspace @dekimuhq/anchors
npm run typecheck --workspace @dekimuhq/anchors
```

Node ≥22 required.

## DCO

All contributions are made under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). Sign off every commit:

```bash
git commit --signoff -m "meta: add ./profile subpath export"
```

CI rejects unsigned commits. **There is no CLA.**

## Code style

- TypeScript strict mode is on, including `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`.
- Re-exports only — no implementation code in `src/`.
- Subpath exports must be declared in `package.json` `exports`.

## Code of conduct

This project follows the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Reports go to **conduct@dekimu.com**.

## Trademark notice

See [`README.md`](./README.md).
