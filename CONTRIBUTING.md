# Contributing to Anchored Receipts

Thanks for considering a contribution. Correctness comes before features here: a change must keep every published conformance vector passing, and it must not change what an existing receipt verifies to.

Changes to what verification *means* (wire format, reason codes, canonicalisation, profile semantics) belong in the spec repository first: [`dekimuhq/anchors-spec`](https://github.com/dekimuhq/anchors-spec).

## Setup

```bash
git clone https://github.com/dekimuhq/anchors.git
git clone --depth 1 https://github.com/dekimuhq/anchors-spec.git   # sibling checkout, read by e2e/
cd anchors
npm ci
npm run build-all
npm run typecheck
npm test
npm run validate
```

You need Node ≥24.6. Packages consume each other through their built `dist/`, so run `npm run build-all` before typecheck, test or validate.

## Versioning

Every source change to a publishable package **must** include a `.changeset/*.md` file. Without a changeset the change is never released, and nothing warns you.

```bash
npx changeset
```

The prompt asks which packages changed, the bump type, and a one-line summary for the changelog.

| Type | When to use |
|------|-------------|
| `patch` | Bug fixes, internal refactors, doc-only changes, metadata fixes |
| `minor` | New exports, new profile validators, additive API changes |
| `major` | Breaking changes to a public API (envelope shape, verifier signature, profile contract) |

Each family's packages (`@dekimuhq/<family>` and `@dekimuhq/<family>-profiles`) are a linked group: a release that bumps both moves them to the same version. Cross-cutting packages (`@dekimuhq/anchors-envelope`, `@dekimuhq/anchors`, `@dekimuhq/did-web-resolver`, `@dekimuhq/anchors-trusted-issuers`, …) version independently.

`npm run changeset:check` fails when source files changed without a changeset.

Releases are cut by the maintainers. Contributors only add changesets.

## Adding a family member

See [`templates/README.md`](templates/README.md). The spec lands in `dekimuhq/anchors-spec` first, then the manifest (`npm run generate`), then the packages.

## DCO

Contributions are made under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). Sign off every commit:

```bash
git commit --signoff -m "envelope: reject duplicate status entries"
```

There is no CLA.

## Code style

- TypeScript strict mode, including `exactOptionalPropertyTypes`. Don't soften it.
- No new runtime npm dependencies without discussion first. Crypto is `node:crypto` only.
- Named exports only. No `console.log` in `src/`.

## Code of conduct

This project follows the [Contributor Covenant 2.1](https://github.com/dekimuhq/anchors-spec/blob/main/CODE_OF_CONDUCT.md). Reports go to **conduct@dekimu.com**.
