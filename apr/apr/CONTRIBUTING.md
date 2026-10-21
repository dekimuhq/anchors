# Contributing to `apr-verifier`

Thanks for considering a contribution. `apr-verifier` is the reference verifier for APR v1, and the bar is correctness over features: every change must keep the published conformance vectors passing byte-for-byte.

## What kind of changes land

- **Bug fixes** to verification logic, canonicalisation, Merkle code, or disclosure projection — yes, with a regression test.
- **Performance improvements** that preserve byte-for-byte output on the conformance vectors — yes.
- **New verification reasons** that extend the open `reasons[]` set without changing existing reason strings — yes, but coordinate with the spec repo first (see [`dekimuhq/anchors-spec`](https://github.com/dekimuhq/anchors-spec/tree/main/apr)).
- **Better tests, better docs, better error messages** — always welcome.
- **Public-API additions** — open a Discussion first. The surface in `src/index.ts` is intentionally narrow.

What we are unlikely to merge:

- Runtime npm dependencies. This package is zero-dep on purpose; please don't add anything to the empty `dependencies` block.
- API changes that break existing callers without a SemVer-major bump and a deprecation story.
- Verification logic that deviates from `apr-spec/v1.md` even if the deviation is "obviously better." Take that conversation to the spec repo first.

## Setup

```bash
git clone https://github.com/dekimuhq/anchors.git
cd anchors
npm ci
npm run build-all
npm test -w @dekimuhq/apr
```

You need Node ≥24.6. Tests run via the built-in `node:test` runner.

## Conformance

The conformance vectors live in [`dekimuhq/anchors-spec`](https://github.com/dekimuhq/anchors-spec/tree/main/apr) under `apr/conformance/test-vectors/`. This package carries a vendored copy in `test/fixtures/conformance-vectors/`, read by `test/conformance.test.ts`; keep it byte-identical to the published vectors.

The cross-family suite in `e2e/` additionally reads `dekimuhq/anchors-spec` from a sibling checkout (`../anchors-spec` next to this repository).

To regenerate vectors after a legitimate canonicalisation change (rare):

```bash
npm run regen-vectors
```

The generator deliberately re-implements `canonicalize` inline rather than importing from `src/` — see `scripts/regen-vectors.ts` header for why. Do not "fix" that duplication.

## DCO

All contributions are made under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). Sign off every commit:

```bash
git commit --signoff -m "verify: handle base64url padding leniency"
```

CI rejects unsigned commits. **There is no CLA.**

The full DCO text is in the [`dekimuhq/anchors-spec` CONTRIBUTING.md](https://github.com/dekimuhq/anchors-spec/blob/main/CONTRIBUTING.md). By signing off you certify the four DCO clauses (you wrote it, or it's based on appropriately-licensed prior work you can submit, or you are passing through a chain of DCO-signed contributions; and you accept that the contribution and your sign-off are public and permanent).

## Code style

- TypeScript strict mode is on, including `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`. Don't soften these.
- No runtime npm dependencies. Type-only devDependencies (`@types/node`, `typescript`) are fine.
- Default-export-free: all exports named.
- No `console.log` in `src/`. Use thrown errors or returned result objects.

## Code of conduct

This project follows the [Contributor Covenant 2.1](./CODE_OF_CONDUCT.md). Reports go to **conduct@dekimu.com**.

## Trademark notice

See [`README.md`](./README.md).
