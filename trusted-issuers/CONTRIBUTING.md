# Contributing to `@dekimuhq/anchors-trusted-issuers`

Thanks for considering a contribution. `anchors-trusted-issuers` is the signed allowlist + hash-chain governance package for the Anchored Receipts protocol family, providing the default `TrustedIssuersSource` implementation backed by `ar.trusted_issuers.v1` standalone-attestations.

## What kind of changes land

- **Bug fixes** to the wire-format validator, signature verification, hash-chain check, or `TrustedIssuersSource` semantics — yes, with a regression test.
- **Performance improvements** that preserve the public API and the typed error-code surface — yes.
- **Tests, docs, error-message improvements** — always welcome.

What we are unlikely to merge:

- New runtime dependencies. The package is zero-dep on purpose; please don't add anything to `dependencies` other than `@dekimuhq/did-web-resolver` and `@dekimuhq/anchors-envelope`.
- Auto-trust logic (e.g. "fetch and trust any issuer that publishes a manifest"). Trust governance is the signed-allowlist + maintainer sign-off flow described in the master plan §2.5; this package implements that flow, it does not bypass it.
- API changes that break existing callers without a SemVer-major bump and a deprecation story.
- Changes to `BOOTSTRAP_PUBLISHER_KEY` without a published rotation decision doc.

## Setup

This package lives in the Anchors workspace. From the workspace root:

```bash
npm install
npm test --workspace @dekimuhq/anchors-trusted-issuers
npm run typecheck --workspace @dekimuhq/anchors-trusted-issuers
```

Node ≥20 required (for `--experimental-strip-types` + native `fetch`). Tests run via the built-in `node:test` runner.

## DCO

All contributions are made under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). Sign off every commit:

```bash
git commit --signoff -m "anchors-trusted-issuers: tighten valid_until boundary check"
```

CI rejects unsigned commits. **There is no CLA.**

## Code style

- TypeScript strict mode is on, including `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`. Don't soften these.
- No runtime npm dependencies. Type-only devDependencies are fine.
- Default-export-free: all exports named.
- No `console.log` in `src/`. Use thrown error instances with discriminated `code` values.

## Code of conduct

This project follows the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Reports go to **conduct@dekimu.com**.

## Trademark notice

See [`README.md`](./README.md).
