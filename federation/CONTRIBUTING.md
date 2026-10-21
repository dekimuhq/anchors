# Contributing to `@dekimuhq/anchors-federation`

Thanks for considering a contribution. `anchors-federation` is the federated discovery package for the Anchored Receipts protocol family, providing fetch + verify of per-issuer manifests (`ar.issuer_manifest.v1`) and a cross-issuer handshake orchestrator.

## What kind of changes land

- **Bug fixes** to the wire-format validator, signature verification, manifest caching, or handshake semantics — yes, with a regression test.
- **Performance improvements** that preserve the public API and the typed error-code surface — yes.
- **Tests, docs, error-message improvements** — always welcome.

What we are unlikely to merge:

- New runtime dependencies. The package is zero-dep on purpose; please don't add anything to `dependencies` other than `@dekimuhq/did-web-resolver` and `@dekimuhq/anchors-envelope`.
- Auto-trust logic (e.g. "fetch manifest and auto-add to allowlist"). Trust governance is the signed-allowlist + maintainer sign-off flow in `@dekimuhq/anchors-trusted-issuers`; this package discovers, it does not decide.
- API changes that break existing callers without a SemVer-major bump and a deprecation story.

## Setup

This package lives in the Anchors workspace. From the workspace root:

```bash
npm install
npm test --workspace @dekimuhq/anchors-federation
npm run typecheck --workspace @dekimuhq/anchors-federation
```

Node ≥20 required (for `--experimental-strip-types` + native `fetch`). Tests run via the built-in `node:test` runner.

## DCO

All contributions are made under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). Sign off every commit:

```bash
git commit --signoff -m "anchors-federation: improve manifest staleness check"
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
