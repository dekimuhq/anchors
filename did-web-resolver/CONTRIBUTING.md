# Contributing to `@dekimuhq/did-web-resolver`

Thanks for considering a contribution. `did-web-resolver` resolves an issuer's `did:web` identifier to the SPKI DER bytes of the public key matching an `iss_key` fingerprint, by fetching `/.well-known/dekimu-keys.json` per the convention documented in the README.

## What kind of changes land

- **Bug fixes** to the `did:web` URL mapping, key-doc validation, rotation-window checks, or cache semantics — yes, with a regression test.
- **Performance improvements** that preserve the public API and the typed error-code surface — yes.
- **Tests, docs, error-message improvements** — always welcome.
- **Spec-conformant cache backends** that implement the `KeyCache` interface — yes, but ship as a separate package; this package keeps a minimal in-memory default.

What we are unlikely to merge:

- Other DID methods (`did:key`, `did:ion`, `did:pkh`). This package is intentionally `did:web`-only — other methods belong in sibling packages with their own resolution semantics.
- New runtime dependencies. The package is zero-dep on purpose; please don't add anything to `dependencies`.
- Trust-list / allowlist logic. Trusting which `did:web` domains to resolve is the caller's concern; this package only resolves.
- API changes that break existing callers without a SemVer-major bump and a deprecation story.

## Setup

This package lives in the Anchors workspace. From the workspace root:

```bash
npm install
npm test --workspace @dekimuhq/did-web-resolver
npm run typecheck --workspace @dekimuhq/did-web-resolver
```

Node ≥20 required (for `--experimental-strip-types` + native `fetch`). Tests run via the built-in `node:test` runner.

## DCO

All contributions are made under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). Sign off every commit:

```bash
git commit --signoff -m "did-web-resolver: tighten valid_until boundary check"
```

CI rejects unsigned commits. **There is no CLA.**

## Code style

- TypeScript strict mode is on, including `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`. Don't soften these.
- No runtime npm dependencies. Type-only devDependencies are fine.
- Default-export-free: all exports named.
- No `console.log` in `src/`. Use thrown `DidWebResolveError` instances with discriminated `code` values.

## Code of conduct

This project follows the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Reports go to **conduct@dekimu.com**.

## Trademark notice

See [`README.md`](./README.md).
