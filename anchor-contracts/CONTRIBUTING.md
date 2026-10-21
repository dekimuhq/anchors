# Contributing to `@dekimuhq/anchors-envelope`

Thanks for considering a contribution. `anchors-envelope` is the shared foundation under every member of the Anchors family — APR, ACR, ARR, and any future member. The bar is correctness over features: every change must keep the published per-family conformance vectors passing byte-for-byte, and must not regress any existing verifier in the workspace.

## What kind of changes land

- **Bug fixes** to canonicalisation (`canonicalize`, `canonicalizeEnvelope`), envelope signature verify, the TSA helpers (`src/tsa/`), the W3C Status List 2021 implementation (`src/status/`), the policy matrix (`src/policy.ts`), or the profile dispatcher (`src/profile/`) — yes, with a regression test.
- **Performance improvements** that preserve byte-for-byte canonical output and identical verify decisions — yes.
- **Spec-conformant additions** that all members can share — yes, but coordinate first; this package is consumed by every member verifier, so the surface needs to stay stable.
- **Tests, docs, error-message improvements** — always welcome.

What we are unlikely to merge:

- Member-specific logic. If a behaviour applies only to APR / ACR / ARR, it belongs in that member's package, not in the shared envelope.
- New runtime dependencies. The package is zero-dep on purpose; please don't add anything to `dependencies`.
- API changes that break existing callers without a SemVer-major bump and a deprecation story. Every member verifier imports from this package.

## Setup

This package lives in the Anchors workspace. From the workspace root:

```bash
npm install
npm test --workspace @dekimuhq/anchors-envelope
npm run typecheck --workspace @dekimuhq/anchors-envelope
```

Node ≥22 required (for `--experimental-strip-types`). Tests run via the built-in `node:test` runner.

When changing shared surface, run the full family sweep before opening a PR:

```bash
npm test --workspaces --if-present
```

## Conformance impact

This package sits below every per-family conformance vector set. After any change here, re-run the conformance suite in each verifier (`apr/apr-verifier`, `acr/acr-verifier`, `arr/arr-verifier`) and the cross-family `e2e/` suite. A failure in any of those is a blocker.

## DCO

All contributions are made under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). Sign off every commit:

```bash
git commit --signoff -m "envelope: tighten policy matrix for batch claim type"
```

CI rejects unsigned commits. **There is no CLA.**

## Code style

- TypeScript strict mode is on, including `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`. Don't soften these.
- No runtime npm dependencies. Type-only devDependencies are fine.
- Default-export-free: all exports named.
- No `console.log` in `src/`. Use thrown errors or returned result objects.

## Code of conduct

This project follows the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Reports go to **conduct@dekimu.com**.

## Trademark notice

See [`README.md`](./README.md).
