# Contributing to `@dekimuhq/guard-detect`

Thanks for considering a contribution. `guard-detect` is a zero-dependency deterministic detection engine for prompt-injection and jailbreak patterns. The bar is correctness over features: every change must keep the published rule corpus producing stable, reproducible `ruleset_hash` values.

## What kind of changes land

- **Bug fixes** to pattern matching logic, decision policy, or type definitions — yes, with a regression test.
- **New rules** that extend the corpus without changing existing rule IDs — yes, but they will change the `ruleset_hash`. Coordinate with the spec repo first.
- **Performance improvements** that preserve deterministic output — yes.
- **Better tests, better docs, better error messages** — always welcome.
- **Public-API additions** — open a Discussion first. The surface in `src/index.ts` is intentionally narrow.

What we are unlikely to merge:

- Any runtime dependencies (this package is zero-dep by design — `node:crypto` only).
- API changes that break existing callers without a SemVer-major bump and a deprecation story.
- Weakening of patterns to reduce false positives without evidence from production data.

## Setup

From the Anchors workspace root:

```bash
npm install
npm test --workspace @dekimuhq/guard-detect
npm run typecheck --workspace @dekimuhq/guard-detect
```

You need Node ≥24.6. Tests run via the built-in `node:test` runner.

## Reproducibility

The `ruleset_hash` is the stability contract. Same rules → same hash → same verdicts. If you add or modify rules, the hash changes — that is intentional and expected. Never modify rules without bumping `RULESET_VERSION`.

## DCO

All contributions are made under the [Developer Certificate of Origin v1.1](https://developercertificate.org/). Sign off every commit:

```bash
git commit --signoff -m "feat: add new jailbreak pattern"
```

CI rejects unsigned commits. **There is no CLA.** Full DCO text in [`dekimuhq/anchors-spec` CONTRIBUTING.md](https://github.com/dekimuhq/anchors-spec/blob/main/CONTRIBUTING.md).

## Code style

- TypeScript strict mode is on, including `exactOptionalPropertyTypes`. Don't soften these.
- Zero runtime dependencies — `node:crypto` only.
- Default-export-free: all exports named.
- No `console.log` in `src/`. Use thrown errors or returned result objects.

## Code of conduct

This project follows the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Reports go to **conduct@dekimu.com**.

## Trademark notice

See [`README.md`](./README.md).
