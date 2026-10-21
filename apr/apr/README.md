# `@dekimuhq/apr`

Reference verifier for **APR (Agent Provenance Receipts) v1** — the verify surface on the package root (`.`); issuer-kit helpers live on the `./issue` subpath. Pure library, zero runtime npm dependencies, conformance-test-driven against the published vectors in [`dekimuhq/anchors-spec`](https://github.com/dekimuhq/anchors-spec/tree/main/apr).

- **Licence:** Apache 2.0.
- **Status:** v0.7.1 — published; v=2 envelope default; defineFamily factory pattern.
- **Spec:** https://github.com/dekimuhq/anchors-spec/blob/main/apr/v1.md

## Envelope versions

This package handles two coexisting envelope shapes:

- **v=1** — legacy single-protocol shape. Existing receipts continue to verify
  byte-equal; no v=1 paths were modified in v1.1.
- **v=2** — shared envelope (`@dekimuhq/anchors-envelope`), `claim_type`-discriminated,
  carries TSA/policy/status fields. Default for `mint*()` from v1.1.

The verifier auto-dispatches on the `v` field (or its absence) of the input
receipt. Callers do not need to specify a version.

Mint v=1 explicitly with `{ envelope_v: 1 }` if you need last-mile compatibility.

## Why a separate verifier package

The verifier is the part of an APR deployment with the strongest correctness obligation: it decides whether a receipt is trustworthy. Keeping it in its own package — with zero runtime dependencies and a narrow API — lets implementers embed it in CI, in serverless functions, in browser extensions, or in long-running services without dragging in a Next.js stack or a Redis client.

The hosted verifier at `verify.dekimu.com` uses this package. You can use the same code without trusting the hosted instance.

## Install

```bash
npm install @dekimuhq/apr
```

Requires Node ≥24.6 (we use the built-in Ed25519 path in `node:crypto`).

## Use

```ts
import { verify } from "@dekimuhq/apr";

const result = verify({
  claim,            // the APR claim under inspection
  anchor,           // the daily-root envelope for the claim's date
  anchorIds,        // the deterministic id list the root was built from
  claimKeyResolver, // (kid) => ClaimVerifyingKey | undefined
  rootKeyResolver,  // (kid) => RootVerifyingKey | undefined
});

// result: { status: "verified" | "tampered" | "unverified", reasons: string[] }
```

The full API is in [`src/index.ts`](./src/index.ts):

- `verify` — top-level orchestrator (claim sig + anchor sig + Merkle inclusion).
- `verifyClaim` / `verifyAnchor` — for callers who want the two phases separately.
- `applyDisclosure` / `pseudonymise` — disclosure projection.
- `canonicalize` — the RFC 8785-lite canonicalisation used by APR.
- `computeMerkleRoot` — the reference Merkle scheme used by conformance vectors.
- Type exports for every shape in the spec.

## Conformance

This package ships with a conformance test that runs the published v1 vectors:

```bash
git clone https://github.com/dekimuhq/anchors.git
cd anchors && npm ci && npm run build-all
npm test -w @dekimuhq/apr
```

The test harness reads a vendored copy of the published vectors from `test/fixtures/conformance-vectors/` (mirrored from `apr/conformance/test-vectors/` in [`dekimuhq/anchors-spec`](https://github.com/dekimuhq/anchors-spec/tree/main/apr)). All 5 v1 vectors must pass with the exact `status` and `reasons` declared in each `expected.json`. A pull request that breaks a single vector won't merge.

## Self-host the verifier

See [`docs/self-host.md`](./docs/self-host.md) for a runnable example of using this library to verify a claim from end to end with no network access — useful for CI gates or for verifying receipts pulled out of an air-gapped environment.

## Reference Merkle scheme

The v1 spec leaves the on-the-wire inclusion-proof format verifier-defined (§7.3). This package implements the reference scheme documented at [`apr-spec/conformance/test-vectors/SCHEME.md`](https://github.com/dekimuhq/anchors-spec/blob/main/apr/conformance/test-vectors/SCHEME.md): SHA-256 leaves over UTF-8 claim ids, raw-concat parents, odd-level duplication, hex-encoded root. Implementations that ship a different inclusion-proof format (sparse trees, compact proofs, RFC 9162) can replace `computeMerkleRoot` with their own; the rest of the verifier is unaffected.

## Trademark notice

- **"APR"** is the technical acronym (*Agent Provenance Receipts*) and is unclaimed. Anyone may build, distribute, and describe their work as "APR", "APR-compatible", or "an APR receipt" without reference to Dekimu.
- Using **"Dekimu APR"** to describe a downstream implementation requires v1 conformance.

See also the [`dekimuhq/anchors-spec` README](https://github.com/dekimuhq/anchors-spec/blob/main/README.md).

## Security

See [`SECURITY.md`](./SECURITY.md). 90-day disclosure window. Reports to **security@dekimu.com**.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). DCO required. No CLA. No runtime dependencies.
