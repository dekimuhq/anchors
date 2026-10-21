# @dekimuhq/quality

**Anchored Quality Receipts (AQR)** — verify (default) + issue (`./issue`).

The 16th member of the [Anchors](https://github.com/dekimuhq/anchors-spec) family
(chip 16, wire noun `ar.quality.v1`). AQR mints one signed, Merkle-anchored
receipt per quality evaluation of an AI/agent output or a release version against
a named eval suite:

> Output (or version) **O** was scored against suite **S** by scorer **K** at
> time **T**, producing score **X** vs threshold **Th** → verdict **V**.

It is a **null-subject, non-revocable event receipt** (not a data-subject
receipt). It reuses the `@dekimuhq/anchors-envelope` v=2 Ed25519 core verbatim —
no new cryptographic primitive.

> **Evaluation provenance — not a correctness guarantee.** An AQR records the
> issuer's *asserted* verdict against a *named* suite. The verifier checks the
> receipt's shape and signature; it NEVER re-runs the eval, re-derives the score,
> or cross-checks the verdict against the score. A valid AQR proves *who scored
> what, when, and against which suite* — it does not prove the output is actually
> correct.

**Distinct from AER** (`ar.evaluation.v1`, Anchored Evaluation Receipts), which
targets AI Act conformity assessment. AQR is general engineering/agent-output
quality provenance.

## Install

```bash
npm install @dekimuhq/quality
```

## Verify

```ts
import { verifyReceipt } from "@dekimuhq/quality";

const result = await verifyReceipt(envelope, { resolveKey });
// result.signature_valid, result.body_valid, result.profile_valid, ...
```

The body-shape verifier is also exported standalone:

```ts
import { verifyQualityBody } from "@dekimuhq/quality";

const r = verifyQualityBody(body); // { valid, errors, body }
```

## Issue

```ts
import { mintQualityV1 } from "@dekimuhq/quality/issue";
```

`mintQualityV1` signs a v=2 Ed25519 envelope (verify-before-sign, null subject, `policy_*` optional). Provenance only — it never asserts the score is correct.

## Design

https://github.com/dekimuhq/anchors-spec/tree/main/quality

## License

Apache-2.0
