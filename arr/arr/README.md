# `@dekimuhq/arr`

Reference verifier for **ARR (Anchored Retention Receipts) v1** — the verify surface on the package root (`.`); issuer-kit helpers live on the `./issue` subpath. Pure library, edge-runtime compatible, two runtime deps (`@dekimuhq/apr` for canonicalisation re-exports, `@dekimuhq/acr` for cross-receipt resolution).

- **Licence:** Apache 2.0.
- **Status:** v0.9.0 — published; v=2 envelope default; defineFamily factory pattern.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/arr.
- **Pairs with:** this package's own `./issue` subpath (`@dekimuhq/arr/issue`, the consolidated issuer-kit) for the mint side and [`@dekimuhq/arr-profiles`](../arr-profiles) for regulator-fit validators.

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

ARR receipts attest to **retention-lifecycle operations** — erasure, expiry, hold extensions and releases, anonymisation, pseudonymisation, archival. They are the audit-trail counterpart to ACR (consent) and APR (processing). The verifier's job is to decide whether each receipt is genuinely signed, structurally valid, and (if part of a chain) consistent with its predecessor.

Like ACR — and unlike APR — verification is **self-contained per receipt**: each ARR carries the issuer's public key in `iss_key`. No catalog is required. Chain walks for the same target use each receipt's own pubkey.

Keeping the verifier in its own package lets it ship into CI gates, retention-job runners, and serverless consumers without the issuer-side machinery.

## Install

```bash
npm install @dekimuhq/arr
```

Requires Node ≥24.6 (built-in Ed25519 in `node:crypto`).

## Use

```ts
import {
  verifyReceipt,
  verifySingleReceipt,
  verifyBatchReceipt,
  resolveTargetChain,
  verify30DayWindow,
} from "@dekimuhq/arr";

// Single-receipt verification: signature + structural rules (trigger_receipt
// required when trigger === "subject_request", effective_until required on
// hold_extension / archive, etc.).
const result = verifySingleReceipt(receipt, {
  anchorInclusionTime: "2026-05-16T09:15:00Z",
});
if (!result.valid) console.error("errors:", result.errors);

// Batch verification: signature + target_count + RFC 6962 Merkle root over
// the disclosed targets.
const batchResult = verifyBatchReceipt(batchReceipt, {
  anchorInclusionTime: "2026-05-16T09:15:00Z",
  disclosedTargets: ["sha256:...", "sha256:..."], // optional
});

// Per-target chain walk: validates `prev` integrity and reports terminal state.
const chain = resolveTargetChain([erasureV1, holdExtensionV1, holdReleaseV1]);
// chain.terminal: true if the chain has reached an erasure or anonymisation.
// chain.currentState: the latest state_snapshot.
// chain.errors: chain-integrity issues, if any.
// chain.terminalKind: which kind terminated it, or null.

// Art. 12(3) 30-day window: erasure must land within 30 days of the ACR
// withdrawal it answers. Errors: "event_before_withdrawal", "gdpr.art12.timeout".
const window = verify30DayWindow({
  erasureEventAt: "2026-05-15T10:00:00Z",
  acrWithdrawalGrantedAt: "2026-05-10T10:00:00Z",
});
```

`verifySingleReceipt` requires an `anchorInclusionTime` so it can check that the anchor was minted after `granted_at` — a spec-§3.2 freshness rule that prevents pre-signed-receipt attacks.

`verifyReceipt` is the top-level, envelope-version-aware entry point: it dispatches
`v: 2` receipts to the family verifier and `v: 1` (or absent `v`) to
`verifySingleReceipt`. It is async and fails closed on any unknown version. A v=1
receipt requires `opts.v1Opts.anchorInclusionTime`, or it returns
`reason: "v1_requires_anchor_inclusion_time"`.

`resolveTargetChain` does NOT re-verify signatures — pair with `verifySingleReceipt` on each link if the chain source is untrusted.

## Batch receipts

ARR supports batched retention operations via `ar.batch.v1`. A single signed envelope covers up to **65,536 targets** (RFC 6962 Merkle depth ≤ 16) and amortises signature overhead across the batch. Per-target disclosure proofs let auditors verify a single target was included without expanding the whole tree.

```ts
// Batch with a per-target disclosure proof.
const inclusion = verifyBatchDisclosure({
  snapshot,          // the per-target ArrStateSnapshot at batch time
  leafIndex,         // this target's position in the tree
  proof,             // RFC 6962 sibling-path (string[])
  root,              // batch_root from the ar.batch.v1 receipt
  totalLeaves,       // target_count from the same receipt
});
// inclusion.valid / inclusion.errors ("leaf_index.out_of_bounds", ...)
```

The Mode-A / Mode-B distinction (chain-authoritative vs batch-authoritative) is pinned per profile — see [`@dekimuhq/arr-profiles`](../arr-profiles).

## API surface

Full surface in [`src/index.ts`](./src/index.ts):

- **Envelope dispatch:** `verifyReceipt` (async, v=1/v=2), `EnvelopeVerifyResult`, `EnvelopeVerifyOptions`, `arrFamily`.
- **Single-receipt verification:** `verifySingleReceipt`, `VerifyResult`, `VerifySingleOptions`.
- **Batch:** `verifyBatchReceipt`, `VerifyBatchOptions`, `BatchVerifyResult`, `verifyBatchDisclosure`, `BatchDisclosureInput`, `BatchDisclosureResult`.
- **Chain:** `resolveTargetChain`, `ChainResolution`.
- **Triggers:** `resolveTriggerReceipt` — resolves and checks the `trigger_receipt` cross-reference required when `trigger: subject_request` (issuer + kind match). Types: `ResolveTriggerInput`, `TriggerResolutionResult`, `ResolvedTriggerReceipt`, `TriggerReceiptResolver`.
- **Windows:** `verify30DayWindow` — Art. 12(3) 30-day arithmetic between an erasure event and the ACR withdrawal that triggered it. Types: `Verify30DayInput`, `Window30Result`.
- **TSA mandate:** `applyArrTsaMandate`, `ArrTsaMandateTarget` — per-event TSA grading (FAMILY-CONSISTENCY §2).
- **Crypto re-exports:** `canonicalize`, `commit`, `buildTree`, `inclusionProof`, `verifyInclusion` — pulled from upstream packages for symbol symmetry across the family.
- **Types:** `ARRReceipt`, `ARRBatchReceipt`, `ArrKind`, `ArrSingleKind`, `ArrBatchEventKind`, `ArrProfile`, `ArrTrigger`, `ArrTargetKind`, `ArrAnchor`, `ArrStateSnapshot`.

## Spec conformance

The ARR v1 spec lives at https://github.com/dekimuhq/anchors-spec/tree/main/arr. This package's `src/` is the implementation source-of-truth for the wire format.

Test vectors will live at `verify.dekimu.com/arr/v1` once published; the in-tree test suite (`test/*.test.ts`) covers single-receipt verify, batch verify, batch disclosure, chain walks, trigger semantics, and the Art. 12(3) 30-day window helper.
