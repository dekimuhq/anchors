# `@dekimuhq/acr`

Reference verifier for **ACR (Anchored Consent Receipts) v1** — the verify surface on the package root (`.`); issuer-kit helpers live on the `./issue` subpath. Pure library, edge-runtime compatible, one runtime dep (`@dekimuhq/apr` for canonicalisation re-exports).

- **Licence:** Apache 2.0.
- **Status:** v0.7.0 — published; v=2 envelope default; defineFamily factory pattern.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/acr.
- **Pairs with:** this package's own `./issue` subpath (`@dekimuhq/acr/issue`, the consolidated issuer-kit) for the mint side and [`@dekimuhq/acr-profiles`](../acr-profiles) for regulator-fit validators.

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

The verifier is the part of an ACR deployment with the strongest correctness obligation: it decides whether a receipt is trustworthy. Keeping it in its own package — with a narrow API and no Node-specific assumptions beyond `node:crypto`'s Ed25519 path — lets implementers embed it in CI gates, serverless functions, browser extensions, or long-running services without dragging in unrelated infrastructure.

Verification is **self-contained per receipt**: each ACR carries its issuer's public key in `iss_key`, so the verifier does not need a kid → key catalog (a structural difference from APR). The only external state a verifier needs is the chain of prior receipts (for `resolveChainState`) and the field disclosures it wants to validate (for `verifyDisclosureProof`).

## Install

```bash
npm install @dekimuhq/acr
```

Requires Node ≥24.6 (built-in Ed25519 in `node:crypto`).

## Use

```ts
import {
  verifyReceiptSignature,
  resolveChainState,
  verifyDisclosureProof,
  hashReceipt,
} from "@dekimuhq/acr";

// Single-receipt signature check — fast, no external lookups.
if (!verifyReceiptSignature(receipt)) throw new Error("signature invalid");

// Full lifecycle walk — consent + optional modifications + optional withdrawal.
const state = resolveChainState([consent, modification, withdrawal]);
// state.status: "active" | "modified" | "withdrawn" | "broken"
// state.terminal_kind, state.terminal_granted_at

// Selective-disclosure proof verification.
const ok = verifyDisclosureProof(proof, receipt.field_root);
```

`verifyReceiptSignature` validates the Ed25519 signature over the receipt's canonical bytes with `anchor`, `sig`, and `countersig` all set to `null` — so a receipt verifies whether or not it has been anchored or countersigned.

`resolveChainState` walks an ordered chain and returns the terminal state, plus any chain-integrity errors. It does NOT re-verify signatures — pair with `verifyReceiptSignature` on each link if you don't trust the chain source.

## API surface

Full surface in [`src/index.ts`](./src/index.ts):

- **Verification:** `verifyReceiptSignature`, `verifyDisclosureProof`.
- **Chain:** `resolveChainState`, `hashReceipt`. Hash is the canonical SHA-256 used as the `prev` link.
- **Commitments:** `commit`, `verifyCommitment`, `randomSalt`. Salted SHA-256 over UTF-8 (used for `sub_commit` / `purpose_commit` style fields).
- **Merkle:** `buildTree`, `inclusionProof`, `verifyInclusion`, `MerkleTree`. RFC 6962-style; backs the `field_root` shape.
- **Canonicalisation:** `canonicalize`, `base64UrlEncode`, `base64UrlDecode` — re-exported from `@dekimuhq/apr` for symbol symmetry across the family.
- **Types:** `ACRReceipt`, `AcrKind`, `AcrProfile`, `AcrAnchor`, `FieldDisclosure`, `DisclosureProof`, `ChainStatus`, `ChainState`.

## How verification differs from APR

| Question | APR | ACR |
|---|---|---|
| Where does the verifier get the issuer public key? | From a `kid → key` catalog (`CLAIMS_VERIFY_KEYS_JSON` or equivalent) | Embedded in the receipt as `iss_key` |
| How is rotation handled? | Catalog update with `notBefore` / `notAfter` overlap | Issuer-side only — flip the active private key; old receipts keep verifying |
| Is the verifier stateful? | Per-deploy catalog state | None (per receipt) |
| What about anchoring? | Receipts include daily Merkle anchors signed by a separate root key | Anchors are optional; signatures verify independently |

This makes ACR's operational surface smaller: cheaper rotation, fewer moving parts in the verifier, and no catalog deployment dance.

## Spec conformance

The ACR v1 spec lives at https://github.com/dekimuhq/anchors-spec/tree/main/acr. This package's `src/` is the implementation source-of-truth for the wire format; any drift between code and spec is treated as a bug in the spec until resolved.

Test vectors will live at `verify.dekimu.com/acr/v1` once published; the in-tree test suite (`test/*.test.ts`) covers canonicalisation, commitment, chain walks, signature, Merkle, and disclosure scenarios.
