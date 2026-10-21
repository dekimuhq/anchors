# `@dekimuhq/acr-profiles`

Regulation profile validators for **ACR v1**. A profile binds a generic ACR receipt to a specific regulatory framing — confirming that the receipt carries the fields, semantics, and combinations a downstream auditor working under that regulation would expect.

- **Licence:** Apache 2.0.
- **Status:** v0.7.0 — published.
- **Pairs with:** [`@dekimuhq/acr`](../acr) — the consolidated family package: verification at the root export, issuance at its `./issue` subpath.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/acr §5.

## Install

```bash
npm install @dekimuhq/acr-profiles
```

Node ≥22.

## Why profiles exist

The ACR core spec defines a generic consent receipt shape — a kind, a profile tag, an issuer DID, salted commitments for subject + purposes + policy hash, a lawful-basis string, and a signature. That shape works for any regulator, but it does NOT enforce regulator-specific fitness on its own.

Profile validators do that enforcement. `validateGdprArt7(receipt)` checks that the receipt's profile tag, lawful basis, and field shape are consistent with GDPR Art. 7 (consent specificity, recordkeeping for proof of consent, withdrawal capability). `validateAiActArt14(receipt)` decodes the pipe-delimited `oversight_action | apr_receipt_hash | reviewer_role_commit` triple packed into `lawful_basis` and checks each component.

Validators return a `ValidationResult` — `valid: boolean` plus `errors: string[]`. They never throw.

## Validators

| Validator | Profile tag | What it checks |
|---|---|---|
| `validateGdprArt7` | `gdpr.art7` | GDPR Art. 7 consent specificity, lawful-basis under Art. 6(1)(a), `policy_hash` present, at least one purpose |
| `validateAiActArt14` | `aiact.art14` | EU AI Act Art. 14 human-oversight — decodes the `oversight_action \| apr_receipt_hash \| reviewer_role_commit` triple from `lawful_basis` (v1 wire encoding; see spec §5.2) |

## Use

```ts
import { validateGdprArt7, validateAiActArt14 } from "@dekimuhq/acr-profiles";

// Run alongside `verifyReceiptSignature` — signature OK + profile OK = regulator-fit.
const sigOk = verifyReceiptSignature(receipt);
const profileOk = validateGdprArt7(receipt);

if (sigOk && profileOk.valid) {
  // safe to claim "this receipt evidences a GDPR-Art.7-conformant consent"
}

if (!profileOk.valid) {
  console.error("profile validation errors:", profileOk.errors);
}
```

## AI Act Art. 14 — wire encoding note

The spec §5.2 v1 encoding packs three logical fields into the existing `lawful_basis` slot via a pipe-delimited string: `oversight_action | apr_receipt_hash | reviewer_role_commit`. This avoids introducing a new nested object in the canonical JSON before RFC 8785 canonicalisation rules for such nesting are themselves settled.

A future spec revision will reserve a structured `oversight` JSON object (see spec §5.2 "v1 wire encoding" note). `validateAiActArt14` will accept both shapes transparently when the structured form lands; receipts minted today against the pipe-delimited form remain valid.

## API

```ts
import { validateGdprArt7, validateAiActArt14, type ValidationResult } from "@dekimuhq/acr-profiles";

interface ValidationResult {
  valid: boolean;
  errors: string[];
}
```

## What this package is NOT

- **Not the full set of profiles ACR will ship.** v1 ships `gdpr.art7` and `aiact.art14`; more (HIPAA consent, ePrivacy, sector-specific) follow as they're specced.
- **Not a substitute for a real regulator's audit.** A passing profile validator means the receipt's *shape and field semantics* are consistent with the regulation — not that the underlying consent flow is lawful, that the controller has standing, or that the data-processing operation itself is compliant.
- **Not opinionated about chains.** Profile validators run on individual receipts. To evaluate "is this consent currently active under Art. 7," combine the profile validator with `resolveChainState` from `@dekimuhq/acr`.
