# `@dekimuhq/arr-profiles`

Regulation profile validators for **ARR v1**. A profile binds a generic retention receipt to a specific regulatory framing — confirming that the receipt carries the fields, semantics, and combinations a downstream auditor working under that regulation would expect.

- **Licence:** Apache 2.0.
- **Status:** v0.8.2 — published.
- **Pairs with:** [`@dekimuhq/arr`](../arr) — the consolidated family package: verification at the root export, issuance at its `./issue` subpath.
- **Spec:** https://github.com/dekimuhq/anchors-spec/tree/main/arr §5.

## Install

```bash
npm install @dekimuhq/arr-profiles
```

Node ≥22.

## Why profiles exist

The ARR core spec defines a generic retention-lifecycle receipt shape — a kind (erasure / expiry / hold / anonymisation / pseudonymisation / archive), a profile tag, an issuer DID, a target commitment, a policy hash, a trigger, an `event_at` timestamp, a state snapshot, optional anchor and chain pointers, and a signature. That shape works for any regulator, but it does NOT enforce regulator-specific fitness on its own.

Profile validators do that enforcement. `validateGdprArt17(receipt)` checks that an erasure receipt carries the fields a GDPR Art. 17 auditor needs: a terminal kind (`erased` or `anonymized`), a `subject_data_categories` field listing what was removed, and a `controller_contact_hash` so the subject knows whom to query for confirmation.

Validators return a `ProfileValidationResult` — `valid: boolean` plus `errors: string[]`. They never throw.

## Validators

| Validator | Profile tag | Mode pinning | Purpose |
|---|---|---|---|
| `validateGdprArt17` | `gdpr.art17` | Mode A (chain-authoritative) | Right to erasure — terminal kind + subject_data_categories + controller_contact_hash |
| `validateGdprArt5e` | `gdpr.art5e` | Mode B (batch-authoritative) | Storage limitation — retention window arithmetic against `event_at` |
| `validateHipaaRetention` | `hipaa.retention` | Mode A | HIPAA retention windows |
| `validateKycRetention` | `kyc.retention` | unpinned | KYC/AML retention windows |
| `validateSoxRetention` | `sox.retention` | unpinned | SOX records retention |
| `validateMifid2Retention` | `mifid2.retention` | unpinned | MiFID II records retention |
| `validateAiActArt10` | `aiact.art10` | unpinned (APR cross-reference) | EU AI Act Art. 10 training-data retention |

## Mode pinning

ARR v1 supports two operating modes per profile:

- **Mode A — chain-authoritative.** The per-target chain is the single source of truth. Batch receipts are summaries; the chain decides. Used where individual-target audit trails matter (GDPR Art. 17, HIPAA).
- **Mode B — batch-authoritative.** The batch receipt is the single source of truth. The per-target chain may exist as a convenience but is not load-bearing. Used where bulk operations dominate and individual-target reconstructibility from the chain is not required (GDPR Art. 5(e) bulk retention sweeps).

Profile validators enforce mode pinning where it's set: `validateGdprArt17` rejects receipts presented as batch-authoritative; `validateGdprArt5e` accepts both but flags ambiguity. Unpinned profiles accept whichever mode the issuer chose.

## Use

```ts
import { validateGdprArt17, validateGdprArt5e } from "@dekimuhq/arr-profiles";

// Run alongside verifySingleReceipt — signature OK + profile OK = regulator-fit.
const sigResult = verifySingleReceipt(receipt, { anchorInclusionTime });
const profileResult = validateGdprArt17(receipt);

if (sigResult.valid && profileResult.errors.length === 0) {
  // safe to claim "this receipt evidences a GDPR-Art.17-conformant erasure"
}

if (profileResult.errors.length > 0) {
  console.error("profile validation errors:", profileResult.errors);
}
```

## API

```ts
import {
  validateGdprArt17,
  validateGdprArt5e,
  validateHipaaRetention,
  validateKycRetention,
  validateSoxRetention,
  validateMifid2Retention,
  validateAiActArt10,
  type ProfileValidationResult,
} from "@dekimuhq/arr-profiles";

interface ProfileValidationResult {
  valid: boolean;
  errors: string[];
}
```

## What this package is NOT

- **Not the full set of profiles ARR will ship.** v1 ships 7 profiles covering GDPR, HIPAA, KYC, SOX, MiFID II, and the AI Act. More follow as they're specced — likely candidates: PCI-DSS retention, NIS2 incident retention, ePrivacy cookie data.
- **Not a substitute for a real regulator's audit.** A passing profile validator means the receipt's *shape and field semantics* are consistent with the regulation — not that the underlying retention operation was lawful, that the controller had standing, or that downstream backup-and-restore obligations are met.
- **Not opinionated about chains.** Profile validators run on individual receipts. To evaluate "did this target's retention chain reach a terminal state in time," combine the profile validator with `resolveTargetChain` from `@dekimuhq/arr`.
