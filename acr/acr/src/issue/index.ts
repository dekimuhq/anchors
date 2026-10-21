/**
 * `@dekimuhq/acr/issue` — issuance helpers for Anchored Consent Receipts (ACR) v1.
 *
 * The consolidated `@dekimuhq/acr` package's issuer-kit subpath (formerly the
 * standalone `@dekimuhq/acr-issuer-kit`); pairs with the verifier at the root export.
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/acr
 */

export {
  generateKeypair,
  generateIssuerKey,
  encodePublicKey,
  publicKeyFromSeed,
  encodeRaw,
  decodeRaw32,
} from "./keys.ts";
export type { Keypair } from "./keys.ts";

export { mintConsent, mintModification, mintWithdrawal } from "./mint.ts";
export type { SaltBundle } from "./mint.ts";

export { buildDisclosureProof } from "./disclose.ts";

export { mintAcrV2, TsaMintError } from "./mint-v2.ts";
export type { MintAcrV2Input, AcrV2Kind, AcrV2Body, StatusListConfig, SuspensionListConfig } from "./mint-v2.ts";

// `ar.continuity.v1` — issuer key rotation. Family-shared shape re-exported
// from `@dekimuhq/anchors-envelope/continuity`.
// Callers MUST pass `family: "acr"` to `issueContinuityAttestation`.
export {
  issueContinuityAttestation,
  verifyContinuityAttestation,
  type ContinuityAttestation,
  type IssueContinuityInput,
  type VerifyContinuityResult,
  type FamilySlug,
  type ContinuitySealedMappingAlg,
} from "@dekimuhq/anchors-envelope/continuity";

// Re-export read-side types so callers don't need two imports.
export type {
  ACRReceipt,
  AcrKind,
  AcrProfile,
  AcrAnchor,
  FieldDisclosure,
  DisclosureProof,
} from "../index.ts";
