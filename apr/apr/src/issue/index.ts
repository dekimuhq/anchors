/**
 * `@dekimuhq/apr/issue` — reference helpers for issuing APRs.
 *
 * The consolidated `@dekimuhq/apr` package's issuer-kit subpath (formerly the
 * standalone `@dekimuhq/apr-issuer-kit`); pairs with the verifier at the root
 * export. Spec: https://github.com/dekimuhq/anchors-spec/tree/main/apr
 */

export { mint } from "./mint.ts";
export type { MintInput, SigningKey } from "./mint.ts";

export {
  generateKeypair,
  generateIssuerKey,
  encodePublicKey,
  publicKeyFromSeed,
  encodeRaw,
  decodeRaw32,
} from "./keys.ts";
export type { Keypair } from "./keys.ts";

// Re-export types issuers will frequently need from the verifier package, so
// downstream users don't have to import from two places to assemble a body.
export type { APRBody, APRClaim, APRDisclosure } from "../types.ts";

// v=2 mint path (Phase B Task 12b).
export { mintAprV2, TsaMintError } from "./mint-v2.ts";
export type { MintAprV2Input } from "./mint-v2.ts";

// `ar.continuity.v1` — issuer key rotation. Family-shared shape re-exported
// from `@dekimuhq/anchors-envelope/continuity`.
// Callers MUST pass `family: "apr"` to `issueContinuityAttestation`.
export {
  issueContinuityAttestation,
  verifyContinuityAttestation,
  type ContinuityAttestation,
  type IssueContinuityInput,
  type VerifyContinuityResult,
  type FamilySlug,
  type ContinuitySealedMappingAlg,
} from "@dekimuhq/anchors-envelope/continuity";
