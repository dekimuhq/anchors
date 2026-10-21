// @dekimuhq/abr/issue — issuance public surface (consolidated issuer-kit subpath; formerly the standalone @dekimuhq/abr-issuer-kit).

export * from "./keys.ts";
export * from "./mint-v2.ts";
export * from "./mint-single.ts";
export { mintAbrV2Disclosable, type DisclosableMintResult } from "./mint-disclosable.ts";
// `ar.continuity.v1` — issuer key rotation. Family-shared shape re-exported
// from `@dekimuhq/anchors-envelope/continuity` (v0.7.0).
// Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope.
// Callers MUST pass `family: "abr"` to `issueContinuityAttestation`.
export {
  issueContinuityAttestation,
  verifyContinuityAttestation,
  type ContinuityAttestation,
  type IssueContinuityInput,
  type VerifyContinuityResult,
  type FamilySlug,
  type ContinuitySealedMappingAlg,
} from "@dekimuhq/anchors-envelope/continuity";
