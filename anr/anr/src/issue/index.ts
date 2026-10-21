// @dekimuhq/anr/issue — issuance public surface (consolidated issuer-kit subpath; formerly the standalone @dekimuhq/anr-issuer-kit).

export * from "./keys.ts";
export * from "./mint-v2.ts";
export * from "./mint-single.ts";
export { mintAnrV2Disclosable, type DisclosableMintResult } from "./mint-disclosable.ts";
// `ar.continuity.v1` — issuer key rotation. Promoted to the family-shared
// shape in `@dekimuhq/anchors-envelope/continuity` (v0.7.0).
// Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope.
// Callers MUST pass `family: "anr"` to `issueContinuityAttestation`.
export {
  issueContinuityAttestation,
  verifyContinuityAttestation,
  type ContinuityAttestation,
  type IssueContinuityInput,
  type VerifyContinuityResult,
  type FamilySlug,
  type ContinuitySealedMappingAlg,
} from "@dekimuhq/anchors-envelope/continuity";
