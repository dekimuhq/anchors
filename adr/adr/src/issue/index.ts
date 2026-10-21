export * from "./keys.ts";
export * from "./mint-v2.ts";
export * from "./mint-single.ts";

// `ar.continuity.v1` — issuer key rotation. Family-shared shape re-exported
// from `@dekimuhq/anchors-envelope/continuity`.
// Callers MUST pass `family: "adr"` to `issueContinuityAttestation`.
export {
  issueContinuityAttestation,
  verifyContinuityAttestation,
  type ContinuityAttestation,
  type IssueContinuityInput,
  type VerifyContinuityResult,
  type FamilySlug,
  type ContinuitySealedMappingAlg,
} from "@dekimuhq/anchors-envelope/continuity";
