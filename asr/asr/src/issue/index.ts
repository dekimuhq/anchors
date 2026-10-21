/**
 * @dekimuhq/asr/issue — thin re-export over `asrFamily.mintV2`.
 *
 * Phase 3 greenfield via `defineFamily()`. The factory owns the mint
 * pipeline; this package only re-exports the bound function plus a
 * convenience pass-through to envelope's keypair helper.
 */

export { mintAsrV2 } from "./mint-v2.ts";
export { generateKeypair } from "@dekimuhq/anchors-envelope";
export { generateIssuerKey, encodePublicKey } from "./keys.ts";
export { asrFamily } from "../family.ts";

// `ar.continuity.v1` — issuer key rotation. Family-shared shape re-exported
// from `@dekimuhq/anchors-envelope/continuity`.
// Callers MUST pass `family: "asr"` to `issueContinuityAttestation`.
export {
  issueContinuityAttestation,
  verifyContinuityAttestation,
  type ContinuityAttestation,
  type IssueContinuityInput,
  type VerifyContinuityResult,
  type FamilySlug,
  type ContinuitySealedMappingAlg,
} from "@dekimuhq/anchors-envelope/continuity";
export type { SuspensionListConfig, FamilyMintV2Input } from "@dekimuhq/anchors-envelope";
