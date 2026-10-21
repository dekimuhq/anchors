/**
 * `@dekimuhq/acr-profiles` — regulation profiles for ACR v1.
 */

export { validateGdprArt7 } from "./gdpr-art7.ts";
export { validateAiActArt14 } from "./aiact-art14.ts";
export { validateGdprTrain } from "./gdpr-train.ts";
export type { ValidationResult } from "./gdpr-art7.ts";

// Phase D Task 21: profile descriptors + mandate enforcement
export type { ProfileDescriptor } from "./types.ts";
export {
  ESIG_ACCEPT_QES_DESCRIPTOR,
  validateEsigAcceptQes,
} from "./esig-accept.ts";
export type {
  EsigAcceptQesReceipt,
  EsigAcceptQesCtx,
} from "./esig-accept.ts";

// Phase E Task E.2: universal-signature adapter for verifier dispatch.
export {
  validateEsigAcceptQesProfile,
  ESIG_ACCEPT_QES_PROFILE_ID,
} from "./esig-accept-adapter.ts";
