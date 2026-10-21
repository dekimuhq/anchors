export * from "./types.ts";
export * from "./gdpr-art17.ts";
export * from "./gdpr-art5e.ts";
export * from "./hipaa-retention.ts";
export * from "./kyc-retention.ts";
export * from "./sox-retention.ts";
export * from "./mifid2-retention.ts";
export * from "./aiact-art10.ts";

// Universal-signature adapters for v=2 `opts.profile` dispatch.
//
// `gdpr.art17.erasure-finalized` (Phase E Task E.2) validates `kind` + TSA
// posture only. The six retention profiles (2026-05-30) read profile-specific
// body fields, now carried in the additive `body.profile_attributes` slot
// (`ArrProfileAttributes`); their adapters reconstruct the flat receipt shape
// via `toReceipt`. All seven are registered in `arrFamily.profiles{}`.
export {
  validateGdprArt17ErasureFinalizedProfile,
  GDPR_ART17_ERASURE_FINALIZED_PROFILE_ID,
} from "./gdpr-art17-finalized-adapter.ts";
export {
  validateGdprArt5eProfile,
  validateHipaaRetentionProfile,
  validateKycRetentionProfile,
  validateSoxRetentionProfile,
  validateMifid2RetentionProfile,
  validateAiActArt10Profile,
  GDPR_ART5E_PROFILE_ID,
  HIPAA_RETENTION_PROFILE_ID,
  KYC_RETENTION_PROFILE_ID,
  SOX_RETENTION_PROFILE_ID,
  MIFID2_RETENTION_PROFILE_ID,
  AIACT_ART10_PROFILE_ID,
} from "./retention-profile-adapters.ts";
