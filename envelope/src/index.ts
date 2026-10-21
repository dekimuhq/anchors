/**
 * Public API barrel for @dekimuhq/anchors-envelope.
 *
 * Sub-path exports:
 *   @dekimuhq/anchors-envelope/tsa    — TsaBlock type
 *   @dekimuhq/anchors-envelope/status — CredentialStatus type
 */

// Types
export type {
  ClaimType,
  Envelope,
  AnchorProof,
  TsaBlock,
  CredentialStatus,
  Kind,
  Cause,
  SigAlg,
  IssuerKeyRef,
} from "./envelope-types.ts";

// Runtime const (needed for smoke test + runtime discriminator checks)
export { CLAIM_TYPES, KIND_VALUES, CAUSE_VALUES, SIG_ALGS } from "./envelope-types.ts";

// v1.2: JSON Logic predicate surface.
export type {
  JsonLogicAtom,
  JsonLogicValue,
  JsonLogicAst,
} from "./jsonlogic-types.ts";
export {
  JSON_LOGIC_ALLOWLIST_V1_2,
} from "./jsonlogic-allowlist.ts";
export type { JsonLogicOperator } from "./jsonlogic-allowlist.ts";

// v1.2: Predicate AST validator (Phase C).
export { validate as validatePredicate } from "./jsonlogic-validate.ts";
export type {
  ValidateErrorCode,
  ValidateOk,
  ValidateErr,
  ValidateResult,
} from "./jsonlogic-validate.ts";

// v1.2: Predicate evaluator (Phase B) + error classes.
export {
  evaluate as evaluatePredicate,
  JsonLogicError,
  JsonLogicDivisionByZero,
  JsonLogicModuloByZero,
  JsonLogicVarPathInvalid,
} from "./jsonlogic-eval.ts";
export type { JsonLogicErrorCode } from "./jsonlogic-eval.ts";

// v1.2: Verifier-side composable checks (Phase D).
export {
  checkIatMs,
  checkPredicate,
} from "./predicate-verify.ts";
export type {
  PredicateReasonCode,
  PredicateCheckOk,
  PredicateCheckErr,
  PredicateCheckResult,
} from "./predicate-verify.ts";

// Functions
// Task 3: canonicalizeEnvelope + preSigCanonical + signEnvelope
// Task 4: verifyEnvelopeSignature + isKnownClaimType + rejectUnknownFields
// Note: sign (Task 1 alias) and verify (Task 3 stub) are removed — use canonical names.
export {
  canonicalizeEnvelope,
  preSigCanonical,
  signEnvelope,
  signEnvelopeSig2,
  verifyEnvelopeSignature,
  verifyEnvelopeSig2,
  verifyEnvelopeHybrid,
  keyBytesFromKeyRef,
  SIG_ALG_RANK,
  isKnownClaimType,
  rejectUnknownFields,
  isSupportedSigAlg,
} from "./envelope.ts";
export type { HybridVerifyResult } from "./envelope.ts";

// Raw RFC 8785 / JCS canonical JSON (value: unknown) → string.
// Previously unreachable via the barrel due to name collision with the
// envelope-aware wrapper. Now both are accessible.
export { canonicalize } from "./canonicalize.ts";

// Base64url helpers (needed by verify and consumer packages)
export { base64UrlEncode, base64UrlDecode } from "./base64url.ts";

// Task 14: per-claim-type policy field validation matrix.
export {
  validatePolicyFields,
  fetchAndCheckPolicy,
  POLICY_BOUND,
} from "./policy.ts";
export type { PolicyValidationResult } from "./policy.ts";

// Phase E Task E.2: profile-validator dispatch surface (also available via
// `@dekimuhq/anchors-envelope/profile` sub-path export).
export type {
  ProfileValidatorCtx,
  ProfileStateEntry,
  ProfileValidator,
} from "./profile/types.ts";
export { dispatchProfiles } from "./profile/dispatch.ts";

// Ed25519 key helpers + canonical sign/verify (Task 1.3) — hoisted from per-family
// keys.ts files. Consumed by every <family>-issuer-kit and by mintV2 (Task 1.6).
export type { Keypair } from "./ed25519.ts";
export {
  generateKeypair,
  publicKeyFromSeed,
  encodeRaw,
  decodeRaw32,
  signCanonical,
  verifyCanonical,
} from "./ed25519.ts";

// ML-DSA-65 (FIPS 204) key helpers + canonical sign/verify (v1.3 Phase 2) — the
// first post-quantum scheme in the sig_alg hook. Provider: native node:crypto on
// Node ≥24.6. Decision: an internal design record (not published)
export type { MlDsaKeypair, MlDsaSecretKey } from "./ml-dsa.ts";
export {
  MLDSA65_PUBKEY_BYTES,
  MLDSA65_SIG_BYTES,
  MLDSA65_SEED_BYTES,
  generateMlDsaKeypair,
  rawPublicKey,
  publicKeyFromRaw,
  encodeMlDsaIssKey,
  signMlDsaCanonical,
  verifyMlDsaCanonical,
  verifyMlDsaPreSig,
  seedFromPrivateKey,
  toMlDsaSecret,
  privateKeyFromSecret,
  serializeMlDsaSecret,
  deserializeMlDsaSecret,
} from "./ml-dsa.ts";

// defineFamily() factory (Phase A.1) — declarative family-member factory.
// Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
export { defineFamily } from "./define-family.ts";
export type {
  FamilyDefinition,
  FamilyManifest,
  FamilyMeta,
  FamilyCompositionConfig,
  BodyValidator,
  BodyValidateResult,
  SubjectPresence,
  SubjectPresenceResult,
  SubjectPresenceCheckInput,
  SubjectPresenceCheck,
  TsaUpgradePath,
  TsaMandateLevel,
  ComposeInput,
  ComposeResult,
  ComposeCallback,
} from "./define-family.ts";

// family-verify-pipeline (Phase A.2 Task 1.5) — generic verify orchestrator.
export { buildVerifyReceipt } from "./family-verify-pipeline.ts";
export type {
  FamilyVerifyOptions,
  FamilyVerifyResult,
  FamilyVerifyPredicates,
} from "./family-verify-pipeline.ts";

// Issuer-trust type-only surface (v0.8.0) — structural mirror of
// `@dekimuhq/did-web-resolver`'s trust types. Type-only by design so that
// envelope has no runtime dep on did-web-resolver (avoids a dep cycle since
// did-web-resolver depends on @dekimuhq/anchors-envelope for Envelope typing).
//
// Spec: an internal design record (not published)
export type {
  IssuerTrustOutcome,
  IssuerTrustResult,
  IssuerTrustResultValid,
  IssuerTrustResultInvalid,
  TrustedIssuerRecord,
  VerifyIssuerTrust,
  VerifyIssuerPqc,
  VerifyIssuerPqcInput,
  IssuerPqcVerdict,
} from "./issuer-trust.ts";

// family-mint-pipeline (Phase A.2 Task 1.6) — generic mint orchestrator.
export { buildMintV2 } from "./family-mint-pipeline.ts";
export type {
  FamilyMintV2Input,
  FamilyMintPredicates,
} from "./family-mint-pipeline.ts";

// Shared issuer-kit helpers (P0 abstraction) — ULID, Ed25519 seed import,
// field_root computation, SHA-256 hex validation. Lifted from 8 per-family
// mint-v2.ts files.
export {
  generateReceiptId,
  keyObjectFromSeed,
  keyObjectFromMlDsaSecret,
  computeFieldRoot,
  isSha256Hex,
} from "./mint-helpers.ts";

// continuity (Phase A.2 Task 1.8) — ar.continuity.v1 issuer key-rotation attestation.
export {
  issueContinuityAttestation,
  verifyContinuityAttestation,
} from "./continuity.ts";
export type {
  FamilySlug,
  ContinuitySealedMappingAlg,
  ContinuityAttestation,
  IssueContinuityInput,
  VerifyContinuityResult,
} from "./continuity.ts";

// RFC 6962 Merkle tree (shared with @dekimuhq/anchors-disclosure).
export { buildTree, inclusionProof, verifyInclusion, type MerkleTree } from "./merkle.ts";

// Salted commit primitive (shared with @dekimuhq/anchors-disclosure).
export { commit, verifyCommitment, randomSalt } from "./commit.ts";

// ar.field_commit.v1 — issuer-signed standalone field-root attestation (Phase 2 Tier A).
export {
  issueFieldCommit,
  verifyFieldCommit,
} from "./field-commit.ts";
export type {
  FieldCommitAttestation,
  IssueFieldCommitInput,
  VerifyFieldCommitResult,
} from "./field-commit.ts";

// Wave 3: suspension status support.
export type { SuspensionStatus } from "./envelope-types.ts";
export type { SuspensionCheck } from "./status/suspension-types.ts";
export { validateSuspensionStatusPointer } from "./status/suspension-pointer.ts";
export type { SuspensionStatusPointerResult } from "./status/suspension-pointer.ts";
export { attachSuspensionStatus, MAX_STATUS_INDEX as MAX_SUSPENSION_INDEX } from "./status/suspension-attach.ts";
export type { SuspensionListConfig } from "./status/suspension-attach.ts";
export { verifySuspensionStatus } from "./status/suspension-verify.ts";
export type { SuspensionVerifyOpts } from "./status/suspension-verify.ts";
