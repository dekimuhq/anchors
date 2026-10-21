/**
 * @dekimuhq/anchors-vc — W3C Verifiable Credential binding for Anchored Receipts.
 *
 * Carrier model: an anchored `ar.*` receipt rides verbatim inside a VC so
 * VC-native consumers (A2A / AP2 / MCP) can ingest it; the embedded envelope
 * stays the cryptographic root of trust. Additive, byte-equal, pure node:crypto.
 *
 * Design: an internal design record (not published)
 * Naming posture C (vs AP2 mandates): receipt-OF, never is-a; ADR is the
 * artifact name that travels.
 */

export {
  VC_CONTEXT_V2,
  ANCHORS_VC_CONTEXT,
  ANCHORED_RECEIPT_CREDENTIAL_TYPE,
} from "./types.ts";
export type {
  AnchoredReceiptCredential,
  AnchoredReceiptEvidence,
  AnchoredCredentialSubject,
  ActCredentialSubject,
  DataCredentialSubject,
  DataIntegrityProof,
} from "./types.ts";

export { toVerifiableCredential, isSubjectless } from "./wrap.ts";
export type { ToVcOptions } from "./wrap.ts";

export { extractEnvelope, isAnchoredReceiptCredential, AnchorsVcError } from "./unwrap.ts";

export { attachWrapperProof, verifyWrapperProof, WRAPPER_CRYPTOSUITE } from "./proof.ts";
export type { AttachProofOpts, VerifyProofResult } from "./proof.ts";

export {
  publicKeyFromIssKey,
  verificationMethodFor,
  resolveWrapperKey,
} from "./did.ts";

export { verifyCredential } from "./verify.ts";
export type {
  VerifyCredentialOptions,
  VerifyCredentialResult,
  WrapperProofState,
} from "./verify.ts";
// Q4 RESOLVED: subjectless detection is `subject === null` (verified vs
// FAMILY-CONSISTENCY §3 + family verifiers) — no per-family sentinel table.
