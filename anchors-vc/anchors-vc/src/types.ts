/**
 * W3C Verifiable Credential carrier types for the Anchored Receipts family.
 *
 * Design decision (resolves the 5 open Qs):
 *   an internal design record (not published)
 *
 * The VC is a CARRIER (Q1): the full anchored `Envelope` rides verbatim in
 * `evidence[0].envelope` and remains the cryptographic root of trust. A minimal,
 * lossless set of envelope fields is lifted to VC top-level so standard VC
 * tooling works. The envelope `sig` is NEVER reused as the VC `proof` (Q2) — the
 * envelope signature covers the envelope canonical bytes, not the VC wrapper.
 */

import type {
  Envelope,
  ClaimType,
  CredentialStatus,
  SuspensionStatus,
} from "@dekimuhq/anchors-envelope";

/** W3C VC Data Model 2.0 base context. */
export const VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2" as const;

/** Anchors VC binding context (term definitions for the carrier shape). */
export const ANCHORS_VC_CONTEXT = "https://anchors.dekimu.com/ns/vc/v1" as const;

/** Second `type` entry marking an anchored-receipt carrier credential. */
export const ANCHORED_RECEIPT_CREDENTIAL_TYPE = "AnchoredReceiptCredential" as const;

/**
 * The embedded anchored receipt, carried verbatim (Q1). The `envelope` is the
 * cryptographic root of trust — verify it with the family's existing verifier on
 * `extractEnvelope(vc)`. `anchorLog` / `treeHeadRoot` are human-legible anchoring
 * descriptors only (Q3) — NEVER a VC proof.
 */
export interface AnchoredReceiptEvidence {
  type: ["AnchoredReceipt"];
  /** The entire `Envelope`, untouched. Byte-equal to the minted receipt. */
  envelope: Envelope;
  /** Canonical anchor-log URL surfaced for audit legibility (not a proof). */
  anchorLog?: string;
  /** `sha256:<hex>` Merkle root surfaced for audit legibility (not a proof). */
  treeHeadRoot?: string;
}

/**
 * OPTIONAL Data Integrity proof over the VC wrapper (Q2, layer 2). Signed by the
 * SAME issuer key as the envelope but over the wrapper bytes — lets a pure-VC
 * verifier validate issuer + wrapper integrity without understanding anchors
 * envelopes. Absent ⇒ trust comes solely from the embedded envelope.
 */
export interface DataIntegrityProof {
  type: "DataIntegrityProof";
  /** `eddsa-jcs-2022` for ed25519. PQC suite documented but unregistered (mirrors envelope sig_alg posture). */
  cryptosuite: string;
  created: string;
  verificationMethod: string;
  proofPurpose: "assertionMethod";
  /** base64url signature over the RFC 8785 JCS canonical wrapper (proof removed). */
  proofValue: string;
}

/** Subject of a subjectless (act/output) receipt — no `id` (Q4). */
export interface ActCredentialSubject {
  /** The receipt id this credential is about. */
  receipt: string;
  /** The anchored claim type. */
  claimType: ClaimType;
}

/** Subject of a data-subject receipt — `id` lifted from `envelope.subject` (Q4). */
export interface DataCredentialSubject {
  id: string;
}

export type AnchoredCredentialSubject = ActCredentialSubject | DataCredentialSubject;

/**
 * Anchored Receipt Verifiable Credential — the carrier.
 */
export interface AnchoredReceiptCredential {
  "@context": [typeof VC_CONTEXT_V2, ...string[]];
  type: ["VerifiableCredential", typeof ANCHORED_RECEIPT_CREDENTIAL_TYPE];
  /** Lifted from `envelope.iss` (a DID or self-describing key id). */
  issuer: string;
  /** Lifted from `envelope.iat`. */
  validFrom: string;
  /** Lifted from `envelope.exp` when non-null. */
  validUntil?: string;
  credentialSubject: AnchoredCredentialSubject;
  /**
   * Lifted 1:1 from the envelope's W3C `StatusList2021Entry` (Q4). When both
   * revocation and suspension pointers are present, both are carried as an array.
   */
  credentialStatus?:
    | CredentialStatus
    | SuspensionStatus
    | Array<CredentialStatus | SuspensionStatus>;
  evidence: [AnchoredReceiptEvidence];
  proof?: DataIntegrityProof;
}
