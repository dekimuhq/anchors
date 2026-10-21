/**
 * AUTO-GENERATED from ar.consent.v1.anchor.json
 * Generated: [TIMESTAMP]
 *
 * Do not edit manually — re-run `npm run generate` to regenerate.
 * Manual edits will be lost on next generation.
 */

/** Claim type discriminators for ACR. */
export type ACRClaimType =
  | "ar.consent.v1"
  | "ar.modification.v1"
  | "ar.withdrawal.v1";

/** Event types for ACR. */
export type ACREventType =
  | "consent.given"
  | "consent.modified"
  | "consent.withdrawn";

/** Regulation profiles for ACR. */
export type ACRProfile =
  | "gdpr.art7"
  | "aiact.art14"
  | "hipaa.auth"
  | "kyc.consent"
  | "mifid2.suit"
  | "esig.accept"
  | "gdpr.train";

/** Body fields for ACR receipts. */
export interface ACRBody {
  profile: "gdpr.art7" | "aiact.art14" | "hipaa.auth" | "kyc.consent" | "mifid2.suit" | "esig.accept" | "gdpr.train";
  /** Salted commitment to subject identifier. */
  sub_commit: string;
  /** Salted commitments to purpose descriptors. */
  purposes: readonly string[];
  /** Profile-specific lawful basis, e.g. 6(1)(a). */
  lawful_basis: string;
  /** SHA-256 of the consented policy document. */
  policy_hash: string;
  /** RFC 3339 timestamp. */
  granted_at: string;
  /** RFC 3339 timestamp. */
  expires_at?: string;
  /** Hash of prior receipt for modification/withdrawal. */
  prev: string | null;
  /** Merkle root over salted per-field commitments. */
  field_root: string;
  /** Optional subject countersignature (reserved for EUDI Wallet). */
  countersig: string | null;
  /** `sha256:<hex>` */
  qts_attestation_hash: string | null;
}
