/**
 * AUTO-GENERATED from ar.tokenization.v1.anchor.json
 * Generated: [TIMESTAMP]
 *
 * Do not edit manually — re-run `npm run generate` to regenerate.
 * Manual edits will be lost on next generation.
 */

/** Claim type discriminators for ATokR. */
export type ATokRClaimType =
  | "ar.tokenization.v1";

/** Event types for ATokR. */
export type ATokREventType =
  | "token.issued"
  | "token.redeemed"
  | "token.revoked"
  | "token.rotated";

/** Regulation profiles for ATokR. */
export type ATokRProfile =
  | "tokenization.gdpr.art32"
  | "tokenization.gdpr.art4_5"
  | "tokenization.pci.dss_v4"
  | "tokenization.eudi.wallet_arf"
  | "tokenization.sector.health";

/** Body for ATokR "token.issued" events. */
export interface ATokRTokenIssuedBody {
  event_type: "token.issued";
  token_id: string;
  format_class: "pan" | "email" | "iban" | "phone" | "national_id" | "freeform";
  scope: {
    audience: string;
    purpose: string;
    valid_from: string;
    valid_until: string | null;
    single_use: boolean;
  };
  /** Token ID of the predecessor (for token.rotated). */
  rotation_of: string | null;
  redemption_audit_ref: string | null;
  /** ASR receipt hash for subject-rights linkage. */
  asr_ref: string | null;
  /** ARR receipt hash for retention linkage. */
  arr_ref: string | null;
  /** ALR receipt hash for lineage linkage. */
  alr_ref: string | null;
  /** APuR receipt hash for purpose binding. */
  apur_ref: string | null;
  /** `sha256:<hex>` */
  qts_attestation_hash: string | null;
}

/** Body for ATokR "token.redeemed" events. */
export interface ATokRTokenRedeemedBody {
  event_type: "token.redeemed";
  token_id: string;
  format_class: "pan" | "email" | "iban" | "phone" | "national_id" | "freeform";
  scope: {
    audience: string;
    purpose: string;
    valid_from: string;
    valid_until: string | null;
    single_use: boolean;
  };
  /** Token ID of the predecessor (for token.rotated). */
  rotation_of: string | null;
  redemption_audit_ref: string | null;
  /** ASR receipt hash for subject-rights linkage. */
  asr_ref: string | null;
  /** ARR receipt hash for retention linkage. */
  arr_ref: string | null;
  /** ALR receipt hash for lineage linkage. */
  alr_ref: string | null;
  /** APuR receipt hash for purpose binding. */
  apur_ref: string | null;
  /** `sha256:<hex>` */
  qts_attestation_hash: string | null;
}

/** Body for ATokR "token.revoked" events. */
export interface ATokRTokenRevokedBody {
  event_type: "token.revoked";
  token_id: string;
  format_class: "pan" | "email" | "iban" | "phone" | "national_id" | "freeform";
  scope: {
    audience: string;
    purpose: string;
    valid_from: string;
    valid_until: string | null;
    single_use: boolean;
  };
  /** Token ID of the predecessor (for token.rotated). */
  rotation_of: string | null;
  redemption_audit_ref: string | null;
  /** ASR receipt hash for subject-rights linkage. */
  asr_ref: string | null;
  /** ARR receipt hash for retention linkage. */
  arr_ref: string | null;
  /** ALR receipt hash for lineage linkage. */
  alr_ref: string | null;
  /** APuR receipt hash for purpose binding. */
  apur_ref: string | null;
  /** `sha256:<hex>` */
  qts_attestation_hash: string | null;
}

/** Body for ATokR "token.rotated" events. */
export interface ATokRTokenRotatedBody {
  event_type: "token.rotated";
  token_id: string;
  format_class: "pan" | "email" | "iban" | "phone" | "national_id" | "freeform";
  scope: {
    audience: string;
    purpose: string;
    valid_from: string;
    valid_until: string | null;
    single_use: boolean;
  };
  /** Token ID of the predecessor (for token.rotated). */
  rotation_of: string | null;
  redemption_audit_ref: string | null;
  /** ASR receipt hash for subject-rights linkage. */
  asr_ref: string | null;
  /** ARR receipt hash for retention linkage. */
  arr_ref: string | null;
  /** ALR receipt hash for lineage linkage. */
  alr_ref: string | null;
  /** APuR receipt hash for purpose binding. */
  apur_ref: string | null;
  /** `sha256:<hex>` */
  qts_attestation_hash: string | null;
}

/** Discriminated union of all ATokR body variants. */
export type ATokRBody =
  | ATokRTokenIssuedBody
  | ATokRTokenRedeemedBody
  | ATokRTokenRevokedBody
  | ATokRTokenRotatedBody;
