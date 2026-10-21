export type ArrSingleKind =
  | "ar.erasure.v1"
  | "ar.expiry.v1"
  | "arr.hold_extension.v1"
  | "arr.hold_release.v1"
  | "ar.anonymization.v1"
  | "arr.pseudonymization.v1"
  | "ar.archive.v1";

export type ArrBatchEventKind = ArrSingleKind;

export type ArrKind = ArrSingleKind | "ar.batch.v1";

export type ArrProfile =
  | "gdpr.art17"
  | "gdpr.art5e"
  | "hipaa.retention"
  | "kyc.retention"
  | "sox.retention"
  | "mifid2.retention"
  | "aiact.art10";

export type ArrTrigger =
  | "subject_request"
  | "scheduled"
  | "legal_order"
  | "regulator_order"
  | "operator";

export type ArrTargetKind = "subject" | "artifact";

export type ArrRetentionStatus =
  | "active"
  | "erased"
  | "expired"
  | "archived"
  | "anonymized"
  | "pseudonymized";

export interface ArrStateSnapshot {
  retention_status: ArrRetentionStatus;
  current_policy_hash: string;
  hold_active: boolean;
  hold_reason_commit: string | null;
  anonymized: boolean;
  archived: boolean;
}

export interface ArrAnchor {
  log: string;
  leaf_index: number;
  inclusion_proof: string[];
}

export interface ARRReceipt {
  kind: ArrSingleKind;
  profile: ArrProfile;
  iss: string;
  iss_key: string;
  target_kind: ArrTargetKind;
  target_commit: string;
  salt_epoch: string;
  policy_hash: string;
  policy_uri: string;
  policy_version: string;
  trigger: ArrTrigger;
  trigger_receipt: string | null;
  event_at: string;
  granted_at: string;
  effective_until: string | null;
  state_snapshot: ArrStateSnapshot;
  prev: string | null;
  field_root: string;
  anchor: ArrAnchor | null;
  sig: string | null;
  /**
   * SHA-256 hash of an AAR receipt attesting QTS posture (`null` when absent).
   * Optional on the v1 receipt: the legacy mint path predates QTS attestation
   * and omits it, so it must not be required (v1 minted output is locked /
   * byte-equal). The v2 body (`ArrV2SingleBody`) carries it required.
   */
  qts_attestation_hash?: string | null;
  [extra: string]: unknown;
}

export interface ARRBatchReceipt {
  kind: "ar.batch.v1";
  profile: ArrProfile;
  iss: string;
  iss_key: string;
  batch_event_kind: ArrBatchEventKind;
  target_kind: ArrTargetKind;
  target_root: string;
  target_count: number;
  salt_epoch: string;
  policy_hash: string;
  policy_uri: string;
  policy_version: string;
  trigger: ArrTrigger;
  trigger_receipt: string | null;
  event_at: string;
  granted_at: string;
  effective_until: string | null;
  state_snapshot_root: string;
  field_root: string;
  anchor: ArrAnchor | null;
  sig: string | null;
  /** SHA-256 hash of an AAR receipt attesting QTS posture (`null` when absent). Optional on v1 — see `ARRReceipt`. */
  qts_attestation_hash?: string | null;
  [extra: string]: unknown;
}

export type AnyARRReceipt = ARRReceipt | ARRBatchReceipt;

export type Mifid2InstrumentClass = "equity" | "derivative" | "bond" | "other";

/**
 * Optional profile-specific attributes carried in a v=2 ARR body (additive —
 * omitted when no regulated retention profile applies; existing receipts stay
 * byte-equal). Rides in the body alongside `qts_attestation_hash`, outside
 * `field_root`, covered by the envelope signature.
 *
 * Each registered retention `ProfileValidator` (gdpr.art5e, hipaa.retention,
 * kyc.retention, sox.retention, mifid2.retention, aiact.art10) reads the subset
 * it needs. All fields optional so one body shape serves every profile.
 */
export interface ArrProfileAttributes {
  // gdpr.art5e (storage limitation)
  retention_basis_commit?: string;
  original_collection_at?: string;
  // hipaa.retention / sox.retention / mifid2.retention / aiact.art10 (shared origin clock)
  record_origin_at?: string;
  // hipaa.retention
  covered_entity_commit?: string;
  phi_categories?: string[];
  // kyc.retention
  customer_commit?: string;
  relationship_end_at?: string;
  risk_profile_hash?: string;
  // sox.retention
  audit_record_commit?: string;
  fiscal_period?: string;
  // mifid2.retention
  trade_commit?: string;
  instrument_commit?: string;
  venue_commit?: string;
  mifid_class?: Mifid2InstrumentClass;
  // aiact.art10
  model_commit?: string;
  dataset_commit?: string;
  conformity_assessment_at?: string;
}

export const MAX_BATCH_TARGET_COUNT = 65_536;
