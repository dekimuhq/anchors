/**
 * AAR (Anchored Attestation Receipts) body-type definitions.
 *
 * Body shape — what goes in `Envelope.body` — plus the discriminated union
 * keyed on `event_type` that the verifier's per-event body validator dispatches
 * on, and the profile-id union the profile validators are keyed by.
 *
 * These types live in `@dekimuhq/aar-profiles` (not the verifier) so the
 * profile validators can import the body shape without depending on the
 * verifier package — the verifier imports profile *values* (`family.ts`), so a
 * profiles→verifier type edge would form an import cycle that blocks the
 * topological built-`dist` publish. `@dekimuhq/aar` re-exports every
 * symbol here, so its public API is unchanged for downstream consumers.
 *
 * Envelope-level fields (`v`, `id`, `claim_type`, `iss`, `iss_key`, `iat`,
 * `iat_ms`, `subject`, `policy_uri`, `policy_hash`, `policy_version`,
 * `field_root`, `prev`, `credentialStatus`, `tsa`, `anchor`, `sig`,
 * `countersig`, `countersig_key`, `kind`, `cause`, `predicate`) are provided by
 * `@dekimuhq/anchors-envelope` and are NOT repeated here.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/aar.
 */

// ── Claim type ──────────────────────────────────────────────────────────────────

export type AarClaimType = "ar.attestation.v1";

// ── Event types (spec §4, v1.1 envelope mapping) ───────────────────────────────

export type AarEventType = "issuance" | "revocation";

// ── Profiles (spec §5) ─────────────────────────────────────────────────────────

export type AarProfile =
  | "eidas.qes"
  | "eidas.qeseal"
  | "eidas.qts"
  | "eidas.qereg"
  | "eidas.qcert.natural"
  | "eidas.qcert.legal"
  | "eidas.qwallet"
  | "eidas.qattest";

// ── Service types (spec §4, D12-AAR) ───────────────────────────────────────────

export type AarServiceType =
  | "qes"
  | "qeseal"
  | "qts"
  | "qereg"
  | "qcert_natural"
  | "qcert_legal"
  | "qwallet"
  | "qattest";

// ── Signature formats (spec §4.3, ETSI EN 319 132/142/162/182) ─────────────────

export type AarSignatureFormat =
  | "pades_b_b" | "pades_b_t" | "pades_b_lt" | "pades_b_lta"
  | "xades_b_b" | "xades_b_t" | "xades_b_lt" | "xades_b_lta"
  | "cades_b_b" | "cades_b_t" | "cades_b_lt" | "cades_b_lta"
  | "jades_b_b" | "jades_b_t" | "jades_b_lt" | "jades_b_lta";

// ── Revocation reasons (spec §4.2) ─────────────────────────────────────────────

export type AarRevocationReason =
  | "key_compromise"
  | "policy_violation"
  | "recipient_request"
  | "controller_decision"
  | "tsl_delisted"
  | "superseded";

// ── Body variants (discriminated union on event_type) ──────────────────────────

/** issuance — spec §4.1. Chain head (prev MUST be null). */
export interface AarIssuanceBody {
  event_type: "issuance";
  service_type: AarServiceType;
  service_policy_oid: string;
  service_recipient_commit: string;
  artefact_hash: string | null;
  artefact_metadata_commit: string;
  signature_format: AarSignatureFormat | null;
  qcert_serial_commit: string | null;
  tsl_country: string;
  tsl_entry_hash: string;
  tsl_signed_tree_head_root: string;
  tsl_tree_size: number;
  tsl_inclusion_proof: string[];
  tsl_log_time: string;
  atr_transfer_hash: string | null;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
}

/** revocation — spec §4.2. prev MUST reference an issuance receipt. */
export interface AarRevocationBody {
  event_type: "revocation";
  reason: AarRevocationReason;
  reason_ref_hash: string | null;
  tsl_country: string;
  tsl_entry_hash: string;
  tsl_signed_tree_head_root: string;
  tsl_tree_size: number;
  tsl_inclusion_proof: string[];
  tsl_log_time: string;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
}

/** Discriminated union of both event types. */
export type AarBody = AarIssuanceBody | AarRevocationBody;
