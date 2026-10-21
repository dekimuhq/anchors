/**
 * ATR (Anchored Transfer Receipts) body-type definitions.
 *
 * Body shape — what goes in `Envelope.body` — plus the discriminated union
 * keyed on `event_type` that the verifier's per-event body validator dispatches
 * on, and the profile-id union the profile validators are keyed by.
 *
 * These types live in `@dekimuhq/atr-profiles` (not the verifier) so the
 * profile validators can import the body shape without depending on the
 * verifier package — the verifier imports profile *values* (`family.ts`), so a
 * profiles→verifier type edge would form an import cycle that blocks the
 * topological built-`dist` publish. `@dekimuhq/atr` re-exports every
 * symbol here, so its public API is unchanged for downstream consumers.
 *
 * Envelope-level fields (`v`, `id`, `claim_type`, `iss`, `iss_key`, `iat`,
 * `iat_ms`, `subject`, `policy_uri`, `policy_hash`, `policy_version`,
 * `field_root`, `prev`, `credentialStatus`, `tsa`, `anchor`, `sig`,
 * `countersig`, `countersig_key`, `kind`, `cause`, `predicate`) are provided by
 * `@dekimuhq/anchors-envelope` and are NOT repeated here.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/atr.
 */

// ── Claim type ────────────────────────────────────────────────────────────────

export type AtrClaimType = "ar.transfer.v1";

// ── Event types (spec §4, v1.1 canonical §3.1) ────────────────────────────────

export type AtrEventType =
  | "arrangement"
  | "transfer"
  | "tia"
  | "suspension";

// ── Profiles (spec §5) ────────────────────────────────────────────────────────

export type AtrProfile =
  | "gdpr.art45.adequacy"
  | "gdpr.art46.scc"
  | "gdpr.art46.bcr"
  | "gdpr.art46.idta"
  | "gdpr.art47.bcr_authorised"
  | "gdpr.art49.derogation"
  | "gdpr.dpf"
  | "schremsii.tia";

// ── Mechanism versions (spec §4.5) ────────────────────────────────────────────

export type AtrMechanismVersion =
  | "scc-2021-c-pp"
  | "scc-2021-c-c"
  | "scc-2021-p-p"
  | "scc-2021-p-c"
  | "bcr-c"
  | "bcr-p"
  | "bcr-c-authorised"
  | "bcr-p-authorised"
  | "idta-2022"
  | "addendum-2022"
  | "art49-1-a"
  | "art49-1-b"
  | "art49-1-c"
  | "art49-1-d"
  | "art49-1-e"
  | "art49-1-f"
  | "art49-1-g"
  | "dpf-2023";
// Adequacy mechanism versions are dynamic: `adequacy:<CC>` (ISO 3166 alpha-2).

// ── Assessment outcome (spec §4.5, TIA) ──────────────────────────────────────

export type AtrAssessmentOutcome =
  | "permitted_plain"
  | "permitted_with_supplementary"
  | "not_permitted";

// ── Suspension trigger (spec §4.5) ────────────────────────────────────────────

export type AtrSuspensionTrigger =
  | "cjeu_judgment"
  | "dpa_order"
  | "adequacy_repeal"
  | "controller_decision"
  | "dpf_delisting"
  | "arrangement_expiry";

// ── Subject count bucket (spec §4.5) ──────────────────────────────────────────

export type AtrSubjectCountBucket =
  | "1"
  | "2_9"
  | "10_99"
  | "100_999"
  | "1k_9k"
  | "10k_99k"
  | "100k_plus";

// ── Body variants (discriminated union on event_type) ─────────────────────────

export interface AtrArrangementBody {
  event_type: "arrangement";
  arrangement_id_commit: string;
  recipient_commit: string;
  destination_country: string;
  mechanism_version: string;
  contract_doc_hash: string;
  in_force_from: string;
  in_force_until: string | null;
  supplementary_measures_hash: string;
  qts_attestation_hash: string | null;
}

export interface AtrTransferBody {
  event_type: "transfer";
  arrangement_hash: string;
  tia_hash: string | null;
  destination_country: string;
  recipient_commit: string;
  data_categories: readonly string[];
  subject_count_bucket: AtrSubjectCountBucket;
  transfer_window_start: string;
  transfer_window_end: string;
  artifact_apr_hash: string | null;
  consent_receipt_hash: string | null;
  purpose_binding_hash: string | null;
  qts_attestation_hash: string | null;
}

export interface AtrTiaBody {
  event_type: "tia";
  arrangement_hash: string;
  destination_country: string;
  assessment_doc_hash: string;
  surveillance_law_refs: readonly string[];
  assessment_outcome: AtrAssessmentOutcome;
  supplementary_measures_hash: string;
  valid_from: string;
  valid_until: string;
  qts_attestation_hash: string | null;
}

export interface AtrSuspensionBody {
  event_type: "suspension";
  trigger: AtrSuspensionTrigger;
  trigger_ref_hash: string;
  effective_at: string;
  qts_attestation_hash: string | null;
}

export type AtrBody =
  | AtrArrangementBody
  | AtrTransferBody
  | AtrTiaBody
  | AtrSuspensionBody;
