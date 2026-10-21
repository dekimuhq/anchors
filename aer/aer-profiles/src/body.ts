/**
 * AER (Anchored Evaluation Receipts) body-type definitions.
 *
 * Body shape — what goes in `Envelope.body` — plus the discriminated union
 * keyed on `event_type` that the verifier's per-event body validator dispatches
 * on, and the profile-id union the profile validators are keyed by.
 *
 * These types live in `@dekimuhq/aer-profiles` (not the verifier) so the
 * profile validators can import the body shape without depending on the
 * verifier package — the verifier imports profile *values* (`family.ts`), so a
 * profiles→verifier type edge would form an import cycle that blocks the
 * topological built-`dist` publish. `@dekimuhq/aer` re-exports every
 * symbol here, so its public API is unchanged for downstream consumers.
 *
 * Envelope-level fields (`v`, `id`, `claim_type`, `iss`, `iss_key`, `iat`,
 * `iat_ms`, `subject`, `policy_uri`, `policy_hash`, `policy_version`,
 * `field_root`, `prev`, `credentialStatus`, `tsa`, `anchor`, `sig`,
 * `countersig`, `countersig_key`, `kind`, `cause`, `predicate`) are provided by
 * `@dekimuhq/anchors-envelope` and are NOT repeated here.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/aer.
 */

// ── Claim type ────────────────────────────────────────────────────────────────

export type AerClaimType = "ar.evaluation.v1";

// ── Event types (spec §4, D10-AER) ─────────────────────────────────────────────

export type AerEventType = "conformity" | "transparency";

// ── Profiles (spec §5) ─────────────────────────────────────────────────────────

export type AerProfile =
  | "aiact.art43.internal"
  | "aiact.art43.thirdparty"
  | "aiact.art43.fr_assessment"
  | "aiact.art50.chatbot"
  | "aiact.art50.synthetic_media"
  | "aiact.art50.emotion_biocategorization"
  | "aiact.art50.public_text"
  | "aiact.art52.gpai"
  | "nist.aimrf.profile";

// ── Risk class (D15-AER) ───────────────────────────────────────────────────────

export type AerRiskClass =
  | "prohibited"
  | "high"
  | "limited"
  | "minimal"
  | "gpai"
  | "gpai_systemic";

// ── Assessment route (D11-AER) ─────────────────────────────────────────────────

export type AerAssessmentRoute =
  | "internal_control"
  | "thirdparty_notified_body"
  | "fundamental_rights";

// ── Annex III categories (spec §4.3) ────────────────────────────────────────────

export type AerAnnexIiiCategory =
  | "biometrics"
  | "critical_infrastructure"
  | "education_training"
  | "employment_management"
  | "essential_services"
  | "law_enforcement"
  | "migration_border"
  | "justice_democratic";

// ── Disclosure type (spec §4.3) ─────────────────────────────────────────────────

export type AerDisclosureType =
  | "chatbot"
  | "synthetic_audio"
  | "synthetic_image"
  | "synthetic_video"
  | "deepfake_recognisable_person"
  | "deepfake_artistic"
  | "emotion_recognition"
  | "biometric_categorisation"
  | "ai_generated_text_public_interest";

// ── Disclosure scope (D13-AER) ──────────────────────────────────────────────────

export type AerDisclosureScope = "single" | "session" | "batch";

// ── Watermark scheme (D14-AER) ──────────────────────────────────────────────────

export type AerWatermarkScheme = "c2pa" | "starc" | "nlsw" | "none";

// ── Body variants (discriminated union on event_type) ───────────────────────────

/** conformity — spec §4.1. Provider-side, periodic, AI-system-subject. */
export interface AerConformityBody {
  event_type: "conformity";
  profile: string;
  system_id_commit: string;
  system_version: string;
  model_id_commit: string;
  risk_class: AerRiskClass;
  annex_iii_categories: AerAnnexIiiCategory[] | null;
  assessment_route: AerAssessmentRoute;
  notified_body_id: string | null;
  harmonized_standards: string[];
  tech_doc_hash: string;
  tech_doc_arr_receipt_hash: string | null;
  risk_management_system_hash: string;
  data_governance_hash: string;
  fundamental_rights_hash: string | null;
  training_atr_arrangement_hash: string | null;
  training_apur_binding_hash: string | null;
  valid_from: string;
  valid_until: string | null;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
}

/** transparency — spec §4.2. Deployer-side, per-interaction/session/batch. */
export interface AerTransparencyBody {
  event_type: "transparency";
  profile: string;
  system_id_commit: string;
  system_apr_kid: string | null;
  conformity_receipt_hash: string;
  subject_commit: string;
  disclosure_scope: AerDisclosureScope;
  disclosure_type: AerDisclosureType;
  disclosure_text_hash: string;
  disclosure_locale: string;
  interaction_window_start: string;
  interaction_window_end: string;
  artifact_apr_hash: string | null;
  oversight_acr_hash: string | null;
  watermark_scheme: AerWatermarkScheme;
  watermark_sample_commit: string | null;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
}

/** Discriminated union of both event types. */
export type AerBody = AerConformityBody | AerTransparencyBody;
