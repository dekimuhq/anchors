/**
 * AIR (Anchored Impact-Assessment Receipts) body-type definitions.
 *
 * Body shape — what goes in `Envelope.body` — plus the discriminated union
 * keyed on `event_type` that the verifier's per-event body validator dispatches
 * on, and the profile-id union the profile validators are keyed by.
 *
 * These types live in `@dekimuhq/air-profiles` (not the verifier) so the
 * profile validators can import the body shape without depending on the
 * verifier package — the verifier imports profile *values* (`family.ts`), so a
 * profiles→verifier type edge would form an import cycle that blocks the
 * topological built-`dist` publish. `@dekimuhq/air` re-exports every
 * symbol here, so its public API is unchanged for downstream consumers.
 *
 * Envelope-level fields (`v`, `id`, `claim_type`, `iss`, `iss_key`, `iat`,
 * `iat_ms`, `subject`, `policy_uri`, `policy_hash`, `policy_version`,
 * `field_root`, `prev`, `credentialStatus`, `tsa`, `anchor`, `sig`,
 * `countersig`, `kind`, `cause`, `predicate`) are provided by
 * `@dekimuhq/anchors-envelope` and are NOT repeated here.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/air.
 * Family invariants: `meta/FAMILY-CONSISTENCY.md` (chip #13,
 * subject-presence per-event split — `null` everywhere except OPTIONALLY
 * on `dpia.stakeholders_consulted` per D10-AIR-6 — and Status List 2021
 * consumer #7 with the `active | closed | withdrawn | revoked` state set
 * per spec §6.3).
 */

// ── Claim type ────────────────────────────────────────────────────────────────

/** AIR v=2 claim_type — the only registered discriminator for this family. */
export type AirClaimType = "ar.impact.v1";

// ── Event types ───────────────────────────────────────────────────────────────

/**
 * The eleven wire-level event-type discriminators defined in AIR spec §4.
 *
 * - `dpia.threshold_triggered`           — chain-start (§4.1).
 * - `dpia.scope_locked`                  — DPIA scope finalised (§4.2).
 * - `dpia.dpo_advised`                   — Art. 35(2) DPO advice (§4.3).
 * - `dpia.stakeholders_consulted`        — Art. 35(9) consultation (§4.4).
 * - `dpia.completed`                     — DPIA artifact anchored (§4.5).
 * - `dpia.reviewed`                      — Art. 35(11) review (§4.6).
 * - `dpia.prior_consultation_initiated`  — Art. 36(1) submission to DPA (§4.7).
 * - `dpia.prior_consultation_resolved`   — Art. 36(2) DPA advice landed (§4.8).
 * - `dpia.processing_authorised`         — terminal disposition (§4.9).
 * - `dpia.processing_blocked`            — terminal disposition (§4.9).
 * - `dpia.terminated`                    — terminal withdrawal (§4.9).
 */
export type AirEventType =
  | "dpia.threshold_triggered"
  | "dpia.scope_locked"
  | "dpia.dpo_advised"
  | "dpia.stakeholders_consulted"
  | "dpia.completed"
  | "dpia.reviewed"
  | "dpia.prior_consultation_initiated"
  | "dpia.prior_consultation_resolved"
  | "dpia.processing_authorised"
  | "dpia.processing_blocked"
  | "dpia.terminated";

// ── Profile union ─────────────────────────────────────────────────────────────

/**
 * The five v1 regulatory profiles (spec §5). Profile validators ship in the
 * separate `@dekimuhq/air-profiles` package; the verifier loads them
 * dynamically. The verifier rejects any receipt with an unregistered profile.
 */
export type AirProfile =
  | "impact.art35_3_a_automated_decisions"
  | "impact.art35_3_b_large_scale_special_categories"
  | "impact.art35_3_c_public_monitoring"
  | "impact.art35_4_dpa_list"
  | "impact.voluntary";

// ── Closed enums (body sub-fields) ────────────────────────────────────────────

/**
 * Residual-risk classification (spec §4.5).
 *
 * `dpia.completed.body.residual_risk_level === "high"` triggers the
 * D10-AIR-4 prior-consultation gate: the chain MUST pass through
 * `dpia.prior_consultation_initiated` + `dpia.prior_consultation_resolved`
 * before any `dpia.processing_authorised`.
 */
export type AirResidualRiskLevel = "low" | "medium" | "high";

/**
 * Stakeholder-consultation method enum (spec §4.4).
 *
 * `representative_org` and `ngo_review` are the only methods where the
 * envelope-level `subject` MAY carry a `sub_commit` of the consulted
 * representative organisation (D10-AIR-6); other methods MUST keep
 * `subject: null`.
 */
export type AirConsultationMethod =
  | "survey"
  | "focus_group"
  | "representative_org"
  | "public_consultation"
  | "ngo_review"
  | "internal_advisory_panel"
  | "other";

/**
 * Review outcome enum (spec §4.6).
 *
 * `material_change` and `superseded` both mark the current chain as a
 * predecessor that the §6 verifier walker accepts as the target of a
 * subsequent chain's `dpia.threshold_triggered.prev` (re-DPIA inheritance,
 * §6.2 rule 7).
 */
export type AirReviewOutcome =
  | "no_material_change"
  | "material_change"
  | "superseded";

/**
 * Terminal-disposition enum (spec §4.9).
 *
 * Each terminal event type pins exactly one value:
 * - `dpia.processing_authorised` → `"authorised"`
 * - `dpia.processing_blocked`    → `"blocked"`
 * - `dpia.terminated`            → `"terminated"`
 *
 * §C body verifier enforces this 1:1 pairing.
 */
export type AirTerminalDisposition = "authorised" | "blocked" | "terminated";

// ── Status List 2021 on-list state (spec §6.3) ────────────────────────────────

/**
 * On-list interpretation of the Status List 2021 bit value for AIR.
 *
 * | State        | When issued                                                       |
 * |--------------|-------------------------------------------------------------------|
 * | `active`     | default; DPIA still in lifecycle                                  |
 * | `closed`     | terminal event has flipped the chain bit; downstream resolves OK |
 * | `withdrawn`  | controller withdraws the receipt as in-error (per an internal design record (not published)) |
 * | `revoked`    | controller-side revocation for fraud / error / compromise         |
 *
 * The runtime status-list check is performed by `verifyCredentialStatus`
 * from `@dekimuhq/anchors-envelope/status`. This type names the on-list
 * states for AIR-specific audit tooling. `closed` and `withdrawn` are
 * informational at the bit layer (per spec §6.3); `revoked` invalidates
 * the entire DPIA chain.
 */
export type AirStatusState = "active" | "closed" | "withdrawn" | "revoked";

// ── Per-event-type body variants ──────────────────────────────────────────────

/**
 * Fields common to all eleven event-type bodies (spec §3.1 + D10-AIR-2 +
 * D10-AIR-3).
 *
 * `air_receipt_id` MUST be identical across every receipt in a single
 * DPIA's lifecycle (D10-AIR-2). `processing_activity_id` is stable across
 * DPIAs covering the same processing activity (D10-AIR-3); a controller
 * running its second DPIA on activity P uses the same
 * `processing_activity_id` and a fresh `air_receipt_id`. §C chain walker
 * enforces both invariants.
 */
interface AirBodyBase {
  air_receipt_id: string;
  processing_activity_id: string;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
}

/**
 * Body for `dpia.threshold_triggered` (spec §4.1).
 *
 * Chain-start event. `prev` is `null` on first DPIA; on re-DPIA after
 * material change `prev` references the predecessor chain's
 * `dpia.reviewed` with `review_outcome ∈ {"material_change","superseded"}`
 * (D10-AIR-2, §6.2 rule 7). `processing_activity_hash` is a stable
 * canonical hash of the RoPA-entry snapshot in scope at trigger time;
 * later events in the chain reference the same hash (§6.2 rule 3).
 *
 * `kind: "observation"`; `cause ∈ {"event","review_cycle","material_change"}`.
 */
export interface AirThresholdTriggeredBody extends AirBodyBase {
  event_type: "dpia.threshold_triggered";
  processing_activity_hash: string;
  processing_start_at: string;

  // Cross-event-pinned fields (always null on `dpia.threshold_triggered`).
  scope_hash: null;
  dpo_did_or_email_commit: null;
  dpo_advice_hash: null;
  consultation_method: null;
  consultation_output_hash: null;
  dpia_artifact_hash: null;
  dpia_uri: null;
  residual_risk_level: null;
  review_due_at: null;
  review_outcome: null;
  review_evidence_hash: null;
  dpa_jurisdiction: null;
  submission_hash: null;
  dpa_advice_hash: null;
  dpa_did: null;
  controller_response_hash: null;
  terminal_disposition: null;
  termination_reason_hash: null;
  aer_receipt_ids: null;
  atr_receipt_ids: null;
  alr_receipt_ids: null;
  apur_receipt_ids: null;
  abr_receipt_id: null;
}

/**
 * Body for `dpia.scope_locked` (spec §4.2).
 *
 * `scope_hash` SHA-256s the canonical scope statement. A second
 * `scope_locked` in the same chain without an intervening `dpia.reviewed`
 * (review_outcome=material_change) surfaces `scope_rewrite_without_review`
 * HARD-invalid (D10-AIR threat: re-scope-after-finding) — enforced by §C
 * chain walker.
 *
 * `kind: "decision"`; `cause: "event"`.
 */
export interface AirScopeLockedBody extends AirBodyBase {
  event_type: "dpia.scope_locked";
  scope_hash: string;

  // Cross-event-pinned fields.
  processing_activity_hash: null;
  processing_start_at: null;
  dpo_did_or_email_commit: null;
  dpo_advice_hash: null;
  consultation_method: null;
  consultation_output_hash: null;
  dpia_artifact_hash: null;
  dpia_uri: null;
  residual_risk_level: null;
  review_due_at: null;
  review_outcome: null;
  review_evidence_hash: null;
  dpa_jurisdiction: null;
  submission_hash: null;
  dpa_advice_hash: null;
  dpa_did: null;
  controller_response_hash: null;
  terminal_disposition: null;
  termination_reason_hash: null;
  aer_receipt_ids: null;
  atr_receipt_ids: null;
  alr_receipt_ids: null;
  apur_receipt_ids: null;
  abr_receipt_id: null;
}

/**
 * Body for `dpia.dpo_advised` (spec §4.3).
 *
 * Art. 35(2) — `dpo_did_or_email_commit` is an HMAC-salted commit of the
 * DPO's directory entry; `dpo_advice_hash` SHA-256s the written advice.
 * §C chain walker surfaces `dpo_commit_drift` informational when the
 * commit value changes across the same controller's chains in the same
 * time window.
 *
 * `kind: "observation"`; `cause: "event"`.
 */
export interface AirDpoAdvisedBody extends AirBodyBase {
  event_type: "dpia.dpo_advised";
  dpo_did_or_email_commit: string;
  dpo_advice_hash: string;

  // Cross-event-pinned fields.
  processing_activity_hash: null;
  processing_start_at: null;
  scope_hash: null;
  consultation_method: null;
  consultation_output_hash: null;
  dpia_artifact_hash: null;
  dpia_uri: null;
  residual_risk_level: null;
  review_due_at: null;
  review_outcome: null;
  review_evidence_hash: null;
  dpa_jurisdiction: null;
  submission_hash: null;
  dpa_advice_hash: null;
  dpa_did: null;
  controller_response_hash: null;
  terminal_disposition: null;
  termination_reason_hash: null;
  aer_receipt_ids: null;
  atr_receipt_ids: null;
  alr_receipt_ids: null;
  apur_receipt_ids: null;
  abr_receipt_id: null;
}

/**
 * Body for `dpia.stakeholders_consulted` (spec §4.4).
 *
 * Art. 35(9). `consultation_output_hash` MUST NOT equal the canonical hash
 * of an empty document; §C body verifier surfaces `consultation_output_empty`
 * HARD-invalid when it does.
 *
 * Per FAMILY-CONSISTENCY §3 + D10-AIR-6, the envelope-level `subject` MAY
 * be `"sha256:<hex>"` (representative-org `sub_commit`) ONLY when
 * `consultation_method ∈ {"representative_org","ngo_review"}`; other
 * methods MUST keep `subject: null`. §E subject-presence rule enforces this.
 *
 * `kind: "observation"`; `cause: "event"`.
 */
export interface AirStakeholdersConsultedBody extends AirBodyBase {
  event_type: "dpia.stakeholders_consulted";
  consultation_method: AirConsultationMethod;
  consultation_output_hash: string;

  // Cross-event-pinned fields.
  processing_activity_hash: null;
  processing_start_at: null;
  scope_hash: null;
  dpo_did_or_email_commit: null;
  dpo_advice_hash: null;
  dpia_artifact_hash: null;
  dpia_uri: null;
  residual_risk_level: null;
  review_due_at: null;
  review_outcome: null;
  review_evidence_hash: null;
  dpa_jurisdiction: null;
  submission_hash: null;
  dpa_advice_hash: null;
  dpa_did: null;
  controller_response_hash: null;
  terminal_disposition: null;
  termination_reason_hash: null;
  aer_receipt_ids: null;
  atr_receipt_ids: null;
  alr_receipt_ids: null;
  apur_receipt_ids: null;
  abr_receipt_id: null;
}

/**
 * Body for `dpia.completed` (spec §4.5).
 *
 * The DPIA artifact (canonical PDF or controlled-markdown) is hashed and
 * committed. `dpia_artifact_hash` is **immutable** for a given
 * `air_receipt_id` (D10-AIR-7): later events referencing a different hash
 * surface `dpia_artifact_hash_drift` HARD-invalid. To replace the
 * artifact, controllers MUST emit `dpia.reviewed` with `review_outcome ∈
 * {"material_change","superseded"}` and start a fresh chain.
 *
 * Composition fields (spec §8):
 * - `aer_receipt_ids`: STRONGLY RECOMMENDED on `impact.art35_3_a_automated_decisions`
 *   (§8.1); absent surfaces `art35_3a_aer_link_missing` informational.
 * - `atr_receipt_ids`: recommended for cross-border processing (§8.2).
 * - `alr_receipt_ids`: recommended for data-flow lineage (§8.3); strongest
 *   recommendation on the `b_large_scale_special_categories` and
 *   `c_public_monitoring` profiles.
 * - `apur_receipt_ids`: recommended for purpose-binding assessment (§8.4).
 *
 * §D TSA mandate matrix RECOMMENDS a `tsa` block on this event
 * (sequence-vs-processing-start clock).
 *
 * `kind: "decision"`; `cause ∈ {"event","review_cycle","material_change"}`.
 */
export interface AirCompletedBody extends AirBodyBase {
  event_type: "dpia.completed";
  dpia_artifact_hash: string;
  dpia_uri: string;
  residual_risk_level: AirResidualRiskLevel;
  review_due_at: string;

  /** Composition: AER (`ar.evaluation.v1`, `event_type: "conformity"`, `profile: "aer.adm"`) receipt ids (§8.1). */
  aer_receipt_ids: readonly string[] | null;
  /** Composition: ATR (`ar.transfer.v1`) receipt ids for cross-border transfers in scope (§8.2). */
  atr_receipt_ids: readonly string[] | null;
  /** Composition: ALR (`ar.lineage.v1`) receipt ids for data flows in scope (§8.3). */
  alr_receipt_ids: readonly string[] | null;
  /** Composition: APuR (`ar.purpose.v1`) receipt ids for purpose bindings in scope (§8.4). */
  apur_receipt_ids: readonly string[] | null;

  // Cross-event-pinned fields.
  processing_activity_hash: null;
  processing_start_at: null;
  scope_hash: null;
  dpo_did_or_email_commit: null;
  dpo_advice_hash: null;
  consultation_method: null;
  consultation_output_hash: null;
  review_outcome: null;
  review_evidence_hash: null;
  dpa_jurisdiction: null;
  submission_hash: null;
  dpa_advice_hash: null;
  dpa_did: null;
  controller_response_hash: null;
  terminal_disposition: null;
  termination_reason_hash: null;
  abr_receipt_id: null;
}

/**
 * Body for `dpia.reviewed` (spec §4.6).
 *
 * Art. 35(11) periodic or event-triggered review. `review_outcome ∈
 * {"material_change","superseded"}` marks this event as a valid predecessor
 * for a successor chain's `dpia.threshold_triggered.prev` (§6.2 rule 7).
 *
 * Composition: `abr_receipt_id` carries an ABR receipt id when the review
 * is triggered by a breach (§8.5). `cause` SHOULD be `"breach"` in this
 * case (v1.2 envelope §3.2).
 *
 * `kind: "decision"`; `cause ∈ {"review_cycle","material_change","breach"}`.
 */
export interface AirReviewedBody extends AirBodyBase {
  event_type: "dpia.reviewed";
  review_outcome: AirReviewOutcome;
  review_evidence_hash: string;

  /** Composition: ABR (`ar.breach.v1`) receipt id for breach-triggered review (§8.5). */
  abr_receipt_id: string | null;

  // Cross-event-pinned fields.
  processing_activity_hash: null;
  processing_start_at: null;
  scope_hash: null;
  dpo_did_or_email_commit: null;
  dpo_advice_hash: null;
  consultation_method: null;
  consultation_output_hash: null;
  dpia_artifact_hash: null;
  dpia_uri: null;
  residual_risk_level: null;
  review_due_at: null;
  dpa_jurisdiction: null;
  submission_hash: null;
  dpa_advice_hash: null;
  dpa_did: null;
  controller_response_hash: null;
  terminal_disposition: null;
  termination_reason_hash: null;
  aer_receipt_ids: null;
  atr_receipt_ids: null;
  alr_receipt_ids: null;
  apur_receipt_ids: null;
}

/**
 * Body for `dpia.prior_consultation_initiated` (spec §4.7).
 *
 * Art. 36(1) — controller submits the DPIA to the supervisory authority
 * because residual risk is high. `prev` MUST reference `dpia.completed`
 * with `residual_risk_level === "high"`; voluntary consultation after a
 * non-high `completed` is valid but surfaces `voluntary_prior_consultation`
 * informational (§C body verifier).
 *
 * `dpa_jurisdiction` is an ISO-3166-1 alpha-2 code or `"EU-EDPB"` for
 * EDPB consistency-mechanism cases. §D TSA mandate matrix RECOMMENDS a
 * `tsa` block on this event (Art. 36 clock).
 *
 * `kind: "decision"`; `cause: "event"`.
 */
export interface AirPriorConsultationInitiatedBody extends AirBodyBase {
  event_type: "dpia.prior_consultation_initiated";
  dpa_jurisdiction: string;
  submission_hash: string;

  // Cross-event-pinned fields.
  processing_activity_hash: null;
  processing_start_at: null;
  scope_hash: null;
  dpo_did_or_email_commit: null;
  dpo_advice_hash: null;
  consultation_method: null;
  consultation_output_hash: null;
  dpia_artifact_hash: null;
  dpia_uri: null;
  residual_risk_level: null;
  review_due_at: null;
  review_outcome: null;
  review_evidence_hash: null;
  dpa_advice_hash: null;
  dpa_did: null;
  controller_response_hash: null;
  terminal_disposition: null;
  termination_reason_hash: null;
  aer_receipt_ids: null;
  atr_receipt_ids: null;
  alr_receipt_ids: null;
  apur_receipt_ids: null;
  abr_receipt_id: null;
}

/**
 * Body for `dpia.prior_consultation_resolved` (spec §4.8).
 *
 * Art. 36(2) — the supervisory authority's written advice (max 8 weeks,
 * extendable by 6 weeks). `dpa_advice_hash` SHA-256s the DPA's advice;
 * `controller_response_hash` SHA-256s the controller's response. `dpa_did`
 * is OPTIONAL and reserved for future bilateral anchoring once EUDI Wallet
 * supports DPA DIDs; v1 deployments leave it `null`.
 *
 * §C body verifier surfaces `art36_consultation_overdue` informational
 * when `iat > prior_consultation_initiated.iat + 14 weeks` (the overrun is
 * on the DPA's side procedurally, not HARD-invalid). §D TSA mandate matrix
 * RECOMMENDS a `tsa` block on this event (DPA-advice receipt clock).
 *
 * `kind: "observation"`; `cause: "event"`.
 */
export interface AirPriorConsultationResolvedBody extends AirBodyBase {
  event_type: "dpia.prior_consultation_resolved";
  dpa_advice_hash: string;
  controller_response_hash: string;
  /** OPTIONAL DPA DID when the DPA has signed its advice (pre-EUDI-Wallet rare); `null` otherwise. */
  dpa_did: string | null;

  // Cross-event-pinned fields.
  processing_activity_hash: null;
  processing_start_at: null;
  scope_hash: null;
  dpo_did_or_email_commit: null;
  dpo_advice_hash: null;
  consultation_method: null;
  consultation_output_hash: null;
  dpia_artifact_hash: null;
  dpia_uri: null;
  residual_risk_level: null;
  review_due_at: null;
  review_outcome: null;
  review_evidence_hash: null;
  dpa_jurisdiction: null;
  submission_hash: null;
  terminal_disposition: null;
  termination_reason_hash: null;
  aer_receipt_ids: null;
  atr_receipt_ids: null;
  alr_receipt_ids: null;
  apur_receipt_ids: null;
  abr_receipt_id: null;
}

/**
 * Body for `dpia.processing_authorised` (spec §4.9 terminal trio).
 *
 * Controller decides to proceed with processing, with the documented
 * mitigations. `terminal_disposition` is pinned to `"authorised"`.
 *
 * Verifier rule (CRITICAL — D10-AIR-4): when the most recent
 * `dpia.completed` in the chain has `residual_risk_level === "high"`, the
 * chain MUST pass through `dpia.prior_consultation_resolved` before this
 * event. §C chain walker rejects with `art36_prior_consultation_skipped`
 * HARD-invalid otherwise.
 *
 * `kind: "decision"`; `cause: "event"`.
 */
export interface AirProcessingAuthorisedBody extends AirBodyBase {
  event_type: "dpia.processing_authorised";
  terminal_disposition: "authorised";

  // Cross-event-pinned fields.
  processing_activity_hash: null;
  processing_start_at: null;
  scope_hash: null;
  dpo_did_or_email_commit: null;
  dpo_advice_hash: null;
  consultation_method: null;
  consultation_output_hash: null;
  dpia_artifact_hash: null;
  dpia_uri: null;
  residual_risk_level: null;
  review_due_at: null;
  review_outcome: null;
  review_evidence_hash: null;
  dpa_jurisdiction: null;
  submission_hash: null;
  dpa_advice_hash: null;
  dpa_did: null;
  controller_response_hash: null;
  termination_reason_hash: null;
  aer_receipt_ids: null;
  atr_receipt_ids: null;
  alr_receipt_ids: null;
  apur_receipt_ids: null;
  abr_receipt_id: null;
}

/**
 * Body for `dpia.processing_blocked` (spec §4.9 terminal trio).
 *
 * Controller (or DPA via Art. 58(2)(f)) decides to block processing.
 * `terminal_disposition` is pinned to `"blocked"`.
 *
 * `kind: "decision"`; `cause: "event"`.
 */
export interface AirProcessingBlockedBody extends AirBodyBase {
  event_type: "dpia.processing_blocked";
  terminal_disposition: "blocked";

  // Cross-event-pinned fields.
  processing_activity_hash: null;
  processing_start_at: null;
  scope_hash: null;
  dpo_did_or_email_commit: null;
  dpo_advice_hash: null;
  consultation_method: null;
  consultation_output_hash: null;
  dpia_artifact_hash: null;
  dpia_uri: null;
  residual_risk_level: null;
  review_due_at: null;
  review_outcome: null;
  review_evidence_hash: null;
  dpa_jurisdiction: null;
  submission_hash: null;
  dpa_advice_hash: null;
  dpa_did: null;
  controller_response_hash: null;
  termination_reason_hash: null;
  aer_receipt_ids: null;
  atr_receipt_ids: null;
  alr_receipt_ids: null;
  apur_receipt_ids: null;
  abr_receipt_id: null;
}

/**
 * Body for `dpia.terminated` (spec §4.9 terminal trio).
 *
 * Controller withdraws the DPIA — typically because the processing plan
 * was abandoned or because a successor DPIA is taking over (material
 * change). `terminal_disposition` is pinned to `"terminated"`;
 * `termination_reason_hash` SHA-256s the withdrawal-rationale document.
 *
 * `kind: "decision"`; `cause ∈ {"material_change","event"}`.
 */
export interface AirTerminatedBody extends AirBodyBase {
  event_type: "dpia.terminated";
  terminal_disposition: "terminated";
  termination_reason_hash: string;

  // Cross-event-pinned fields.
  processing_activity_hash: null;
  processing_start_at: null;
  scope_hash: null;
  dpo_did_or_email_commit: null;
  dpo_advice_hash: null;
  consultation_method: null;
  consultation_output_hash: null;
  dpia_artifact_hash: null;
  dpia_uri: null;
  residual_risk_level: null;
  review_due_at: null;
  review_outcome: null;
  review_evidence_hash: null;
  dpa_jurisdiction: null;
  submission_hash: null;
  dpa_advice_hash: null;
  dpa_did: null;
  controller_response_hash: null;
  aer_receipt_ids: null;
  atr_receipt_ids: null;
  alr_receipt_ids: null;
  apur_receipt_ids: null;
  abr_receipt_id: null;
}

/**
 * Discriminated union of all eleven AIR body variants.
 * §C body verifier dispatches on `body.event_type`.
 */
export type AirBody =
  | AirThresholdTriggeredBody
  | AirScopeLockedBody
  | AirDpoAdvisedBody
  | AirStakeholdersConsultedBody
  | AirCompletedBody
  | AirReviewedBody
  | AirPriorConsultationInitiatedBody
  | AirPriorConsultationResolvedBody
  | AirProcessingAuthorisedBody
  | AirProcessingBlockedBody
  | AirTerminatedBody;
