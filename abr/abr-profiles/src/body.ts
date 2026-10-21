/**
 * ABR (Anchored Breach Receipts) body-type definitions.
 *
 * Body shape — what goes in `Envelope.body` — plus the discriminated union
 * keyed on `event_type` that the verifier's per-event body validator dispatches
 * on, and the profile-id union the profile validators are keyed by.
 *
 * These types live in `@dekimuhq/abr-profiles` (not the verifier) so the
 * profile validators can import the body shape without depending on the
 * verifier package — the verifier imports profile *values* (`family.ts`), so a
 * profiles→verifier type edge would form an import cycle that blocks the
 * topological built-`dist` publish. `@dekimuhq/abr` re-exports every
 * symbol here, so its public API is unchanged for downstream consumers.
 *
 * Envelope-level fields (`v`, `id`, `claim_type`, `iss`, `iss_key`, `iat`,
 * `iat_ms`, `subject`, `policy_uri`, `policy_hash`, `policy_version`,
 * `field_root`, `prev`, `credentialStatus`, `tsa`, `anchor`, `sig`,
 * `countersig`, `countersig_key`, `kind`, `cause`, `predicate`) are provided by
 * `@dekimuhq/anchors-envelope` and are NOT repeated here.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/abr.
 * Family invariants: `meta/FAMILY-CONSISTENCY.md` (chip #11,
 * subject-presence per-event split, TSA mandate row — `breach.detected`
 * MANDATORY, others RECOMMENDED — and status-list consumer #5).
 */

// ── Claim type ────────────────────────────────────────────────────────────────

/** ABR v=2 claim_type — the only registered discriminator for this family. */
export type AbrClaimType = "ar.breach.v1";

// ── Event types ───────────────────────────────────────────────────────────────

/**
 * The eight breach-lifecycle event types defined in ABR spec §4.
 *
 * - `breach.detected`                       — clock-start (§4.1).
 * - `breach.assessed`                       — risk-assessment outcome (§4.2).
 * - `breach.dpa_notified`                   — supervisory-authority filing (§4.3).
 * - `breach.dpa_delayed`                    — Art. 33(1) delay justification (§4.4).
 * - `breach.subject_notified`               — Art. 34 subject notice (§4.5).
 * - `breach.subject_notification_exempted`  — Art. 34(3)(a–c) exemption (§4.6).
 * - `breach.contained`                      — controller containment attestation (§4.7).
 * - `breach.closed`                         — terminal incident closure (§4.8).
 */
export type AbrEventType =
  | "breach.detected"
  | "breach.assessed"
  | "breach.dpa_notified"
  | "breach.dpa_delayed"
  | "breach.subject_notified"
  | "breach.subject_notification_exempted"
  | "breach.contained"
  | "breach.closed";

// ── Profile union ─────────────────────────────────────────────────────────────

/**
 * The nine v1 regulatory profiles (spec §5). Profile validators ship in this
 * `@dekimuhq/abr-profiles` package; the verifier loads them dynamically. The
 * verifier rejects any receipt with an unregistered profile.
 *
 * The four `breach.nis2.annex1.*` sub-profiles are NIS2 Annex I sectoral
 * profiles (spec §5.4–§5.7) that extend `breach.nis2.art23` with sector-
 * specific incident-reporting obligations.
 */
export type AbrProfile =
  | "breach.gdpr.art33"
  | "breach.gdpr.art34"
  | "breach.nis2.art23"
  | "breach.nis2.annex1.energy"
  | "breach.nis2.annex1.transport"
  | "breach.nis2.annex1.health"
  | "breach.nis2.annex1.digital_infrastructure"
  | "breach.dora.art19"
  | "breach.us_state.attorney_general";

// ── Closed enums (body sub-fields) ────────────────────────────────────────────

/**
 * Severity classification (spec §3.1, §4.1, §4.2).
 *
 * Mirrors GDPR Art. 33(1) "unless unlikely to result in a risk" trichotomy.
 * `breach.detected` carries the initial assessment; `breach.assessed` MAY
 * carry a different post-assessment value.
 */
export type AbrSeverityClass = "no_risk" | "risk" | "high_risk";

/**
 * Closed enum of Art. 34(3) exemption grounds (spec §4.6).
 *
 * Used on `breach.subject_notification_exempted` events only.
 */
export type AbrExemptionGround =
  | "art34_3_a_encrypted"
  | "art34_3_b_mitigated"
  | "art34_3_c_disproportionate";

/**
 * NIS2 Art. 23 notification phase (spec §4.3).
 *
 * Used on `breach.dpa_notified` events when `profile === "breach.nis2.art23"`.
 * The spec recognises three phases — early warning (24h), full notification
 * (72h), and final report (1 month) — distinguished by this value so the
 * verifier can resolve which deadline applies.
 *
 * `null` on profiles that do not phase-split notifications (Art. 33 / Art. 34 /
 * DORA / US-AG).
 */
export type AbrNotificationPhase =
  | "early_warning"
  | "full_notification"
  | "final_report";

// ── Status List 2021 on-list state (spec §6.3) ────────────────────────────────

/**
 * On-list interpretation of the Status List 2021 bit value for ABR.
 *
 * | State        | When issued                                                       |
 * |--------------|-------------------------------------------------------------------|
 * | `active`     | default; receipt is current                                       |
 * | `closed`     | terminal `breach.closed` event has flipped the incident-chain bit |
 * | `revoked`    | controller-side revocation for fraud / error / compromise         |
 *
 * The runtime status-list check is performed by `verifyCredentialStatus`
 * from `@dekimuhq/anchors-envelope/status`. This type names the on-list
 * states for ABR-specific audit tooling. The `closed` value is informational
 * (per spec §4.8) and does not invalidate earlier receipts in the chain.
 */
export type AbrStatusState = "active" | "closed" | "revoked";

// ── Per-event-type body variants ──────────────────────────────────────────────

/**
 * Fields common to all eight event-type bodies (spec §3.1 + D10-ABR-3).
 *
 * `profile` pins the receipt to one of the five v1 regulatory rationales.
 * `incident_correlation_id` MUST be identical across every receipt in an
 * incident-chain — across profiles, across jurisdictions (D10-ABR-3). §C
 * chain walker enforces parity.
 */
interface AbrBodyBase {
  profile: AbrProfile;
  incident_correlation_id: string;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  qts_attestation_hash: string | null;
}

/**
 * Body for `breach.detected` (spec §4.1).
 *
 * The clock-start event. Required: `detected_at`, `severity_class`,
 * `affected_data_categories`, `affected_data_hash`, `affected_count`
 * (may be `-1` when undetermined), `jurisdiction`.
 *
 * §D enforces `tsa` MANDATORY on this event (D10-ABR-2 — the 72-hour clock
 * starts here).
 *
 * The composition field `affected_aer_ids` lives here so the incident is
 * tied to AI-Act high-risk systems at detection time (spec §8.4 — audit
 * fix C5).
 */
export interface AbrDetectedBody extends AbrBodyBase {
  event_type: "breach.detected";
  detected_at: string;
  severity_class: AbrSeverityClass;
  affected_data_categories: readonly string[];
  affected_data_hash: string;
  /** Integer; `-1` when undetermined at time of receipt. */
  affected_count: number;
  jurisdiction: string;

  /** Composition: affected AER (`ar.evaluation.v1`) receipt ids (§8.4). */
  affected_aer_ids: readonly string[] | null;

  // Cross-event-pinned fields (always null on `breach.detected`).
  assessment_method_hash: null;
  notification_uri: null;
  notification_hash: null;
  dpa_reference_id: null;
  notification_phase: null;
  delay_reason_hash: null;
  delay_until_at: null;
  subject_batch_root: null;
  subject_batch_size: null;
  exemption_ground: null;
  justification_hash: null;
  public_communication_uri: null;
  containment_at: null;
  containment_summary_hash: null;
  containment_attestation: null;
  closed_at: null;
  closure_dpa_reference_id: null;
  containment_remediation_arr_ids: null;
  transfer_suspension_atr_ids: null;
  post_breach_anr_id: null;
  qes_aar_id: null;
}

/**
 * Body for `breach.assessed` (spec §4.2).
 *
 * Risk-assessment outcome. `severity_class` MAY differ from the
 * `breach.detected` value. `assessment_method_hash` SHA-256s the
 * methodology document or risk-assessment template.
 *
 * §C chain walker requires `prev` to reference the `breach.detected`
 * receipt for this incident.
 */
export interface AbrAssessedBody extends AbrBodyBase {
  event_type: "breach.assessed";
  severity_class: AbrSeverityClass;
  assessment_method_hash: string;

  // Cross-event-pinned fields.
  detected_at: null;
  affected_data_categories: null;
  affected_data_hash: null;
  affected_count: null;
  jurisdiction: null;
  notification_uri: null;
  notification_hash: null;
  dpa_reference_id: null;
  notification_phase: null;
  delay_reason_hash: null;
  delay_until_at: null;
  subject_batch_root: null;
  subject_batch_size: null;
  exemption_ground: null;
  justification_hash: null;
  public_communication_uri: null;
  containment_at: null;
  containment_summary_hash: null;
  containment_attestation: null;
  closed_at: null;
  closure_dpa_reference_id: null;
  affected_aer_ids: null;
  containment_remediation_arr_ids: null;
  transfer_suspension_atr_ids: null;
  post_breach_anr_id: null;
  qes_aar_id: null;
}

/**
 * Body for `breach.dpa_notified` (spec §4.3).
 *
 * Art. 33 (or NIS2 Art. 23 / DORA Art. 19) notification to the supervisory
 * authority. `notification_phase` is non-null only on the NIS2 profile
 * (early-warning / full / final). `dpa_reference_id` is null when the DPA
 * has not yet assigned a case id at submission time.
 *
 * Composition: `qes_aar_id` carries an AAR receipt id when the DPA mandates
 * a Qualified Electronic Signature on the notification (§8.2 — audit
 * fix C5). `countersig` (envelope-level) MAY carry the DPA's signature
 * under future EU Digital Wallet / EUDI pilots.
 */
export interface AbrDpaNotifiedBody extends AbrBodyBase {
  event_type: "breach.dpa_notified";
  notification_uri: string;
  notification_hash: string;
  dpa_reference_id: string | null;
  notification_phase: AbrNotificationPhase | null;

  /** Composition: AAR receipt id (`ar.attestation.v1`) for QES-signed filings (§8.2). */
  qes_aar_id: string | null;

  // Cross-event-pinned fields.
  detected_at: null;
  severity_class: null;
  affected_data_categories: null;
  affected_data_hash: null;
  affected_count: null;
  jurisdiction: null;
  assessment_method_hash: null;
  delay_reason_hash: null;
  delay_until_at: null;
  subject_batch_root: null;
  subject_batch_size: null;
  exemption_ground: null;
  justification_hash: null;
  public_communication_uri: null;
  containment_at: null;
  containment_summary_hash: null;
  containment_attestation: null;
  closed_at: null;
  closure_dpa_reference_id: null;
  affected_aer_ids: null;
  containment_remediation_arr_ids: null;
  transfer_suspension_atr_ids: null;
  post_breach_anr_id: null;
}

/**
 * Body for `breach.dpa_delayed` (spec §4.4).
 *
 * Art. 33(1) "reasons for the delay" anchored as a first-class event so the
 * delay reasoning is timestamped before the late notification.
 * `delay_until_at` is the controller-asserted target notification time.
 */
export interface AbrDpaDelayedBody extends AbrBodyBase {
  event_type: "breach.dpa_delayed";
  delay_reason_hash: string;
  delay_until_at: string;

  // Cross-event-pinned fields.
  detected_at: null;
  severity_class: null;
  affected_data_categories: null;
  affected_data_hash: null;
  affected_count: null;
  jurisdiction: null;
  assessment_method_hash: null;
  notification_uri: null;
  notification_hash: null;
  dpa_reference_id: null;
  notification_phase: null;
  subject_batch_root: null;
  subject_batch_size: null;
  exemption_ground: null;
  justification_hash: null;
  public_communication_uri: null;
  containment_at: null;
  containment_summary_hash: null;
  containment_attestation: null;
  closed_at: null;
  closure_dpa_reference_id: null;
  affected_aer_ids: null;
  containment_remediation_arr_ids: null;
  transfer_suspension_atr_ids: null;
  post_breach_anr_id: null;
  qes_aar_id: null;
}

/**
 * Body for `breach.subject_notified` (spec §4.5).
 *
 * Art. 34 notification to affected subjects, batch-anchored.
 * `subject_batch_root` is a Merkle root over `sub_commit` leaves (canonical
 * sorted hex order); `subject_batch_size` is the leaf count. Maximum 65,536
 * leaves per receipt; larger incidents emit multiple receipts sharing
 * `incident_correlation_id` (D10-ABR-4 + spec §4.5).
 *
 * Per FAMILY-CONSISTENCY §3, the envelope `subject` field MUST be set to
 * `"sha256:<hex>"` (the batch root) on this event (enforced in §E).
 */
export interface AbrSubjectNotifiedBody extends AbrBodyBase {
  event_type: "breach.subject_notified";
  subject_batch_root: string;
  /** Integer; leaf count of `subject_batch_root` (max 65 536). */
  subject_batch_size: number;
  notification_uri: string;
  notification_hash: string;

  // Cross-event-pinned fields.
  detected_at: null;
  severity_class: null;
  affected_data_categories: null;
  affected_data_hash: null;
  affected_count: null;
  jurisdiction: null;
  assessment_method_hash: null;
  dpa_reference_id: null;
  notification_phase: null;
  delay_reason_hash: null;
  delay_until_at: null;
  exemption_ground: null;
  justification_hash: null;
  public_communication_uri: null;
  containment_at: null;
  containment_summary_hash: null;
  containment_attestation: null;
  closed_at: null;
  closure_dpa_reference_id: null;
  affected_aer_ids: null;
  containment_remediation_arr_ids: null;
  transfer_suspension_atr_ids: null;
  post_breach_anr_id: null;
  qes_aar_id: null;
}

/**
 * Body for `breach.subject_notification_exempted` (spec §4.6).
 *
 * One of the three Art. 34(3) grounds is asserted; `justification_hash`
 * SHA-256s the off-chain justification text. When
 * `exemption_ground === "art34_3_c_disproportionate"` the spec requires a
 * paired `public_communication_uri` (Art. 34(3)(c)). §C body verifier
 * surfaces `art34_3_c_public_comm_missing` when this is absent.
 */
export interface AbrSubjectNotificationExemptedBody extends AbrBodyBase {
  event_type: "breach.subject_notification_exempted";
  exemption_ground: AbrExemptionGround;
  justification_hash: string;
  /** Required when `exemption_ground === "art34_3_c_disproportionate"`; else `null`. */
  public_communication_uri: string | null;

  // Cross-event-pinned fields.
  detected_at: null;
  severity_class: null;
  affected_data_categories: null;
  affected_data_hash: null;
  affected_count: null;
  jurisdiction: null;
  assessment_method_hash: null;
  notification_uri: null;
  notification_hash: null;
  dpa_reference_id: null;
  notification_phase: null;
  delay_reason_hash: null;
  delay_until_at: null;
  subject_batch_root: null;
  subject_batch_size: null;
  containment_at: null;
  containment_summary_hash: null;
  containment_attestation: null;
  closed_at: null;
  closure_dpa_reference_id: null;
  affected_aer_ids: null;
  containment_remediation_arr_ids: null;
  transfer_suspension_atr_ids: null;
  post_breach_anr_id: null;
  qes_aar_id: null;
}

/**
 * Body for `breach.contained` (spec §4.7).
 *
 * Controller attestation that the breach is contained.
 * `containment_summary_hash` SHA-256s the containment narrative.
 *
 * Composition fields (audit fix C5):
 * - `containment_attestation`: optional AAR receipt id when containment is
 *   independently attested by a forensic firm (§8.1).
 * - `containment_remediation_arr_ids`: optional ARR receipt ids
 *   (`ar.erasure.v1` / `ar.anonymization.v1`) for forced-erasure
 *   remediation tying breach containment to subject-data outcomes (§8.3).
 * - `transfer_suspension_atr_ids`: optional ATR receipt ids
 *   (`ar.transfer.v1` with `body.event_type: "suspension"`) for
 *   cross-border transfer suspensions (§8.3).
 */
export interface AbrContainedBody extends AbrBodyBase {
  event_type: "breach.contained";
  containment_at: string;
  containment_summary_hash: string;

  /** Composition: optional AAR receipt id for independent attestation (§8.1). */
  containment_attestation: string | null;
  /** Composition: ARR (`ar.erasure.v1`/`ar.anonymization.v1`) receipt ids (§8.3). */
  containment_remediation_arr_ids: readonly string[] | null;
  /** Composition: ATR (`ar.transfer.v1`) receipt ids for transfer suspensions (§8.3). */
  transfer_suspension_atr_ids: readonly string[] | null;

  // Cross-event-pinned fields.
  detected_at: null;
  severity_class: null;
  affected_data_categories: null;
  affected_data_hash: null;
  affected_count: null;
  jurisdiction: null;
  assessment_method_hash: null;
  notification_uri: null;
  notification_hash: null;
  dpa_reference_id: null;
  notification_phase: null;
  delay_reason_hash: null;
  delay_until_at: null;
  subject_batch_root: null;
  subject_batch_size: null;
  exemption_ground: null;
  justification_hash: null;
  public_communication_uri: null;
  closed_at: null;
  closure_dpa_reference_id: null;
  affected_aer_ids: null;
  post_breach_anr_id: null;
  qes_aar_id: null;
}

/**
 * Body for `breach.closed` (spec §4.8).
 *
 * Terminal event in the incident chain. `closure_dpa_reference_id` is `null`
 * when no DPA was notified (low-risk path per §4.2).
 *
 * Composition: `post_breach_anr_id` carries an ANR receipt id when a
 * post-breach privacy-notice update has been published (§8.5 — audit
 * fix C5). The reverse direction is intentionally NOT supported (would
 * re-expose subjects).
 *
 * Status List 2021: §C/§F flips the incident chain's bit to `closed`
 * informationally (does not invalidate earlier receipts).
 */
export interface AbrClosedBody extends AbrBodyBase {
  event_type: "breach.closed";
  closed_at: string;
  closure_dpa_reference_id: string | null;

  /** Composition: ANR (`ar.notice.v1`) receipt id for post-breach notice update (§8.5). */
  post_breach_anr_id: string | null;

  // Cross-event-pinned fields.
  detected_at: null;
  severity_class: null;
  affected_data_categories: null;
  affected_data_hash: null;
  affected_count: null;
  jurisdiction: null;
  assessment_method_hash: null;
  notification_uri: null;
  notification_hash: null;
  dpa_reference_id: null;
  notification_phase: null;
  delay_reason_hash: null;
  delay_until_at: null;
  subject_batch_root: null;
  subject_batch_size: null;
  exemption_ground: null;
  justification_hash: null;
  public_communication_uri: null;
  containment_at: null;
  containment_summary_hash: null;
  containment_attestation: null;
  affected_aer_ids: null;
  containment_remediation_arr_ids: null;
  transfer_suspension_atr_ids: null;
  qes_aar_id: null;
}

/**
 * Discriminated union of all eight ABR body variants.
 * §C body verifier dispatches on `body.event_type`.
 */
export type AbrBody =
  | AbrDetectedBody
  | AbrAssessedBody
  | AbrDpaNotifiedBody
  | AbrDpaDelayedBody
  | AbrSubjectNotifiedBody
  | AbrSubjectNotificationExemptedBody
  | AbrContainedBody
  | AbrClosedBody;
