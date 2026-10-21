/**
 * ASR — TypeScript types for the `ar.subject_rights.v1` claim_type.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/asr
 *
 * Phase 3 greenfield via `defineFamily()` — there is no hand-rolled
 * `envelope-v2.ts`; runtime validation lives in `body-schema.ts` and is
 * wired into the factory through `asrFamily.body_schema`. Profile-specific
 * required-field minimums (Art. 18 `restriction_reason_code`, Art. 20
 * `portability_format`, Art. 21 `objection_scope` / `balancing_test_hash`)
 * are enforced by the profile validators in `@dekimuhq/asr-profiles`, not
 * here — body-schema enforces ONLY the per-event minimums from spec §4.
 */

/** ASR's single claim_type discriminator. */
export type AsrClaimType = "ar.subject_rights.v1";

/** Nine event types per spec §4. Closed enum; unknown values reject. */
export type AsrEventType =
  | "request.received"
  | "request.identity_verified"
  | "request.scope_clarified"
  | "request.extended"
  | "request.partially_honoured"
  | "request.fulfilled"
  | "request.refused"
  | "request.escalated"
  | "request.recipient_notified";

export const ASR_EVENT_TYPES: readonly AsrEventType[] = [
  "request.received",
  "request.identity_verified",
  "request.scope_clarified",
  "request.extended",
  "request.partially_honoured",
  "request.fulfilled",
  "request.refused",
  "request.escalated",
  "request.recipient_notified",
] as const;

/** Six v1 profile IDs per spec §5. */
export type AsrProfile =
  | "subject_rights.art15.access"
  | "subject_rights.art16.rectification"
  | "subject_rights.art17.erasure_request"
  | "subject_rights.art18.restriction"
  | "subject_rights.art20.portability"
  | "subject_rights.art21.objection";

export const ASR_PROFILES: readonly AsrProfile[] = [
  "subject_rights.art15.access",
  "subject_rights.art16.rectification",
  "subject_rights.art17.erasure_request",
  "subject_rights.art18.restriction",
  "subject_rights.art20.portability",
  "subject_rights.art21.objection",
] as const;

/** Channel through which the subject-rights request arrived (spec §3.1). */
export type AsrChannel =
  | "email"
  | "web_form"
  | "postal"
  | "in_person"
  | "phone"
  | "api";

export const ASR_CHANNELS: readonly AsrChannel[] = [
  "email",
  "web_form",
  "postal",
  "in_person",
  "phone",
  "api",
] as const;

/**
 * Refusal grounds — closed enum covering Art. 12(5) and right-specific
 * Art. 17(3) exemptions (spec §4.7 + §5.3).
 */
export type AsrRefusalGround =
  | "art12_5_a_unfounded"
  | "art12_5_b_excessive"
  | "art17_3_a_freedom_of_expression"
  | "art17_3_b_legal_obligation"
  | "art17_3_c_public_interest"
  | "art17_3_d_research_archiving"
  | "art17_3_e_legal_claims";

export const ASR_REFUSAL_GROUNDS: readonly AsrRefusalGround[] = [
  "art12_5_a_unfounded",
  "art12_5_b_excessive",
  "art17_3_a_freedom_of_expression",
  "art17_3_b_legal_obligation",
  "art17_3_c_public_interest",
  "art17_3_d_research_archiving",
  "art17_3_e_legal_claims",
] as const;

/**
 * Common body fields present on every ASR event type. Per-event extensions
 * narrow this through the discriminated union below.
 */
interface AsrBodyBase {
  readonly event_type: AsrEventType;
  /** Per spec D10-ASR-2 — identical across all receipts in one request lifecycle. */
  readonly subject_rights_request_id: string;
  /** SHA-256 hash of an AAR receipt attesting QTS posture. `null` when absent. */
  readonly qts_attestation_hash: string | null;
}

/** §4.1 — `request.received` clock-start event. */
export interface AsrRequestReceivedBody extends AsrBodyBase {
  readonly event_type: "request.received";
  readonly channel: AsrChannel;
  readonly received_at: string;
  readonly deadline_at: string;
}

/** §4.2 — `request.identity_verified`. */
export interface AsrIdentityVerifiedBody extends AsrBodyBase {
  readonly event_type: "request.identity_verified";
  readonly verification_method_hash: string;
}

/** §4.3 — `request.scope_clarified`. */
export interface AsrScopeClarifiedBody extends AsrBodyBase {
  readonly event_type: "request.scope_clarified";
  readonly scope_clarification_hash: string;
}

/** §4.4 — `request.extended`. */
export interface AsrExtendedBody extends AsrBodyBase {
  readonly event_type: "request.extended";
  readonly extension_reason_hash: string;
  readonly extended_until_at: string;
}

/** §4.5 — `request.partially_honoured`. */
export interface AsrPartiallyHonouredBody extends AsrBodyBase {
  readonly event_type: "request.partially_honoured";
  readonly fulfilled_partial_scope: readonly string[];
  readonly fulfilled_artifact_hash: string;
  readonly fulfilment_uri: string;
  readonly refusal_ground: AsrRefusalGround;
  readonly refusal_justification_hash: string;
}

/** §4.6 — `request.fulfilled`. */
export interface AsrFulfilledBody extends AsrBodyBase {
  readonly event_type: "request.fulfilled";
  readonly fulfilled_artifact_hash: string;
  readonly fulfilment_uri: string;
  /** Required on `subject_rights.art17.erasure_request` profile (D10-ASR-3); validated by profile. */
  readonly arr_receipt_id?: string | null;
  /** Required on `subject_rights.art20.portability` profile (§5.5); validated by profile. */
  readonly portability_format?: string | null;
}

/** §4.7 — `request.refused`. */
export interface AsrRefusedBody extends AsrBodyBase {
  readonly event_type: "request.refused";
  readonly refusal_ground: AsrRefusalGround;
  readonly refusal_justification_hash: string;
}

/** §4.8 — `request.escalated`. */
export interface AsrEscalatedBody extends AsrBodyBase {
  readonly event_type: "request.escalated";
  readonly escalation_dpa_reference?: string | null;
}

/** §4.9 — `request.recipient_notified` (Art. 19 cascade). */
export interface AsrRecipientNotifiedBody extends AsrBodyBase {
  readonly event_type: "request.recipient_notified";
  readonly recipient_set_alr_ids: readonly string[];
  readonly recipient_notification_uri: string;
  readonly recipient_notification_hash: string;
}

/** Discriminated union over `event_type` covering all 9 events. */
export type AsrBody =
  | AsrRequestReceivedBody
  | AsrIdentityVerifiedBody
  | AsrScopeClarifiedBody
  | AsrExtendedBody
  | AsrPartiallyHonouredBody
  | AsrFulfilledBody
  | AsrRefusedBody
  | AsrEscalatedBody
  | AsrRecipientNotifiedBody;
