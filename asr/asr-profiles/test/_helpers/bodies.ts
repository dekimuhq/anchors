/**
 * Body-fixture helpers for ASR profile-validator tests.
 *
 * Each helper builds a minimal valid `AsrBody` of a given event_type. Tests
 * spread overrides into these to exercise profile-specific extensions
 * (Art. 17 `arr_receipt_id`, Art. 18 `restriction_reason_code`, Art. 20
 * `portability_format` + `portability_format_detail`, Art. 21
 * `objection_scope` + `balancing_test_hash`).
 *
 * Profile-extension fields are NOT typed on `AsrBody` — they ride alongside
 * the per-event typed fields. We model them here via index-signature
 * extension on the typed body, kept readonly to mirror the source types.
 */

import type {
  AsrBody,
  AsrEscalatedBody,
  AsrExtendedBody,
  AsrFulfilledBody,
  AsrIdentityVerifiedBody,
  AsrPartiallyHonouredBody,
  AsrRecipientNotifiedBody,
  AsrRefusedBody,
  AsrRequestReceivedBody,
  AsrScopeClarifiedBody,
} from "@dekimuhq/asr-profiles/body-types";

const REQ_ID = "f4b2d4c0-6e1c-4b9f-9b6d-1a2b3c4d5e6f";

const sha256 = (seed: string): string =>
  `sha256:${seed.repeat(64).slice(0, 64)}`;

export function received(
  overrides: Partial<AsrRequestReceivedBody> = {},
): AsrRequestReceivedBody {
  return {
    event_type: "request.received",
    subject_rights_request_id: REQ_ID,
    qts_attestation_hash: null,
    channel: "email",
    received_at: "2026-05-19T08:00:00Z",
    deadline_at: "2026-06-18T08:00:00Z",
    ...overrides,
  };
}

export function identityVerified(
  overrides: Partial<AsrIdentityVerifiedBody> = {},
): AsrIdentityVerifiedBody {
  return {
    event_type: "request.identity_verified",
    subject_rights_request_id: REQ_ID,
    qts_attestation_hash: null,
    verification_method_hash: sha256("1"),
    ...overrides,
  };
}

export function scopeClarified(
  overrides: Partial<AsrScopeClarifiedBody> = {},
): AsrScopeClarifiedBody {
  return {
    event_type: "request.scope_clarified",
    subject_rights_request_id: REQ_ID,
    qts_attestation_hash: null,
    scope_clarification_hash: sha256("2"),
    ...overrides,
  };
}

export function extended(
  overrides: Partial<AsrExtendedBody> = {},
): AsrExtendedBody {
  return {
    event_type: "request.extended",
    subject_rights_request_id: REQ_ID,
    qts_attestation_hash: null,
    extension_reason_hash: sha256("3"),
    extended_until_at: "2026-07-18T08:00:00Z",
    ...overrides,
  };
}

export function partiallyHonoured(
  overrides: Partial<AsrPartiallyHonouredBody> = {},
): AsrPartiallyHonouredBody {
  return {
    event_type: "request.partially_honoured",
    subject_rights_request_id: REQ_ID,
    qts_attestation_hash: null,
    fulfilled_partial_scope: ["art15"],
    fulfilled_artifact_hash: sha256("4"),
    fulfilment_uri: "https://example.test/partial",
    refusal_ground: "art17_3_b_legal_obligation",
    refusal_justification_hash: sha256("5"),
    ...overrides,
  };
}

/**
 * `request.fulfilled` body builder. Accepts the typed override surface plus
 * the profile-extension fields not present on `AsrFulfilledBody`
 * (`restriction_reason_code`, `objection_scope`, `balancing_test_hash`,
 * `portability_format_detail`).
 */
export function fulfilled(
  overrides: Partial<AsrFulfilledBody> & {
    restriction_reason_code?: string;
    objection_scope?: string;
    balancing_test_hash?: string;
    portability_format_detail?: string;
  } = {},
): AsrBody {
  const base: AsrFulfilledBody = {
    event_type: "request.fulfilled",
    subject_rights_request_id: REQ_ID,
    qts_attestation_hash: null,
    fulfilled_artifact_hash: sha256("6"),
    fulfilment_uri: "https://example.test/artifact",
  };
  return { ...base, ...overrides } as AsrBody;
}

export function refused(
  overrides: Partial<AsrRefusedBody> = {},
): AsrRefusedBody {
  return {
    event_type: "request.refused",
    subject_rights_request_id: REQ_ID,
    qts_attestation_hash: null,
    refusal_ground: "art12_5_a_unfounded",
    refusal_justification_hash: sha256("7"),
    ...overrides,
  };
}

export function escalated(
  overrides: Partial<AsrEscalatedBody> = {},
): AsrEscalatedBody {
  return {
    event_type: "request.escalated",
    subject_rights_request_id: REQ_ID,
    qts_attestation_hash: null,
    escalation_dpa_reference: null,
    ...overrides,
  };
}

export function recipientNotified(
  overrides: Partial<AsrRecipientNotifiedBody> = {},
): AsrRecipientNotifiedBody {
  return {
    event_type: "request.recipient_notified",
    subject_rights_request_id: REQ_ID,
    qts_attestation_hash: null,
    recipient_set_alr_ids: ["alr_01HK0000000000000000000001"],
    recipient_notification_uri: "https://example.test/art19-notify",
    recipient_notification_hash: sha256("8"),
    ...overrides,
  };
}

/** Re-exported sha256 helper for tests that want to seed extra hashes. */
export const H = sha256;
