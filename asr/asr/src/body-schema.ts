/**
 * ASR — runtime body validator wired into `asrFamily.body_schema`.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/anr §3.1 + §4.
 *
 * Pipeline contract (per `@dekimuhq/anchors-envelope` `BodyValidator<T>`):
 * pure, total (never throws), returns `{ ok: true, value }` or
 * `{ ok: false, reason }`. The factory invokes this in the mint pipeline
 * before signing and in the verify pipeline before profile dispatch.
 *
 * Scope: per-event MANDATORY fields from spec §4 only. Profile-specific
 * extensions (Art. 18 `restriction_reason_code`, Art. 20 `portability_format`,
 * Art. 21 `objection_scope` / `balancing_test_hash`, Art. 17 `arr_receipt_id`
 * MANDATORY cross-link) are enforced by the per-profile validators in
 * `@dekimuhq/asr-profiles`. Composition (resolving `arr_receipt_id` against
 * a real ARR receipt) is deferred to Phase 3 §G post-Phase-3.
 */

import type { BodyValidator } from "@dekimuhq/anchors-envelope";
import {
  ASR_CHANNELS,
  ASR_EVENT_TYPES,
  ASR_REFUSAL_GROUNDS,
  type AsrBody,
  type AsrChannel,
  type AsrEventType,
  type AsrRefusalGround,
} from "./types.ts";

const ISO8601_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const isNonEmptyString = (v: unknown): v is string =>
  typeof v === "string" && v.length > 0;

const isIso8601 = (v: unknown): v is string =>
  typeof v === "string" && ISO8601_RE.test(v);

const isStringArray = (v: unknown): v is readonly string[] =>
  Array.isArray(v) && v.every((x) => typeof x === "string" && x.length > 0);

const isAsrEventType = (v: unknown): v is AsrEventType =>
  typeof v === "string" && (ASR_EVENT_TYPES as readonly string[]).includes(v);

const isAsrChannel = (v: unknown): v is AsrChannel =>
  typeof v === "string" && (ASR_CHANNELS as readonly string[]).includes(v);

const isAsrRefusalGround = (v: unknown): v is AsrRefusalGround =>
  typeof v === "string" && (ASR_REFUSAL_GROUNDS as readonly string[]).includes(v);

const fail = (reason: string) => ({ ok: false as const, reason });

export const AsrBodySchema: BodyValidator<AsrBody> = {
  validate(body) {
    if (!isObject(body)) return fail("asr_body_not_object");
    if (!isAsrEventType(body["event_type"])) return fail("asr_unknown_event_type");
    if (!isNonEmptyString(body["subject_rights_request_id"])) {
      return fail("asr_missing_subject_rights_request_id");
    }

    const event_type = body["event_type"];

    switch (event_type) {
      case "request.received": {
        if (!isAsrChannel(body["channel"])) return fail("asr_invalid_channel");
        if (!isIso8601(body["received_at"])) return fail("asr_invalid_received_at");
        if (!isIso8601(body["deadline_at"])) return fail("asr_invalid_deadline_at");
        break;
      }
      case "request.identity_verified": {
        if (!isNonEmptyString(body["verification_method_hash"])) {
          return fail("asr_missing_verification_method_hash");
        }
        break;
      }
      case "request.scope_clarified": {
        if (!isNonEmptyString(body["scope_clarification_hash"])) {
          return fail("asr_missing_scope_clarification_hash");
        }
        break;
      }
      case "request.extended": {
        if (!isNonEmptyString(body["extension_reason_hash"])) {
          return fail("asr_missing_extension_reason_hash");
        }
        if (!isIso8601(body["extended_until_at"])) {
          return fail("asr_invalid_extended_until_at");
        }
        break;
      }
      case "request.partially_honoured": {
        if (!isStringArray(body["fulfilled_partial_scope"])) {
          return fail("asr_invalid_fulfilled_partial_scope");
        }
        if (!isNonEmptyString(body["fulfilled_artifact_hash"])) {
          return fail("asr_missing_fulfilled_artifact_hash");
        }
        if (!isNonEmptyString(body["fulfilment_uri"])) {
          return fail("asr_missing_fulfilment_uri");
        }
        if (!isAsrRefusalGround(body["refusal_ground"])) {
          return fail("asr_invalid_refusal_ground");
        }
        if (!isNonEmptyString(body["refusal_justification_hash"])) {
          return fail("asr_missing_refusal_justification_hash");
        }
        break;
      }
      case "request.fulfilled": {
        if (!isNonEmptyString(body["fulfilled_artifact_hash"])) {
          return fail("asr_missing_fulfilled_artifact_hash");
        }
        if (!isNonEmptyString(body["fulfilment_uri"])) {
          return fail("asr_missing_fulfilment_uri");
        }
        break;
      }
      case "request.refused": {
        if (!isAsrRefusalGround(body["refusal_ground"])) {
          return fail("asr_invalid_refusal_ground");
        }
        if (!isNonEmptyString(body["refusal_justification_hash"])) {
          return fail("asr_missing_refusal_justification_hash");
        }
        break;
      }
      case "request.escalated": {
        break;
      }
      case "request.recipient_notified": {
        if (!isStringArray(body["recipient_set_alr_ids"]) || body["recipient_set_alr_ids"].length === 0) {
          return fail("asr_invalid_recipient_set_alr_ids");
        }
        if (!isNonEmptyString(body["recipient_notification_uri"])) {
          return fail("asr_missing_recipient_notification_uri");
        }
        if (!isNonEmptyString(body["recipient_notification_hash"])) {
          return fail("asr_missing_recipient_notification_hash");
        }
        break;
      }
    }

    return { ok: true, value: body as unknown as AsrBody };
  },
};
