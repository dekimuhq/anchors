/**
 * Tests for `AsrBodySchema` — per-event MANDATORY field minimums (spec §4).
 *
 * Profile-specific extensions (Art. 18 `restriction_reason_code`, Art. 20
 * `portability_format`, Art. 21 `objection_scope` / `balancing_test_hash`,
 * Art. 17 `arr_receipt_id` MANDATORY link) are NOT enforced here — they
 * land in the profile validators (Phase 3 Step 7).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { AsrBodySchema } from "../src/body-schema.ts";
import {
  bodyEscalated,
  bodyExtended,
  bodyFulfilled,
  bodyIdentityVerified,
  bodyPartiallyHonoured,
  bodyRecipientNotified,
  bodyRefused,
  bodyRequestReceived,
  bodyScopeClarified,
} from "./_helpers/fixtures.ts";

// ── Happy paths — one per event_type ──────────────────────────────────────────

test("accepts request.received with all MANDATORY fields", () => {
  const r = AsrBodySchema.validate(bodyRequestReceived());
  assert.equal(r.ok, true);
});

test("accepts request.identity_verified with verification_method_hash", () => {
  const r = AsrBodySchema.validate(bodyIdentityVerified());
  assert.equal(r.ok, true);
});

test("accepts request.scope_clarified with scope_clarification_hash", () => {
  const r = AsrBodySchema.validate(bodyScopeClarified());
  assert.equal(r.ok, true);
});

test("accepts request.extended with extension_reason_hash + extended_until_at", () => {
  const r = AsrBodySchema.validate(bodyExtended());
  assert.equal(r.ok, true);
});

test("accepts request.partially_honoured with full required-field set", () => {
  const r = AsrBodySchema.validate(bodyPartiallyHonoured());
  assert.equal(r.ok, true);
});

test("accepts request.fulfilled with fulfilled_artifact_hash + fulfilment_uri", () => {
  const r = AsrBodySchema.validate(bodyFulfilled());
  assert.equal(r.ok, true);
});

test("accepts request.refused with refusal_ground + refusal_justification_hash", () => {
  const r = AsrBodySchema.validate(bodyRefused());
  assert.equal(r.ok, true);
});

test("accepts request.escalated with optional escalation_dpa_reference null", () => {
  const r = AsrBodySchema.validate(bodyEscalated());
  assert.equal(r.ok, true);
});

test("accepts request.recipient_notified with full required-field set", () => {
  const r = AsrBodySchema.validate(bodyRecipientNotified());
  assert.equal(r.ok, true);
});

// ── Common rejects (apply across event_types) ─────────────────────────────────

test("rejects non-object body", () => {
  for (const body of [null, undefined, "x", 42, [], true]) {
    const r = AsrBodySchema.validate(body);
    assert.equal(r.ok, false);
    if (!r.ok) assert.equal(r.reason, "asr_body_not_object");
  }
});

test("rejects unknown event_type", () => {
  const r = AsrBodySchema.validate({
    event_type: "request.unknown",
    subject_rights_request_id: "req-1",
  });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_unknown_event_type");
});

test("rejects body missing event_type", () => {
  const r = AsrBodySchema.validate({ subject_rights_request_id: "req-1" });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_unknown_event_type");
});

test("rejects body missing subject_rights_request_id", () => {
  const r = AsrBodySchema.validate({ event_type: "request.received" });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_missing_subject_rights_request_id");
});

test("rejects empty subject_rights_request_id", () => {
  const r = AsrBodySchema.validate({
    event_type: "request.received",
    subject_rights_request_id: "",
  });
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_missing_subject_rights_request_id");
});

// ── Per-event field rejects ───────────────────────────────────────────────────

test("request.received rejects invalid channel", () => {
  const body = { ...bodyRequestReceived(), channel: "carrier-pigeon" };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_invalid_channel");
});

test("request.received rejects malformed received_at", () => {
  const body = { ...bodyRequestReceived(), received_at: "yesterday" };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_invalid_received_at");
});

test("request.received rejects malformed deadline_at", () => {
  const body = { ...bodyRequestReceived(), deadline_at: "" };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_invalid_deadline_at");
});

test("request.identity_verified rejects missing verification_method_hash", () => {
  const body = { ...bodyIdentityVerified(), verification_method_hash: null };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_missing_verification_method_hash");
});

test("request.scope_clarified rejects missing scope_clarification_hash", () => {
  const body = { ...bodyScopeClarified(), scope_clarification_hash: "" };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_missing_scope_clarification_hash");
});

test("request.extended rejects missing extension_reason_hash", () => {
  const body = { ...bodyExtended(), extension_reason_hash: null };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_missing_extension_reason_hash");
});

test("request.extended rejects malformed extended_until_at", () => {
  const body = { ...bodyExtended(), extended_until_at: "soon" };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_invalid_extended_until_at");
});

test("request.partially_honoured rejects non-array fulfilled_partial_scope", () => {
  const body = { ...bodyPartiallyHonoured(), fulfilled_partial_scope: "art15" };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_invalid_fulfilled_partial_scope");
});

test("request.partially_honoured rejects invalid refusal_ground", () => {
  const body = { ...bodyPartiallyHonoured(), refusal_ground: "made_up" };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_invalid_refusal_ground");
});

test("request.fulfilled rejects missing fulfilled_artifact_hash", () => {
  const body = { ...bodyFulfilled(), fulfilled_artifact_hash: "" };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_missing_fulfilled_artifact_hash");
});

test("request.fulfilled rejects missing fulfilment_uri", () => {
  const body = { ...bodyFulfilled(), fulfilment_uri: null };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_missing_fulfilment_uri");
});

test("request.refused rejects invalid refusal_ground", () => {
  const body = { ...bodyRefused(), refusal_ground: "no" };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_invalid_refusal_ground");
});

test("request.refused rejects missing refusal_justification_hash", () => {
  const body = { ...bodyRefused(), refusal_justification_hash: null };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_missing_refusal_justification_hash");
});

test("request.recipient_notified rejects empty recipient_set_alr_ids", () => {
  const body = { ...bodyRecipientNotified(), recipient_set_alr_ids: [] };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_invalid_recipient_set_alr_ids");
});

test("request.recipient_notified rejects non-array recipient_set_alr_ids", () => {
  const body = { ...bodyRecipientNotified(), recipient_set_alr_ids: "alr_x" };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_invalid_recipient_set_alr_ids");
});

test("request.recipient_notified rejects missing recipient_notification_uri", () => {
  const body = { ...bodyRecipientNotified(), recipient_notification_uri: "" };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_missing_recipient_notification_uri");
});

test("request.recipient_notified rejects missing recipient_notification_hash", () => {
  const body = { ...bodyRecipientNotified(), recipient_notification_hash: null };
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.reason, "asr_missing_recipient_notification_hash");
});

test("returned ok-value is the same body object reference", () => {
  const body = bodyRequestReceived();
  const r = AsrBodySchema.validate(body);
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.value, body);
  }
});

test("escalated event accepts both null and non-null escalation_dpa_reference", () => {
  assert.equal(AsrBodySchema.validate(bodyEscalated()).ok, true);
  const withRef = { ...bodyEscalated(), escalation_dpa_reference: "AEPD-2026-001" };
  assert.equal(AsrBodySchema.validate(withRef).ok, true);
});
