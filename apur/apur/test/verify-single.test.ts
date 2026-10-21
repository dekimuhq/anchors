/**
 * Tests for the per-event-type APuR body verifier (spec §4).
 *
 * Coverage: body.not_object, event_type.unknown, all three event types with
 * happy paths, per-field missing tests, enum validation, nullable ref handling,
 * and data_categories shape rules.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyApurBody } from "../src/verify-single.ts";

// ── Fixtures ──────────────────────────────────────────────────────────────────

function binding(over: Record<string, unknown> = {}) {
  return {
    event_type: "binding",
    activity_id_commit: "sha256:aaaa",
    purpose_commit: "sha256:bbbb",
    purpose_class: "marketing_analytics",
    lawful_basis: "consent",
    data_categories: ["email", "ip_address"],
    data_subjects_class: "customers",
    policy_hash: "sha256:cccc",
    minimisation_hash: "sha256:dddd",
    consent_receipt_hash: null,
    retention_receipt_hash: null,
    transfer_arrangement_hash: null,
    bound_at: "2026-05-21T10:00:00Z",
    ...over,
  };
}

function repurpose(over: Record<string, unknown> = {}) {
  return {
    event_type: "repurpose",
    new_purpose_commit: "sha256:eeee",
    new_purpose_class: "fraud_detection",
    compat_link_hash: "sha256:f111",
    compat_context_hash: "sha256:f222",
    compat_subjects_reasonable_hash: "sha256:f333",
    compat_consequences_hash: "sha256:f444",
    compat_safeguards_hash: "sha256:f555",
    compat_conclusion: "compatible",
    minimisation_hash: "sha256:f666",
    tested_at: "2026-05-21T11:00:00Z",
    ...over,
  };
}

function unbinding(over: Record<string, unknown> = {}) {
  return {
    event_type: "unbinding",
    reason: "purpose_fulfilled",
    downstream_arr_receipt_hash: null,
    unbound_at: "2026-05-21T12:00:00Z",
    ...over,
  };
}

// ── body.not_object ───────────────────────────────────────────────────────────

test("null -> body.not_object", () => {
  const r = verifyApurBody(null);
  assert.equal(r.valid, false);
  assert.equal(r.errors[0], "body.not_object");
  assert.equal(r.body, null);
});

test("undefined -> body.not_object", () => {
  const r = verifyApurBody(undefined);
  assert.equal(r.valid, false);
  assert.equal(r.errors[0], "body.not_object");
});

test("string -> body.not_object", () => {
  const r = verifyApurBody("binding");
  assert.equal(r.valid, false);
  assert.equal(r.errors[0], "body.not_object");
});

test("number -> body.not_object", () => {
  const r = verifyApurBody(42);
  assert.equal(r.valid, false);
  assert.equal(r.errors[0], "body.not_object");
});

// ── event_type.unknown ────────────────────────────────────────────────────────

test("missing event_type -> event_type.unknown", () => {
  const r = verifyApurBody({ ...binding(), event_type: undefined });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("event_type.unknown"), r.errors.join("|"));
});

test("unknown event_type -> event_type.unknown", () => {
  const r = verifyApurBody({ ...binding(), event_type: "transfer" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("event_type.unknown"), r.errors.join("|"));
});

// ── binding: happy path ───────────────────────────────────────────────────────

test("binding: valid minimal body -> valid", () => {
  const r = verifyApurBody(binding());
  assert.equal(r.valid, true, r.errors.join("|"));
  assert.equal(r.body?.event_type, "binding");
});

// ── binding: missing required fields ─────────────────────────────────────────

test("binding: missing activity_id_commit -> error", () => {
  const r = verifyApurBody(binding({ activity_id_commit: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("activity_id_commit.missing"), r.errors.join("|"));
});

test("binding: missing purpose_commit -> error", () => {
  const r = verifyApurBody(binding({ purpose_commit: undefined }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("purpose_commit.missing"), r.errors.join("|"));
});

test("binding: missing purpose_class -> error", () => {
  const r = verifyApurBody(binding({ purpose_class: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("purpose_class.missing"), r.errors.join("|"));
});

test("binding: missing lawful_basis -> error", () => {
  const r = verifyApurBody(binding({ lawful_basis: undefined }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("lawful_basis.missing"), r.errors.join("|"));
});

test("binding: missing data_subjects_class -> error", () => {
  const r = verifyApurBody(binding({ data_subjects_class: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("data_subjects_class.missing"), r.errors.join("|"));
});

test("binding: missing policy_hash -> error", () => {
  const r = verifyApurBody(binding({ policy_hash: undefined }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("policy_hash.missing"), r.errors.join("|"));
});

test("binding: missing minimisation_hash -> error", () => {
  const r = verifyApurBody(binding({ minimisation_hash: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("minimisation_hash.missing"), r.errors.join("|"));
});

test("binding: missing bound_at -> error", () => {
  const r = verifyApurBody(binding({ bound_at: undefined }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("bound_at.missing"), r.errors.join("|"));
});

// ── binding: data_categories shape ───────────────────────────────────────────

test("binding: data_categories empty array -> invalid", () => {
  const r = verifyApurBody(binding({ data_categories: [] }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("data_categories.invalid"), r.errors.join("|"));
});

test("binding: data_categories not array -> invalid", () => {
  const r = verifyApurBody(binding({ data_categories: "email" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("data_categories.invalid"), r.errors.join("|"));
});

test("binding: data_categories array with non-string item -> invalid", () => {
  const r = verifyApurBody(binding({ data_categories: ["email", 42] }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("data_categories.invalid"), r.errors.join("|"));
});

// ── binding: nullable refs ────────────────────────────────────────────────────

test("binding: consent_receipt_hash null -> valid", () => {
  const r = verifyApurBody(binding({ consent_receipt_hash: null }));
  assert.equal(r.valid, true, r.errors.join("|"));
});

test("binding: consent_receipt_hash string -> valid", () => {
  const r = verifyApurBody(binding({ consent_receipt_hash: "sha256:acr1" }));
  assert.equal(r.valid, true, r.errors.join("|"));
});

test("binding: consent_receipt_hash number -> invalid", () => {
  const r = verifyApurBody(binding({ consent_receipt_hash: 99 }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("consent_receipt_hash.invalid"), r.errors.join("|"));
});

test("binding: retention_receipt_hash number -> invalid", () => {
  const r = verifyApurBody(binding({ retention_receipt_hash: true }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("retention_receipt_hash.invalid"), r.errors.join("|"));
});

test("binding: transfer_arrangement_hash number -> invalid", () => {
  const r = verifyApurBody(binding({ transfer_arrangement_hash: [] }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("transfer_arrangement_hash.invalid"), r.errors.join("|"));
});

// ── repurpose: happy path ─────────────────────────────────────────────────────

test("repurpose: valid body -> valid", () => {
  const r = verifyApurBody(repurpose());
  assert.equal(r.valid, true, r.errors.join("|"));
  assert.equal(r.body?.event_type, "repurpose");
});

// ── repurpose: missing required fields ───────────────────────────────────────

test("repurpose: missing new_purpose_commit -> error", () => {
  const r = verifyApurBody(repurpose({ new_purpose_commit: undefined }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("new_purpose_commit.missing"), r.errors.join("|"));
});

test("repurpose: missing new_purpose_class -> error", () => {
  const r = verifyApurBody(repurpose({ new_purpose_class: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("new_purpose_class.missing"), r.errors.join("|"));
});

test("repurpose: missing compat_link_hash -> error", () => {
  const r = verifyApurBody(repurpose({ compat_link_hash: undefined }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("compat_link_hash.missing"), r.errors.join("|"));
});

test("repurpose: missing compat_context_hash -> error", () => {
  const r = verifyApurBody(repurpose({ compat_context_hash: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("compat_context_hash.missing"), r.errors.join("|"));
});

test("repurpose: missing compat_subjects_reasonable_hash -> error", () => {
  const r = verifyApurBody(repurpose({ compat_subjects_reasonable_hash: undefined }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("compat_subjects_reasonable_hash.missing"), r.errors.join("|"));
});

test("repurpose: missing compat_consequences_hash -> error", () => {
  const r = verifyApurBody(repurpose({ compat_consequences_hash: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("compat_consequences_hash.missing"), r.errors.join("|"));
});

test("repurpose: missing compat_safeguards_hash -> error", () => {
  const r = verifyApurBody(repurpose({ compat_safeguards_hash: undefined }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("compat_safeguards_hash.missing"), r.errors.join("|"));
});

test("repurpose: missing minimisation_hash -> error", () => {
  const r = verifyApurBody(repurpose({ minimisation_hash: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("minimisation_hash.missing"), r.errors.join("|"));
});

test("repurpose: missing tested_at -> error", () => {
  const r = verifyApurBody(repurpose({ tested_at: undefined }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("tested_at.missing"), r.errors.join("|"));
});

// ── repurpose: compat_conclusion enum ────────────────────────────────────────

test("repurpose: compat_conclusion 'compatible' -> valid", () => {
  const r = verifyApurBody(repurpose({ compat_conclusion: "compatible" }));
  assert.equal(r.valid, true, r.errors.join("|"));
});

test("repurpose: compat_conclusion 'incompatible_requires_new_basis' -> valid", () => {
  const r = verifyApurBody(repurpose({ compat_conclusion: "incompatible_requires_new_basis" }));
  assert.equal(r.valid, true, r.errors.join("|"));
});

test("repurpose: compat_conclusion 'incompatible_aborted' -> valid", () => {
  const r = verifyApurBody(repurpose({ compat_conclusion: "incompatible_aborted" }));
  assert.equal(r.valid, true, r.errors.join("|"));
});

test("repurpose: invalid compat_conclusion -> compat_conclusion.invalid", () => {
  const r = verifyApurBody(repurpose({ compat_conclusion: "partially_compatible" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("compat_conclusion.invalid"), r.errors.join("|"));
});

test("repurpose: null compat_conclusion -> compat_conclusion.missing", () => {
  const r = verifyApurBody(repurpose({ compat_conclusion: null }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("compat_conclusion.missing"), r.errors.join("|"));
});

// ── unbinding: happy path ─────────────────────────────────────────────────────

test("unbinding: valid body -> valid", () => {
  const r = verifyApurBody(unbinding());
  assert.equal(r.valid, true, r.errors.join("|"));
  assert.equal(r.body?.event_type, "unbinding");
});

// ── unbinding: all 7 reason values ───────────────────────────────────────────

test("unbinding: reason 'purpose_fulfilled' -> valid", () => {
  assert.equal(verifyApurBody(unbinding({ reason: "purpose_fulfilled" })).valid, true);
});

test("unbinding: reason 'consent_withdrawn' -> valid", () => {
  assert.equal(verifyApurBody(unbinding({ reason: "consent_withdrawn" })).valid, true);
});

test("unbinding: reason 'controller_decision' -> valid", () => {
  assert.equal(verifyApurBody(unbinding({ reason: "controller_decision" })).valid, true);
});

test("unbinding: reason 'retention_expired' -> valid", () => {
  assert.equal(verifyApurBody(unbinding({ reason: "retention_expired" })).valid, true);
});

test("unbinding: reason 'subject_request_art17' -> valid", () => {
  assert.equal(verifyApurBody(unbinding({ reason: "subject_request_art17" })).valid, true);
});

test("unbinding: reason 'regulator_order' -> valid", () => {
  assert.equal(verifyApurBody(unbinding({ reason: "regulator_order" })).valid, true);
});

test("unbinding: reason 'mechanism_struck_down' -> valid", () => {
  assert.equal(verifyApurBody(unbinding({ reason: "mechanism_struck_down" })).valid, true);
});

test("unbinding: invalid reason -> reason.invalid", () => {
  const r = verifyApurBody(unbinding({ reason: "expired" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("reason.invalid"), r.errors.join("|"));
});

// ── unbinding: missing fields ─────────────────────────────────────────────────

test("unbinding: missing unbound_at -> error", () => {
  const r = verifyApurBody(unbinding({ unbound_at: undefined }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("unbound_at.missing"), r.errors.join("|"));
});

// ── unbinding: downstream_arr_receipt_hash nullable ref ──────────────────────

test("unbinding: downstream_arr_receipt_hash null -> valid", () => {
  const r = verifyApurBody(unbinding({ downstream_arr_receipt_hash: null }));
  assert.equal(r.valid, true, r.errors.join("|"));
});

test("unbinding: downstream_arr_receipt_hash string -> valid", () => {
  const r = verifyApurBody(unbinding({ downstream_arr_receipt_hash: "sha256:arr1" }));
  assert.equal(r.valid, true, r.errors.join("|"));
});

test("unbinding: downstream_arr_receipt_hash number -> invalid", () => {
  const r = verifyApurBody(unbinding({ downstream_arr_receipt_hash: 0 }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("downstream_arr_receipt_hash.invalid"), r.errors.join("|"));
});
