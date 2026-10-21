/**
 * Tests for the per-event-type ATR body verifier (spec §4).
 *
 * Coverage: one happy path per event_type plus the rejection cases for each
 * required field, shared field failures (body.not_object, event_type.unknown),
 * and enum validation for subject_count_bucket, assessment_outcome, trigger.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyAtrBody } from "../src/verify-single.ts";

// ── Fixtures ──────────────────────────────────────────────────────────────────

function arrangement(over: Record<string, unknown> = {}) {
  return {
    event_type: "arrangement",
    arrangement_id_commit: "sha256:aaa" + "a".repeat(61),
    recipient_commit: "sha256:bbb" + "b".repeat(61),
    destination_country: "US",
    mechanism_version: "scc-2021-c-pp",
    contract_doc_hash: "sha256:ccc" + "c".repeat(61),
    in_force_from: "2026-01-01T00:00:00Z",
    in_force_until: null,
    supplementary_measures_hash: "sha256:ddd" + "d".repeat(61),
    qts_attestation_hash: null,
    ...over,
  };
}

function transfer(over: Record<string, unknown> = {}) {
  return {
    event_type: "transfer",
    arrangement_hash: "sha256:aaa" + "a".repeat(61),
    tia_hash: null,
    destination_country: "US",
    recipient_commit: "sha256:bbb" + "b".repeat(61),
    data_categories: ["contact", "financial"],
    subject_count_bucket: "10_99",
    transfer_window_start: "2026-01-01T00:00:00Z",
    transfer_window_end: "2026-01-31T23:59:59Z",
    artifact_apr_hash: null,
    consent_receipt_hash: null,
    purpose_binding_hash: null,
    qts_attestation_hash: null,
    ...over,
  };
}

function tia(over: Record<string, unknown> = {}) {
  return {
    event_type: "tia",
    arrangement_hash: "sha256:aaa" + "a".repeat(61),
    destination_country: "US",
    assessment_doc_hash: "sha256:ccc" + "c".repeat(61),
    surveillance_law_refs: ["18 U.S.C. § 702"],
    assessment_outcome: "permitted_with_supplementary",
    supplementary_measures_hash: "sha256:ddd" + "d".repeat(61),
    valid_from: "2026-01-01T00:00:00Z",
    valid_until: "2027-01-01T00:00:00Z",
    qts_attestation_hash: null,
    ...over,
  };
}

function suspension(over: Record<string, unknown> = {}) {
  return {
    event_type: "suspension",
    trigger: "dpa_order",
    trigger_ref_hash: "sha256:eee" + "e".repeat(61),
    effective_at: "2026-06-01T00:00:00Z",
    qts_attestation_hash: null,
    ...over,
  };
}

// ── Happy paths ───────────────────────────────────────────────────────────────

test("arrangement: minimal valid body -> valid", () => {
  const out = verifyAtrBody(arrangement());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "arrangement");
});

test("arrangement: in_force_until as string is valid", () => {
  const out = verifyAtrBody(arrangement({ in_force_until: "2028-01-01T00:00:00Z" }));
  assert.equal(out.valid, true, out.errors.join("|"));
});

test("transfer: minimal valid body -> valid", () => {
  const out = verifyAtrBody(transfer());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "transfer");
});

test("transfer: all subject_count_bucket values accepted", () => {
  const buckets = ["1", "2_9", "10_99", "100_999", "1k_9k", "10k_99k", "100k_plus"];
  for (const bucket of buckets) {
    const out = verifyAtrBody(transfer({ subject_count_bucket: bucket }));
    assert.equal(out.valid, true, `bucket=${bucket}: ${out.errors.join("|")}`);
  }
});

test("tia: minimal valid body -> valid", () => {
  const out = verifyAtrBody(tia());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "tia");
});

test("tia: all assessment_outcome values accepted", () => {
  const outcomes = ["permitted_plain", "permitted_with_supplementary", "not_permitted"];
  for (const outcome of outcomes) {
    const out = verifyAtrBody(tia({ assessment_outcome: outcome }));
    assert.equal(out.valid, true, `outcome=${outcome}: ${out.errors.join("|")}`);
  }
});

test("suspension: minimal valid body -> valid", () => {
  const out = verifyAtrBody(suspension());
  assert.equal(out.valid, true, out.errors.join("|"));
  assert.equal(out.body?.event_type, "suspension");
});

test("suspension: all trigger values accepted", () => {
  const triggers = [
    "cjeu_judgment",
    "dpa_order",
    "adequacy_repeal",
    "controller_decision",
    "dpf_delisting",
    "arrangement_expiry",
  ];
  for (const trigger of triggers) {
    const out = verifyAtrBody(suspension({ trigger }));
    assert.equal(out.valid, true, `trigger=${trigger}: ${out.errors.join("|")}`);
  }
});

// ── Shared rejections ─────────────────────────────────────────────────────────

test("non-object body -> body.not_object", () => {
  assert.equal(verifyAtrBody(null).errors[0], "body.not_object");
  assert.equal(verifyAtrBody(42).errors[0], "body.not_object");
  assert.equal(verifyAtrBody("body").errors[0], "body.not_object");
});

test("missing event_type -> event_type.unknown", () => {
  const out = verifyAtrBody({ ...arrangement(), event_type: undefined });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("event_type.unknown"), out.errors.join("|"));
});

test("unknown event_type -> event_type.unknown", () => {
  const out = verifyAtrBody({ ...arrangement(), event_type: "unknown_event" });
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("event_type.unknown"), out.errors.join("|"));
});

// ── arrangement field rejections ──────────────────────────────────────────────

test("arrangement: missing arrangement_id_commit -> arrangement_id_commit.missing", () => {
  const out = verifyAtrBody(arrangement({ arrangement_id_commit: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("arrangement_id_commit.missing"), out.errors.join("|"));
});

test("arrangement: missing recipient_commit -> recipient_commit.missing", () => {
  const out = verifyAtrBody(arrangement({ recipient_commit: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("recipient_commit.missing"), out.errors.join("|"));
});

test("arrangement: missing destination_country -> destination_country.missing", () => {
  const out = verifyAtrBody(arrangement({ destination_country: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("destination_country.missing"), out.errors.join("|"));
});

test("arrangement: missing mechanism_version -> mechanism_version.missing", () => {
  const out = verifyAtrBody(arrangement({ mechanism_version: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("mechanism_version.missing"), out.errors.join("|"));
});

test("arrangement: missing contract_doc_hash -> contract_doc_hash.missing", () => {
  const out = verifyAtrBody(arrangement({ contract_doc_hash: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("contract_doc_hash.missing"), out.errors.join("|"));
});

test("arrangement: missing in_force_from -> in_force_from.missing", () => {
  const out = verifyAtrBody(arrangement({ in_force_from: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("in_force_from.missing"), out.errors.join("|"));
});

test("arrangement: missing supplementary_measures_hash -> supplementary_measures_hash.missing", () => {
  const out = verifyAtrBody(arrangement({ supplementary_measures_hash: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("supplementary_measures_hash.missing"), out.errors.join("|"));
});

test("arrangement: in_force_until as number -> in_force_until.invalid", () => {
  const out = verifyAtrBody(arrangement({ in_force_until: 42 }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("in_force_until.invalid"), out.errors.join("|"));
});

// ── transfer field rejections ─────────────────────────────────────────────────

test("transfer: missing arrangement_hash -> arrangement_hash.missing", () => {
  const out = verifyAtrBody(transfer({ arrangement_hash: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("arrangement_hash.missing"), out.errors.join("|"));
});

test("transfer: missing destination_country -> destination_country.missing", () => {
  const out = verifyAtrBody(transfer({ destination_country: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("destination_country.missing"), out.errors.join("|"));
});

test("transfer: missing recipient_commit -> recipient_commit.missing", () => {
  const out = verifyAtrBody(transfer({ recipient_commit: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("recipient_commit.missing"), out.errors.join("|"));
});

test("transfer: empty data_categories array -> data_categories.missing", () => {
  const out = verifyAtrBody(transfer({ data_categories: [] }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("data_categories.missing"), out.errors.join("|"));
});

test("transfer: null data_categories -> data_categories.missing", () => {
  const out = verifyAtrBody(transfer({ data_categories: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("data_categories.missing"), out.errors.join("|"));
});

test("transfer: invalid subject_count_bucket -> subject_count_bucket.invalid", () => {
  const out = verifyAtrBody(transfer({ subject_count_bucket: "many" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("subject_count_bucket.invalid"), out.errors.join("|"));
});

test("transfer: missing transfer_window_start -> transfer_window_start.missing", () => {
  const out = verifyAtrBody(transfer({ transfer_window_start: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("transfer_window_start.missing"), out.errors.join("|"));
});

test("transfer: missing transfer_window_end -> transfer_window_end.missing", () => {
  const out = verifyAtrBody(transfer({ transfer_window_end: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("transfer_window_end.missing"), out.errors.join("|"));
});

test("transfer: null cross-ref fields are accepted", () => {
  const out = verifyAtrBody(transfer({
    tia_hash: null,
    artifact_apr_hash: null,
    consent_receipt_hash: null,
    purpose_binding_hash: null,
    qts_attestation_hash: null,
  }));
  assert.equal(out.valid, true, out.errors.join("|"));
});

// ── tia field rejections ──────────────────────────────────────────────────────

test("tia: missing arrangement_hash -> arrangement_hash.missing", () => {
  const out = verifyAtrBody(tia({ arrangement_hash: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("arrangement_hash.missing"), out.errors.join("|"));
});

test("tia: missing destination_country -> destination_country.missing", () => {
  const out = verifyAtrBody(tia({ destination_country: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("destination_country.missing"), out.errors.join("|"));
});

test("tia: missing assessment_doc_hash -> assessment_doc_hash.missing", () => {
  const out = verifyAtrBody(tia({ assessment_doc_hash: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("assessment_doc_hash.missing"), out.errors.join("|"));
});

test("tia: missing supplementary_measures_hash -> supplementary_measures_hash.missing", () => {
  const out = verifyAtrBody(tia({ supplementary_measures_hash: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("supplementary_measures_hash.missing"), out.errors.join("|"));
});

test("tia: empty surveillance_law_refs -> surveillance_law_refs.missing", () => {
  const out = verifyAtrBody(tia({ surveillance_law_refs: [] }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("surveillance_law_refs.missing"), out.errors.join("|"));
});

test("tia: null surveillance_law_refs -> surveillance_law_refs.missing", () => {
  const out = verifyAtrBody(tia({ surveillance_law_refs: null }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("surveillance_law_refs.missing"), out.errors.join("|"));
});

test("tia: invalid assessment_outcome -> assessment_outcome.invalid", () => {
  const out = verifyAtrBody(tia({ assessment_outcome: "allowed" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("assessment_outcome.invalid"), out.errors.join("|"));
});

test("tia: missing valid_from -> valid_from.missing", () => {
  const out = verifyAtrBody(tia({ valid_from: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("valid_from.missing"), out.errors.join("|"));
});

test("tia: missing valid_until -> valid_until.missing", () => {
  const out = verifyAtrBody(tia({ valid_until: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("valid_until.missing"), out.errors.join("|"));
});

// ── suspension field rejections ───────────────────────────────────────────────

test("suspension: invalid trigger -> trigger.invalid", () => {
  const out = verifyAtrBody(suspension({ trigger: "unknown_trigger" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("trigger.invalid"), out.errors.join("|"));
});

test("suspension: missing trigger_ref_hash -> trigger_ref_hash.missing", () => {
  const out = verifyAtrBody(suspension({ trigger_ref_hash: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("trigger_ref_hash.missing"), out.errors.join("|"));
});

test("suspension: missing effective_at -> effective_at.missing", () => {
  const out = verifyAtrBody(suspension({ effective_at: "" }));
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("effective_at.missing"), out.errors.join("|"));
});
