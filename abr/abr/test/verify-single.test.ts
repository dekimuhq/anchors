/**
 * Tests for the per-event-type ABR body verifier (spec §3.1 + §4).
 *
 * Coverage: one happy path per event_type plus the rejection cases named
 * explicitly in §4.1–§4.8 and D10-ABR-3/-4. Cross-event pinning is tested by
 * flipping one field to a non-null value and asserting the corresponding
 * `<field>.must_be_null` error fires.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyAbrBody } from "../src/verify-single.ts";

// ── Shared body templates ─────────────────────────────────────────────────────

const INCIDENT_ID = "incident-2026-05-19-001";
const BASE_FIELDS = {
  profile: "breach.gdpr.art33",
  incident_correlation_id: INCIDENT_ID,
};

/** Every cross-event-pinned field set to null. */
const ALL_PINS_NULL = {
  detected_at: null,
  severity_class: null,
  affected_data_categories: null,
  affected_data_hash: null,
  affected_count: null,
  jurisdiction: null,
  assessment_method_hash: null,
  notification_uri: null,
  notification_hash: null,
  dpa_reference_id: null,
  notification_phase: null,
  delay_reason_hash: null,
  delay_until_at: null,
  subject_batch_root: null,
  subject_batch_size: null,
  exemption_ground: null,
  justification_hash: null,
  public_communication_uri: null,
  containment_at: null,
  containment_summary_hash: null,
  containment_attestation: null,
  closed_at: null,
  closure_dpa_reference_id: null,
  affected_aer_ids: null,
  containment_remediation_arr_ids: null,
  transfer_suspension_atr_ids: null,
  post_breach_anr_id: null,
  qes_aar_id: null,
};

function detected(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    event_type: "breach.detected",
    detected_at: "2026-05-19T08:00:00Z",
    severity_class: "high_risk",
    affected_data_categories: ["email", "ip_address"],
    affected_data_hash: "sha256:abc123",
    affected_count: 1024,
    jurisdiction: "EU",
    ...over,
  };
}

function assessed(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    event_type: "breach.assessed",
    severity_class: "risk",
    assessment_method_hash: "sha256:methodology-v3",
    ...over,
  };
}

function dpaNotified(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    event_type: "breach.dpa_notified",
    notification_uri: "https://dpa.example/case/2026-001",
    notification_hash: "sha256:notif",
    dpa_reference_id: "AEPD-2026-001",
    ...over,
  };
}

function dpaDelayed(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    event_type: "breach.dpa_delayed",
    delay_reason_hash: "sha256:delay-justification",
    delay_until_at: "2026-05-22T08:00:00Z",
    ...over,
  };
}

function subjectNotified(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    profile: "breach.gdpr.art34",
    event_type: "breach.subject_notified",
    subject_batch_root: "sha256:batchroot",
    subject_batch_size: 1024,
    notification_uri: "https://controller.example/notify",
    notification_hash: "sha256:notify",
    ...over,
  };
}

function exempted(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    profile: "breach.gdpr.art34",
    event_type: "breach.subject_notification_exempted",
    exemption_ground: "art34_3_a_encrypted",
    justification_hash: "sha256:justify",
    public_communication_uri: null,
    ...over,
  };
}

function contained(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    event_type: "breach.contained",
    containment_at: "2026-05-19T20:00:00Z",
    containment_summary_hash: "sha256:contained",
    ...over,
  };
}

function closed(over: Record<string, unknown> = {}) {
  return {
    ...BASE_FIELDS,
    ...ALL_PINS_NULL,
    event_type: "breach.closed",
    closed_at: "2026-05-25T12:00:00Z",
    closure_dpa_reference_id: "AEPD-2026-001",
    ...over,
  };
}

// ── Top-level dispatch ────────────────────────────────────────────────────────

test("rejects non-object body", () => {
  for (const v of [null, undefined, 42, "string"]) {
    const r = verifyAbrBody(v);
    assert.equal(r.valid, false);
    assert.deepEqual(r.errors, ["body.not_object"]);
  }
});

test("rejects unknown event_type", () => {
  const r = verifyAbrBody({ ...BASE_FIELDS, event_type: "breach.nope" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("event_type.unknown"));
});

test("rejects unregistered profile", () => {
  const r = verifyAbrBody(detected({ profile: "breach.something_else" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("profile.unregistered"));
});

test("rejects missing incident_correlation_id", () => {
  const r = verifyAbrBody(detected({ incident_correlation_id: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("incident_correlation_id.required"));
});

test("rejects non-string incident_correlation_id", () => {
  const r = verifyAbrBody(detected({ incident_correlation_id: 42 }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("incident_correlation_id.required"));
});

// ── §4.1 breach.detected ──────────────────────────────────────────────────────

test("detected: happy path validates", () => {
  const r = verifyAbrBody(detected());
  assert.equal(r.valid, true, r.errors.join(","));
  assert.equal(r.errors.length, 0);
  assert.equal(r.body?.event_type, "breach.detected");
});

test("detected: rejects bad detected_at", () => {
  const r = verifyAbrBody(detected({ detected_at: "not-a-date" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("detected_at.invalid"));
});

test("detected: rejects invalid severity_class", () => {
  const r = verifyAbrBody(detected({ severity_class: "extreme" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("severity_class.invalid"));
});

test("detected: rejects empty affected_data_categories", () => {
  const r = verifyAbrBody(detected({ affected_data_categories: [] }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("affected_data_categories.invalid"));
});

test("detected: accepts -1 affected_count (undetermined)", () => {
  const r = verifyAbrBody(detected({ affected_count: -1 }));
  assert.equal(r.valid, true, r.errors.join(","));
});

test("detected: rejects affected_count < -1", () => {
  const r = verifyAbrBody(detected({ affected_count: -2 }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("affected_count.invalid"));
});

test("detected: rejects fractional affected_count", () => {
  const r = verifyAbrBody(detected({ affected_count: 12.5 }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("affected_count.invalid"));
});

test("detected: accepts non-null affected_aer_ids composition", () => {
  const r = verifyAbrBody(detected({ affected_aer_ids: ["01HXAEREVAL"] }));
  assert.equal(r.valid, true, r.errors.join(","));
});

test("detected: rejects empty-array affected_aer_ids", () => {
  const r = verifyAbrBody(detected({ affected_aer_ids: [] }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("affected_aer_ids.invalid"));
});

test("detected: rejects non-null assessment_method_hash (cross-event pin)", () => {
  const r = verifyAbrBody(detected({ assessment_method_hash: "sha256:nope" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("assessment_method_hash.must_be_null"));
});

test("detected: rejects non-null subject_batch_root (cross-event pin)", () => {
  const r = verifyAbrBody(detected({ subject_batch_root: "sha256:root" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("subject_batch_root.must_be_null"));
});

// ── §4.2 breach.assessed ──────────────────────────────────────────────────────

test("assessed: happy path validates", () => {
  const r = verifyAbrBody(assessed());
  assert.equal(r.valid, true, r.errors.join(","));
});

test("assessed: rejects missing assessment_method_hash", () => {
  const r = verifyAbrBody(assessed({ assessment_method_hash: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("assessment_method_hash.required"));
});

test("assessed: rejects non-null detected_at (cross-event pin)", () => {
  const r = verifyAbrBody(assessed({ detected_at: "2026-05-19T08:00:00Z" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("detected_at.must_be_null"));
});

// ── §4.3 breach.dpa_notified ──────────────────────────────────────────────────

test("dpa_notified: happy path (Art. 33, no phase)", () => {
  const r = verifyAbrBody(dpaNotified());
  assert.equal(r.valid, true, r.errors.join(","));
});

test("dpa_notified: NIS2 happy path with phase", () => {
  const r = verifyAbrBody(
    dpaNotified({
      profile: "breach.nis2.art23",
      notification_phase: "early_warning",
    }),
  );
  assert.equal(r.valid, true, r.errors.join(","));
});

test("dpa_notified: rejects phase on non-NIS2 profile", () => {
  const r = verifyAbrBody(dpaNotified({ notification_phase: "full_notification" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("notification_phase.only_on_nis2"));
});

test("dpa_notified: rejects invalid phase value", () => {
  const r = verifyAbrBody(
    dpaNotified({
      profile: "breach.nis2.art23",
      notification_phase: "later",
    }),
  );
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("notification_phase.invalid"));
});

test("dpa_notified: accepts null dpa_reference_id (case id not yet assigned)", () => {
  const r = verifyAbrBody(dpaNotified({ dpa_reference_id: null }));
  assert.equal(r.valid, true, r.errors.join(","));
});

test("dpa_notified: rejects missing notification_uri", () => {
  const r = verifyAbrBody(dpaNotified({ notification_uri: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("notification_uri.required"));
});

test("dpa_notified: accepts QES AAR composition pointer", () => {
  const r = verifyAbrBody(dpaNotified({ qes_aar_id: "01HXAAR-QES" }));
  assert.equal(r.valid, true, r.errors.join(","));
});

test("dpa_notified: rejects non-null severity_class (cross-event pin)", () => {
  const r = verifyAbrBody(dpaNotified({ severity_class: "risk" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("severity_class.must_be_null"));
});

// ── §4.4 breach.dpa_delayed ───────────────────────────────────────────────────

test("dpa_delayed: happy path validates", () => {
  const r = verifyAbrBody(dpaDelayed());
  assert.equal(r.valid, true, r.errors.join(","));
});

test("dpa_delayed: rejects bad delay_until_at", () => {
  const r = verifyAbrBody(dpaDelayed({ delay_until_at: "soon" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("delay_until_at.invalid"));
});

test("dpa_delayed: rejects missing delay_reason_hash", () => {
  const r = verifyAbrBody(dpaDelayed({ delay_reason_hash: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("delay_reason_hash.required"));
});

// ── §4.5 breach.subject_notified ──────────────────────────────────────────────

test("subject_notified: happy path validates", () => {
  const r = verifyAbrBody(subjectNotified());
  assert.equal(r.valid, true, r.errors.join(","));
});

test("subject_notified: rejects batch_size 0", () => {
  const r = verifyAbrBody(subjectNotified({ subject_batch_size: 0 }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("subject_batch_size.invalid"));
});

test("subject_notified: accepts max batch_size 65 536 (D10-ABR-4 ceiling)", () => {
  const r = verifyAbrBody(subjectNotified({ subject_batch_size: 65_536 }));
  assert.equal(r.valid, true, r.errors.join(","));
});

test("subject_notified: rejects batch_size > 65 536", () => {
  const r = verifyAbrBody(subjectNotified({ subject_batch_size: 65_537 }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("subject_batch_size.invalid"));
});

test("subject_notified: rejects missing subject_batch_root", () => {
  const r = verifyAbrBody(subjectNotified({ subject_batch_root: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("subject_batch_root.required"));
});

test("subject_notified: rejects fractional batch_size", () => {
  const r = verifyAbrBody(subjectNotified({ subject_batch_size: 12.5 }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("subject_batch_size.invalid"));
});

// ── §4.6 breach.subject_notification_exempted ─────────────────────────────────

test("exempted: art34_3_a happy path (no public_comm needed)", () => {
  const r = verifyAbrBody(exempted());
  assert.equal(r.valid, true, r.errors.join(","));
});

test("exempted: art34_3_b happy path", () => {
  const r = verifyAbrBody(exempted({ exemption_ground: "art34_3_b_mitigated" }));
  assert.equal(r.valid, true, r.errors.join(","));
});

test("exempted: art34_3_c rejects missing public_communication_uri", () => {
  const r = verifyAbrBody(
    exempted({ exemption_ground: "art34_3_c_disproportionate" }),
  );
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("art34_3_c_public_comm_missing"));
});

test("exempted: art34_3_c accepts non-null public_communication_uri", () => {
  const r = verifyAbrBody(
    exempted({
      exemption_ground: "art34_3_c_disproportionate",
      public_communication_uri: "https://controller.example/public-notice",
    }),
  );
  assert.equal(r.valid, true, r.errors.join(","));
});

test("exempted: rejects non-null public_communication_uri on art34_3_a", () => {
  const r = verifyAbrBody(
    exempted({
      exemption_ground: "art34_3_a_encrypted",
      public_communication_uri: "https://controller.example/should-not-be-here",
    }),
  );
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("public_communication_uri.must_be_null"));
});

test("exempted: rejects unknown exemption_ground", () => {
  const r = verifyAbrBody(exempted({ exemption_ground: "art_made_up" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("exemption_ground.invalid"));
});

test("exempted: rejects missing justification_hash", () => {
  const r = verifyAbrBody(exempted({ justification_hash: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("justification_hash.required"));
});

// ── §4.7 breach.contained ─────────────────────────────────────────────────────

test("contained: happy path validates", () => {
  const r = verifyAbrBody(contained());
  assert.equal(r.valid, true, r.errors.join(","));
});

test("contained: rejects bad containment_at", () => {
  const r = verifyAbrBody(contained({ containment_at: "yesterday" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("containment_at.invalid"));
});

test("contained: rejects missing containment_summary_hash", () => {
  const r = verifyAbrBody(contained({ containment_summary_hash: "" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("containment_summary_hash.required"));
});

test("contained: accepts the three composition fields populated", () => {
  const r = verifyAbrBody(
    contained({
      containment_attestation: "01HXAAR-1",
      containment_remediation_arr_ids: ["01HXARR-ERASE-1"],
      transfer_suspension_atr_ids: ["01HXATR-SUSPEND-1", "01HXATR-SUSPEND-2"],
    }),
  );
  assert.equal(r.valid, true, r.errors.join(","));
});

test("contained: rejects empty containment_remediation_arr_ids", () => {
  const r = verifyAbrBody(contained({ containment_remediation_arr_ids: [] }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("containment_remediation_arr_ids.invalid"));
});

test("contained: rejects non-string entries in transfer_suspension_atr_ids", () => {
  const r = verifyAbrBody(
    contained({ transfer_suspension_atr_ids: ["ok", 42 as unknown as string] }),
  );
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("transfer_suspension_atr_ids.invalid"));
});

// ── §4.8 breach.closed ────────────────────────────────────────────────────────

test("closed: happy path validates", () => {
  const r = verifyAbrBody(closed());
  assert.equal(r.valid, true, r.errors.join(","));
});

test("closed: accepts null closure_dpa_reference_id (low-risk path)", () => {
  const r = verifyAbrBody(closed({ closure_dpa_reference_id: null }));
  assert.equal(r.valid, true, r.errors.join(","));
});

test("closed: rejects bad closed_at", () => {
  const r = verifyAbrBody(closed({ closed_at: "soon" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("closed_at.invalid"));
});

test("closed: accepts post_breach_anr_id composition pointer", () => {
  const r = verifyAbrBody(closed({ post_breach_anr_id: "01HXANR-POST" }));
  assert.equal(r.valid, true, r.errors.join(","));
});

test("closed: rejects empty-string post_breach_anr_id", () => {
  const r = verifyAbrBody(closed({ post_breach_anr_id: "" }));
  assert.equal(r.valid, false);
  // Empty string is not isNonEmptyString → invalid.
  assert.ok(r.errors.includes("post_breach_anr_id.invalid"));
});

test("closed: rejects non-null containment_at (cross-event pin)", () => {
  const r = verifyAbrBody(closed({ containment_at: "2026-05-25T11:00:00Z" }));
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("containment_at.must_be_null"));
});
