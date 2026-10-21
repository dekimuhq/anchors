/**
 * Tests for the eight per-event-type convenience wrappers in mint-single.ts.
 * Each wrapper produces a receipt with the correct `event_type` discriminator
 * and `claim_type: "ar.breach.v1"`. Where the verifier accepts the receipt
 * without TSA (RECOMMENDED events), we round-trip through verifyReceipt;
 * `breach.detected` mandates TSA per §D so we assert structural fields only.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  mintDetected,
  mintAssessed,
  mintDpaNotified,
  mintDpaDelayed,
  mintSubjectNotified,
  mintSubjectNotificationExempted,
  mintContained,
  mintClosed,
} from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import { baseCommon, H, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

test("S1: mintDetected produces a structurally-valid receipt (TSA required → verify reports tsa_required)", async () => {
  const env = await mintDetected({
    ...baseCommon,
    signingKey: makeSigningKey(),
    detected_at: "2026-05-19T12:00:00Z",
    severity_class: "risk",
    affected_data_categories: ["email", "name"],
    affected_data_hash: H("a"),
    affected_count: 1234,
    jurisdiction: "EU",
  });
  assert.equal(env.claim_type, "ar.breach.v1");
  assert.equal((env.body as { event_type: string }).event_type, "breach.detected");
  assert.equal(env.subject, null);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false, "expected tsa_required gate");
  assert.equal(r.reason, "tsa_required");
});

test("S2: mintAssessed round-trips through the verifier", async () => {
  const env = await mintAssessed({
    ...baseCommon,
    signingKey: makeSigningKey(),
    severity_class: "high_risk",
    assessment_method_hash: H("b"),
  });
  assert.equal((env.body as { event_type: string }).event_type, "breach.assessed");
  assert.equal(env.subject, null);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S3: mintDpaNotified round-trips (Art. 33 profile, no notification_phase)", async () => {
  const env = await mintDpaNotified({
    ...baseCommon,
    signingKey: makeSigningKey(),
    notification_uri: "https://aepd.example/filings/abc",
    notification_hash: H("c"),
  });
  assert.equal((env.body as { event_type: string }).event_type, "breach.dpa_notified");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S4: mintDpaNotified under NIS2 profile carries notification_phase", async () => {
  const env = await mintDpaNotified({
    ...baseCommon,
    profile: "breach.nis2.art23",
    signingKey: makeSigningKey(),
    notification_uri: "https://csirt.example/filings/x",
    notification_hash: H("d"),
    notification_phase: "early_warning",
  });
  const body = env.body as { notification_phase: string };
  assert.equal(body.notification_phase, "early_warning");
});

test("S5: mintDpaDelayed round-trips", async () => {
  const env = await mintDpaDelayed({
    ...baseCommon,
    signingKey: makeSigningKey(),
    delay_reason_hash: H("e"),
    delay_until_at: "2026-05-22T12:00:00Z",
  });
  assert.equal((env.body as { event_type: string }).event_type, "breach.dpa_delayed");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S6: mintSubjectNotified pins subject = subject_batch_root (D10-ABR-4)", async () => {
  const env = await mintSubjectNotified({
    ...baseCommon,
    profile: "breach.gdpr.art34",
    signingKey: makeSigningKey(),
    subject_batch_root: H("f"),
    subject_batch_size: 42,
    notification_uri: "https://example.test/breach-notice/v1",
    notification_hash: H("2"),
  });
  assert.equal((env.body as { event_type: string }).event_type, "breach.subject_notified");
  assert.equal(env.subject, H("f"));
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S7: mintSubjectNotificationExempted round-trips on art34_3_b_mitigated (no public_communication_uri)", async () => {
  const env = await mintSubjectNotificationExempted({
    ...baseCommon,
    profile: "breach.gdpr.art34",
    signingKey: makeSigningKey(),
    exemption_ground: "art34_3_b_mitigated",
    justification_hash: H("3"),
  });
  assert.equal(
    (env.body as { event_type: string }).event_type,
    "breach.subject_notification_exempted",
  );
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S8: mintContained round-trips and carries composition fields", async () => {
  const env = await mintContained({
    ...baseCommon,
    signingKey: makeSigningKey(),
    containment_at: "2026-05-19T18:00:00Z",
    containment_summary_hash: H("4"),
    containment_attestation: "AAR-01HABC",
    containment_remediation_arr_ids: ["ARR-01HABC", "ARR-01HDEF"],
  });
  const body = env.body as {
    event_type: string;
    containment_attestation: string;
    containment_remediation_arr_ids: readonly string[];
  };
  assert.equal(body.event_type, "breach.contained");
  assert.equal(body.containment_attestation, "AAR-01HABC");
  assert.deepEqual(body.containment_remediation_arr_ids, ["ARR-01HABC", "ARR-01HDEF"]);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S9: mintClosed round-trips with post_breach_anr_id composition", async () => {
  const env = await mintClosed({
    ...baseCommon,
    signingKey: makeSigningKey(),
    closed_at: "2026-05-20T09:00:00Z",
    closure_dpa_reference_id: "AEPD-0001/2026",
    post_breach_anr_id: "ANR-01HABC",
  });
  const body = env.body as { event_type: string; post_breach_anr_id: string };
  assert.equal(body.event_type, "breach.closed");
  assert.equal(body.post_breach_anr_id, "ANR-01HABC");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S10: every wrapper pins subject = null except breach.subject_notified", async () => {
  const sk = makeSigningKey();
  const envs = await Promise.all([
    mintAssessed({
      ...baseCommon,
      signingKey: sk,
      severity_class: "risk",
      assessment_method_hash: H("a"),
    }),
    mintDpaNotified({
      ...baseCommon,
      signingKey: sk,
      notification_uri: "https://x.example",
      notification_hash: H("b"),
    }),
    mintDpaDelayed({
      ...baseCommon,
      signingKey: sk,
      delay_reason_hash: H("c"),
      delay_until_at: "2026-05-22T12:00:00Z",
    }),
    mintSubjectNotificationExempted({
      ...baseCommon,
      profile: "breach.gdpr.art34",
      signingKey: sk,
      exemption_ground: "art34_3_a_encrypted",
      justification_hash: H("d"),
    }),
    mintContained({
      ...baseCommon,
      signingKey: sk,
      containment_at: "2026-05-19T18:00:00Z",
      containment_summary_hash: H("e"),
    }),
    mintClosed({
      ...baseCommon,
      signingKey: sk,
      closed_at: "2026-05-20T09:00:00Z",
    }),
  ]);
  for (const env of envs) {
    assert.equal(env.subject, null, `expected subject null on ${(env.body as { event_type: string }).event_type}`);
  }
});
