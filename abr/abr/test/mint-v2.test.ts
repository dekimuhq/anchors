/**
 * Validation tests for mint-v2.ts — exercises every documented throw plus
 * key happy-path invariants (claim_type, subject pinning, field_root,
 * envelope_kind default, prev passthrough).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintAbrV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import { baseCommon, H, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

// ── Generic validations ──────────────────────────────────────────────────────

test("V1: throws when issuer missing", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        issuer: "",
        signingKey: makeSigningKey(),
        event_type: "breach.assessed",
        severity_class: "risk",
        assessment_method_hash: H("a"),
      }),
    /issuer required/,
  );
});

test("V2: throws when signingKey.kid missing", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: { kid: "", privateKey: new Uint8Array(32) },
        event_type: "breach.assessed",
        severity_class: "risk",
        assessment_method_hash: H("a"),
      }),
    /signingKey\.kid required/,
  );
});

test("V3: throws when private key seed is wrong length", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: { kid: "k", privateKey: new Uint8Array(16) },
        event_type: "breach.assessed",
        severity_class: "risk",
        assessment_method_hash: H("a"),
      }),
    /32-byte Ed25519 seed/,
  );
});

test("V4: throws when incident_correlation_id empty (D10-ABR-3)", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        incident_correlation_id: "",
        signingKey: makeSigningKey(),
        event_type: "breach.assessed",
        severity_class: "risk",
        assessment_method_hash: H("a"),
      }),
    /incident_correlation_id required/,
  );
});

test("V5: throws when tsa config is set without tsaFetcher", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.assessed",
        severity_class: "risk",
        assessment_method_hash: H("a"),
        tsa: { provider: "freetsa", hash_alg: "sha256" } as never,
      }),
    /tsaFetcher required/,
  );
});

// ── breach.detected validations ──────────────────────────────────────────────

test("V6: breach.detected requires detected_at", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.detected",
        detected_at: "",
        severity_class: "risk",
        affected_data_categories: ["email"],
        affected_data_hash: H("a"),
        affected_count: 1,
        jurisdiction: "EU",
      }),
    /detected_at/,
  );
});

test("V7: breach.detected rejects empty affected_data_categories", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.detected",
        detected_at: "2026-05-19T12:00:00Z",
        severity_class: "risk",
        affected_data_categories: [],
        affected_data_hash: H("a"),
        affected_count: 1,
        jurisdiction: "EU",
      }),
    /non-empty affected_data_categories/,
  );
});

test("V8: breach.detected rejects malformed affected_data_hash", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.detected",
        detected_at: "2026-05-19T12:00:00Z",
        severity_class: "risk",
        affected_data_categories: ["email"],
        affected_data_hash: "not-a-hash",
        affected_count: 1,
        jurisdiction: "EU",
      }),
    /affected_data_hash/,
  );
});

test("V9: breach.detected requires integer affected_count", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.detected",
        detected_at: "2026-05-19T12:00:00Z",
        severity_class: "risk",
        affected_data_categories: ["email"],
        affected_data_hash: H("a"),
        affected_count: 1.5,
        jurisdiction: "EU",
      }),
    /integer affected_count/,
  );
});

test("V10: breach.detected requires jurisdiction", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.detected",
        detected_at: "2026-05-19T12:00:00Z",
        severity_class: "risk",
        affected_data_categories: ["email"],
        affected_data_hash: H("a"),
        affected_count: 1,
        jurisdiction: "",
      }),
    /jurisdiction/,
  );
});

// ── breach.assessed validations ──────────────────────────────────────────────

test("V11: breach.assessed rejects malformed assessment_method_hash", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.assessed",
        severity_class: "risk",
        assessment_method_hash: "nope",
      }),
    /assessment_method_hash/,
  );
});

// ── breach.dpa_notified validations ──────────────────────────────────────────

test("V12: breach.dpa_notified requires notification_uri", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.dpa_notified",
        notification_uri: "",
        notification_hash: H("a"),
      }),
    /notification_uri/,
  );
});

test("V13: breach.dpa_notified rejects malformed notification_hash", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.dpa_notified",
        notification_uri: "https://x.example",
        notification_hash: "bad",
      }),
    /notification_hash/,
  );
});

test("V14: breach.dpa_notified under nis2.art23 requires notification_phase", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        profile: "breach.nis2.art23",
        signingKey: makeSigningKey(),
        event_type: "breach.dpa_notified",
        notification_uri: "https://x.example",
        notification_hash: H("a"),
      }),
    /requires notification_phase/,
  );
});

test("V15: notification_phase rejected on non-nis2 profile", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.dpa_notified",
        notification_uri: "https://x.example",
        notification_hash: H("a"),
        notification_phase: "full_notification",
      }),
    /only permitted on breach\.nis2\.art23/,
  );
});

// ── breach.dpa_delayed validations ───────────────────────────────────────────

test("V16: breach.dpa_delayed rejects malformed delay_reason_hash", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.dpa_delayed",
        delay_reason_hash: "bad",
        delay_until_at: "2026-05-22T12:00:00Z",
      }),
    /delay_reason_hash/,
  );
});

test("V17: breach.dpa_delayed requires delay_until_at", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.dpa_delayed",
        delay_reason_hash: H("a"),
        delay_until_at: "",
      }),
    /delay_until_at/,
  );
});

// ── breach.subject_notified validations ──────────────────────────────────────

test("V18: breach.subject_notified rejects malformed subject_batch_root", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.subject_notified",
        subject_batch_root: "raw-not-hashed",
        subject_batch_size: 10,
        notification_uri: "https://x.example",
        notification_hash: H("a"),
      }),
    /subject_batch_root/,
  );
});

test("V19: breach.subject_notified rejects non-positive subject_batch_size", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.subject_notified",
        subject_batch_root: H("a"),
        subject_batch_size: 0,
        notification_uri: "https://x.example",
        notification_hash: H("b"),
      }),
    /positive integer subject_batch_size/,
  );
});

test("V20: breach.subject_notified rejects subject_batch_size > 65536", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.subject_notified",
        subject_batch_root: H("a"),
        subject_batch_size: 65537,
        notification_uri: "https://x.example",
        notification_hash: H("b"),
      }),
    /D10-ABR-4/,
  );
});

test("V21: breach.subject_notified requires notification_uri", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.subject_notified",
        subject_batch_root: H("a"),
        subject_batch_size: 10,
        notification_uri: "",
        notification_hash: H("b"),
      }),
    /notification_uri/,
  );
});

test("V22: breach.subject_notified rejects malformed notification_hash", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.subject_notified",
        subject_batch_root: H("a"),
        subject_batch_size: 10,
        notification_uri: "https://x.example",
        notification_hash: "bad",
      }),
    /notification_hash/,
  );
});

// ── breach.subject_notification_exempted validations ─────────────────────────

test("V23: rejects malformed justification_hash", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.subject_notification_exempted",
        exemption_ground: "art34_3_a_encrypted",
        justification_hash: "bad",
      }),
    /justification_hash/,
  );
});

test("V24: art34_3_c_disproportionate requires public_communication_uri", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.subject_notification_exempted",
        exemption_ground: "art34_3_c_disproportionate",
        justification_hash: H("a"),
      }),
    /public_communication_uri/,
  );
});

test("V25: public_communication_uri rejected on non-art34_3_c exemption", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.subject_notification_exempted",
        exemption_ground: "art34_3_a_encrypted",
        justification_hash: H("a"),
        public_communication_uri: "https://example.test/comm",
      }),
    /only permitted on art34_3_c_disproportionate/,
  );
});

// ── breach.contained validations ─────────────────────────────────────────────

test("V26: breach.contained requires containment_at", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.contained",
        containment_at: "",
        containment_summary_hash: H("a"),
      }),
    /containment_at/,
  );
});

test("V27: breach.contained rejects malformed containment_summary_hash", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.contained",
        containment_at: "2026-05-19T18:00:00Z",
        containment_summary_hash: "bad",
      }),
    /containment_summary_hash/,
  );
});

// ── breach.closed validations ────────────────────────────────────────────────

test("V28: breach.closed requires closed_at", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "breach.closed",
        closed_at: "",
      }),
    /closed_at/,
  );
});

// ── Happy paths / invariants ─────────────────────────────────────────────────

test("P1: claim_type is ar.breach.v1", async () => {
  const env = await mintAbrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "breach.assessed",
    severity_class: "risk",
    assessment_method_hash: H("a"),
  });
  assert.equal(env.claim_type, "ar.breach.v1");
});

test("P2: subject pinned null on every non-subject_notified event", async () => {
  const sk = makeSigningKey();
  const env = await mintAbrV2({
    ...baseCommon,
    signingKey: sk,
    event_type: "breach.assessed",
    severity_class: "risk",
    assessment_method_hash: H("a"),
  });
  assert.equal(env.subject, null);
});

test("P3: subject_notified pins subject = subject_batch_root", async () => {
  const root = H("9");
  const env = await mintAbrV2({
    ...baseCommon,
    profile: "breach.gdpr.art34",
    signingKey: makeSigningKey(),
    event_type: "breach.subject_notified",
    subject_batch_root: root,
    subject_batch_size: 99,
    notification_uri: "https://x.example",
    notification_hash: H("a"),
  });
  assert.equal(env.subject, root);
});

test("P4: minted body carries field_root commitment", async () => {
  const env = await mintAbrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "breach.assessed",
    severity_class: "risk",
    assessment_method_hash: H("a"),
  });
  const body = env.body as { field_root: string };
  assert.match(body.field_root, /^sha256:[0-9a-f]{64}$/);
});

test("P5: envelope_kind defaults to 'decision' and can be opted out via null", async () => {
  const sk = makeSigningKey();
  const defaulted = await mintAbrV2({
    ...baseCommon,
    signingKey: sk,
    event_type: "breach.assessed",
    severity_class: "risk",
    assessment_method_hash: H("a"),
  });
  assert.equal(defaulted.kind, "decision");
  const optedOut = await mintAbrV2({
    ...baseCommon,
    signingKey: sk,
    event_type: "breach.assessed",
    envelope_kind: null,
    severity_class: "risk",
    assessment_method_hash: H("a"),
  });
  assert.equal(optedOut.kind, null);
});

test("P6: prev passthrough is preserved", async () => {
  const env = await mintAbrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "breach.assessed",
    severity_class: "risk",
    assessment_method_hash: H("a"),
    prev: "01HABCDEF0000000000000",
  });
  assert.equal(env.prev, "01HABCDEF0000000000000");
});

test("P7: incident_correlation_id is preserved in body across events", async () => {
  const sk = makeSigningKey();
  const env = await mintAbrV2({
    ...baseCommon,
    incident_correlation_id: "INC-2026-ABCD",
    signingKey: sk,
    event_type: "breach.closed",
    closed_at: "2026-05-20T09:00:00Z",
  });
  const body = env.body as { incident_correlation_id: string };
  assert.equal(body.incident_correlation_id, "INC-2026-ABCD");
});

test("P8: breach.assessed round-trips through verifier", async () => {
  const env = await mintAbrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "breach.assessed",
    severity_class: "high_risk",
    assessment_method_hash: H("a"),
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("P9: composition fields pinned null when omitted", async () => {
  const env = await mintAbrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "breach.contained",
    containment_at: "2026-05-19T18:00:00Z",
    containment_summary_hash: H("a"),
  });
  const body = env.body as {
    containment_attestation: string | null;
    containment_remediation_arr_ids: readonly string[] | null;
    transfer_suspension_atr_ids: readonly string[] | null;
  };
  assert.equal(body.containment_attestation, null);
  assert.equal(body.containment_remediation_arr_ids, null);
  assert.equal(body.transfer_suspension_atr_ids, null);
});

test("P10: composition fields preserved when supplied", async () => {
  const env = await mintAbrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "breach.detected",
    detected_at: "2026-05-19T12:00:00Z",
    severity_class: "risk",
    affected_data_categories: ["email"],
    affected_data_hash: H("a"),
    affected_count: 1,
    jurisdiction: "EU",
    affected_aer_ids: ["AER-001", "AER-002"],
  });
  const body = env.body as { affected_aer_ids: readonly string[] };
  assert.deepEqual(body.affected_aer_ids, ["AER-001", "AER-002"]);
});

test("V_QTS: non-null qts_attestation_hash round-trips through verifier", async () => {
  const QTS = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const env = await mintAbrV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "breach.assessed",
    severity_class: "risk",
    assessment_method_hash: H("a"),
    qts_attestation_hash: QTS,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.qts_attestation_hash, QTS);
  const result = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(result.signature_valid, true, result.reason ?? "ok");
});
