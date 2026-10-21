/**
 * Gap-fill tests for mint-v2.ts beyond the V1-V28 throws and P1-P10 invariants
 * already covered in mint-v2.test.ts.
 *
 * Drives abr-issuer-kit above the ≥99 per-package test floor (Phase 3 §I).
 * Groups:
 *   E*  — envelope passthrough invariants (v / id / iat / iat_ms / iss / iss_key
 *         / exp / cause / predicate / kind explicit / policy / anchor / sig)
 *   F*  — field_root commitment invariants (format / determinism / per-event
 *         differentiation / per-input differentiation / surface placement)
 *   B*  — body construction invariants per event_type (discriminator + at least
 *         one cross-event-pinned null + the event-specific field)
 *   S*  — credentialStatus attach round-trip + subject pinning interaction
 *   X*  — extra throws + positive validation paths not covered by V1-V28
 *   BV* — boundary inputs (subject_batch_size endpoints, affected_count -1/0)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintAbrV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import type { JsonLogicAst } from "@dekimuhq/anchors-envelope";
import { baseCommon, H, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

// ── Convenience makers ───────────────────────────────────────────────────────

const sk = () => makeSigningKey();

const mkAssessed = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "breach.assessed" as const,
    severity_class: "risk" as const,
    assessment_method_hash: H("a"),
    ...overrides,
  }) as Parameters<typeof mintAbrV2>[0];

const mkDetected = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "breach.detected" as const,
    detected_at: "2026-05-19T12:00:00Z",
    severity_class: "risk" as const,
    affected_data_categories: ["email"],
    affected_data_hash: H("a"),
    affected_count: 1,
    jurisdiction: "EU",
    ...overrides,
  }) as Parameters<typeof mintAbrV2>[0];

const mkSubjectNotified = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    profile: "breach.gdpr.art34" as const,
    signingKey: sk(),
    event_type: "breach.subject_notified" as const,
    subject_batch_root: H("9"),
    subject_batch_size: 5,
    notification_uri: "https://x.example",
    notification_hash: H("a"),
    ...overrides,
  }) as Parameters<typeof mintAbrV2>[0];

const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const ED25519_KEY_RE = /^ed25519:[A-Za-z0-9_-]+$/;

// ── E — envelope passthrough ─────────────────────────────────────────────────

test("E1: envelope.v is 2", async () => {
  const env = await mintAbrV2(mkAssessed());
  assert.equal(env.v, 2);
});

test("E2: id is a 26-character Crockford ULID", async () => {
  const env = await mintAbrV2(mkAssessed());
  assert.equal(env.id.length, 26);
  assert.match(env.id, ULID_RE);
});

test("E3: iat is ISO-8601 UTC and iat_ms matches Date.parse(iat)", async () => {
  const env = await mintAbrV2(mkAssessed());
  assert.match(env.iat, ISO_RE);
  assert.equal(env.iat_ms, Date.parse(env.iat));
});

test("E4: iss is the supplied issuer string", async () => {
  const env = await mintAbrV2(mkAssessed({ issuer: "did:web:abr.example" }));
  assert.equal(env.iss, "did:web:abr.example");
});

test("E5: iss_key has shape `ed25519:<base64url>`", async () => {
  const env = await mintAbrV2(mkAssessed());
  assert.match(env.iss_key, ED25519_KEY_RE);
});

test("E6: exp defaults to null when omitted", async () => {
  const env = await mintAbrV2(mkAssessed());
  assert.equal(env.exp, null);
});

test("E7: exp passthrough preserved when supplied", async () => {
  const env = await mintAbrV2(mkAssessed({ exp: "2027-01-01T00:00:00Z" }));
  assert.equal(env.exp, "2027-01-01T00:00:00Z");
});

test("E8: explicit prev: null behaves identically to omission", async () => {
  const env = await mintAbrV2(mkAssessed({ prev: null }));
  assert.equal(env.prev, null);
});

test("E9: policy_uri / policy_hash / policy_version pass through verbatim", async () => {
  const env = await mintAbrV2(
    mkAssessed({
      policy_uri: "https://controller.example/breach-playbook/v2",
      policy_hash: "sha256:" + "f".repeat(64),
      policy_version: "2.1.3",
    }),
  );
  assert.equal(env.policy_uri, "https://controller.example/breach-playbook/v2");
  assert.equal(env.policy_hash, "sha256:" + "f".repeat(64));
  assert.equal(env.policy_version, "2.1.3");
});

test("E10: anchor passthrough is deep-equal to input", async () => {
  const env = await mintAbrV2(mkAssessed());
  assert.deepEqual(env.anchor, baseCommon.anchor);
});

test("E11: cause defaults to null and supplied cause passes through", async () => {
  const def = await mintAbrV2(mkAssessed());
  assert.equal(def.cause, null);
  const set = await mintAbrV2(mkAssessed({ cause: "breach" }));
  assert.equal(set.cause, "breach");
});

test("E12: predicate defaults to null and supplied predicate passes through", async () => {
  const def = await mintAbrV2(mkAssessed());
  assert.equal(def.predicate, null);
  const predicate = { "===": [1, 1] } as unknown as JsonLogicAst;
  const set = await mintAbrV2(mkAssessed({ predicate }));
  assert.deepEqual(set.predicate, { "===": [1, 1] });
});

test("E13: envelope_kind 'observation' passes through explicitly", async () => {
  const env = await mintAbrV2(mkAssessed({ envelope_kind: "observation" }));
  assert.equal(env.kind, "observation");
});

test("E14: signed envelope sig is a non-empty string", async () => {
  const env = await mintAbrV2(mkAssessed());
  assert.equal(typeof env.sig, "string");
  assert.ok(env.sig.length > 0, "sig should be non-empty");
});

test("E15: claim_type is ar.breach.v1 across every event_type", async () => {
  const inputs: Parameters<typeof mintAbrV2>[0][] = [
    mkDetected(),
    mkAssessed(),
    mkAssessed({ event_type: "breach.dpa_notified", notification_uri: "https://x.example", notification_hash: H("a") }),
    mkAssessed({ event_type: "breach.dpa_delayed", delay_reason_hash: H("a"), delay_until_at: "2026-05-22T00:00:00Z" }),
    mkSubjectNotified(),
    mkAssessed({ event_type: "breach.subject_notification_exempted", exemption_ground: "art34_3_a_encrypted", justification_hash: H("a") }),
    mkAssessed({ event_type: "breach.contained", containment_at: "2026-05-19T18:00:00Z", containment_summary_hash: H("a") }),
    mkAssessed({ event_type: "breach.closed", closed_at: "2026-05-20T09:00:00Z" }),
  ];
  for (const inp of inputs) {
    const env = await mintAbrV2(inp);
    assert.equal(env.claim_type, "ar.breach.v1");
  }
});

test("E16: countersig is null at mint", async () => {
  const env = await mintAbrV2(mkAssessed());
  assert.equal(env.countersig, null);
});

test("E17: tsa block is null when no tsa config is supplied", async () => {
  const env = await mintAbrV2(mkAssessed());
  assert.equal(env.tsa, null);
});

// ── F — field_root commitment ────────────────────────────────────────────────

test("F1: every event_type emits a body.field_root commitment", async () => {
  const inputs: Parameters<typeof mintAbrV2>[0][] = [
    mkDetected(),
    mkAssessed(),
    mkAssessed({ event_type: "breach.dpa_notified", notification_uri: "https://x.example", notification_hash: H("a") }),
    mkAssessed({ event_type: "breach.dpa_delayed", delay_reason_hash: H("a"), delay_until_at: "2026-05-22T00:00:00Z" }),
    mkSubjectNotified(),
    mkAssessed({ event_type: "breach.subject_notification_exempted", exemption_ground: "art34_3_a_encrypted", justification_hash: H("a") }),
    mkAssessed({ event_type: "breach.contained", containment_at: "2026-05-19T18:00:00Z", containment_summary_hash: H("a") }),
    mkAssessed({ event_type: "breach.closed", closed_at: "2026-05-20T09:00:00Z" }),
  ];
  for (const inp of inputs) {
    const env = await mintAbrV2(inp);
    const body = env.body as { field_root: string };
    assert.match(body.field_root, /^sha256:[0-9a-f]{64}$/, `event_type ${(inp as { event_type: string }).event_type}`);
  }
});

test("F2: field_root is deterministic for identical body input across mints", async () => {
  // Two separate mints with the same input keys (different signing keys + ids +
  // iats) — but field_root commits over body only, which omits id/iat/sig/iss_key.
  // Same body fields ⇒ same field_root.
  const a = await mintAbrV2(mkAssessed());
  const b = await mintAbrV2(mkAssessed());
  const ar = (a.body as { field_root: string }).field_root;
  const br = (b.body as { field_root: string }).field_root;
  assert.equal(ar, br);
});

test("F3: field_root differs across event_types with otherwise-identical context", async () => {
  const a = await mintAbrV2(mkAssessed());
  const b = await mintAbrV2(
    mkAssessed({
      event_type: "breach.dpa_delayed",
      delay_reason_hash: H("a"),
      delay_until_at: "2026-05-22T00:00:00Z",
      // overwrite the assessed-only fields so the union shape is clean
      severity_class: undefined,
      assessment_method_hash: undefined,
    }),
  );
  const ar = (a.body as { field_root: string }).field_root;
  const br = (b.body as { field_root: string }).field_root;
  assert.notEqual(ar, br);
});

test("F4: field_root differs when an input field changes", async () => {
  const a = await mintAbrV2(mkAssessed({ severity_class: "risk" }));
  const b = await mintAbrV2(mkAssessed({ severity_class: "high_risk" }));
  const ar = (a.body as { field_root: string }).field_root;
  const br = (b.body as { field_root: string }).field_root;
  assert.notEqual(ar, br);
});

test("F5: field_root lives on body, not on the envelope surface", async () => {
  const env = await mintAbrV2(mkAssessed());
  assert.ok("field_root" in (env.body as object));
  assert.equal((env as unknown as { field_root?: unknown }).field_root, undefined);
});

test("F6: incident_correlation_id is reflected in body across distinct events", async () => {
  const env1 = await mintAbrV2(mkAssessed({ incident_correlation_id: "INC-FOO" }));
  const env2 = await mintAbrV2(
    mkAssessed({
      incident_correlation_id: "INC-FOO",
      event_type: "breach.closed",
      closed_at: "2026-05-20T09:00:00Z",
      severity_class: undefined,
      assessment_method_hash: undefined,
    }),
  );
  assert.equal((env1.body as { incident_correlation_id: string }).incident_correlation_id, "INC-FOO");
  assert.equal((env2.body as { incident_correlation_id: string }).incident_correlation_id, "INC-FOO");
});

// ── B — per-event body construction ──────────────────────────────────────────

test("B1: breach.detected body carries event_type + detected_at + cross-event nulls", async () => {
  const env = await mintAbrV2(mkDetected());
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "breach.detected");
  assert.equal(body.detected_at, "2026-05-19T12:00:00Z");
  assert.equal(body.containment_at, null);
  assert.equal(body.closed_at, null);
  assert.equal(body.subject_batch_root, null);
});

test("B2: breach.assessed body carries assessment_method_hash + cross-event nulls", async () => {
  const env = await mintAbrV2(mkAssessed());
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "breach.assessed");
  assert.equal(body.assessment_method_hash, H("a"));
  assert.equal(body.detected_at, null);
  assert.equal(body.closed_at, null);
});

test("B3: breach.dpa_notified body carries notification_uri/hash + cross-event nulls", async () => {
  const env = await mintAbrV2(
    mkAssessed({
      event_type: "breach.dpa_notified",
      notification_uri: "https://x.example",
      notification_hash: H("b"),
      severity_class: undefined,
      assessment_method_hash: undefined,
    }),
  );
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "breach.dpa_notified");
  assert.equal(body.notification_uri, "https://x.example");
  assert.equal(body.notification_hash, H("b"));
  assert.equal(body.detected_at, null);
  assert.equal(body.containment_at, null);
});

test("B4: breach.dpa_delayed body carries delay_reason_hash + delay_until_at", async () => {
  const env = await mintAbrV2(
    mkAssessed({
      event_type: "breach.dpa_delayed",
      delay_reason_hash: H("c"),
      delay_until_at: "2026-05-22T12:00:00Z",
      severity_class: undefined,
      assessment_method_hash: undefined,
    }),
  );
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "breach.dpa_delayed");
  assert.equal(body.delay_reason_hash, H("c"));
  assert.equal(body.delay_until_at, "2026-05-22T12:00:00Z");
  assert.equal(body.notification_uri, null);
});

test("B5: breach.subject_notified body carries subject_batch_root + size", async () => {
  const env = await mintAbrV2(mkSubjectNotified({ subject_batch_size: 42 }));
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "breach.subject_notified");
  assert.equal(body.subject_batch_size, 42);
  assert.equal(body.subject_batch_root, H("9"));
  assert.equal(body.detected_at, null);
});

test("B6: breach.subject_notification_exempted body carries exemption_ground + justification_hash", async () => {
  const env = await mintAbrV2(
    mkAssessed({
      event_type: "breach.subject_notification_exempted",
      exemption_ground: "art34_3_b_subsequent_measures",
      justification_hash: H("d"),
      severity_class: undefined,
      assessment_method_hash: undefined,
    }),
  );
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "breach.subject_notification_exempted");
  assert.equal(body.exemption_ground, "art34_3_b_subsequent_measures");
  assert.equal(body.justification_hash, H("d"));
  assert.equal(body.public_communication_uri, null);
});

test("B7: breach.contained body carries containment_at + summary_hash + composition nulls", async () => {
  const env = await mintAbrV2(
    mkAssessed({
      event_type: "breach.contained",
      containment_at: "2026-05-19T18:00:00Z",
      containment_summary_hash: H("e"),
      severity_class: undefined,
      assessment_method_hash: undefined,
    }),
  );
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "breach.contained");
  assert.equal(body.containment_at, "2026-05-19T18:00:00Z");
  assert.equal(body.containment_summary_hash, H("e"));
  assert.equal(body.containment_attestation, null);
  assert.equal(body.transfer_suspension_atr_ids, null);
});

test("B8: breach.closed body carries closed_at + composition nulls", async () => {
  const env = await mintAbrV2(
    mkAssessed({
      event_type: "breach.closed",
      closed_at: "2026-05-20T09:00:00Z",
      severity_class: undefined,
      assessment_method_hash: undefined,
    }),
  );
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "breach.closed");
  assert.equal(body.closed_at, "2026-05-20T09:00:00Z");
  assert.equal(body.closure_dpa_reference_id, null);
  assert.equal(body.post_breach_anr_id, null);
  assert.equal(body.detected_at, null);
});

// ── S — credentialStatus attach round-trip ───────────────────────────────────

const mkStatusListCfg = () => ({
  baseUrl: "https://status.example/abr",
  getNextStatusIndex: async (_bucket: string) => 7,
});

test("S1: omitted statusList ⇒ envelope.credentialStatus is null", async () => {
  const env = await mintAbrV2(mkAssessed());
  assert.equal(env.credentialStatus, null);
});

test("S2: statusList attached ⇒ credentialStatus block populated", async () => {
  const env = await mintAbrV2(mkAssessed({ statusList: mkStatusListCfg() }));
  assert.notEqual(env.credentialStatus, null);
  const cs = env.credentialStatus as {
    id: string;
    type: string;
    statusPurpose: string;
    statusListIndex: string;
    statusListCredential: string;
  };
  assert.equal(cs.type, "StatusList2021Entry");
  assert.equal(cs.statusPurpose, "revocation");
  assert.equal(cs.statusListIndex, "7");
  assert.match(cs.statusListCredential, /^https:\/\/status\.example\/abr\/\d{4}\/\d{2}$/);
  assert.match(cs.id, /^https:\/\/status\.example\/abr\/\d{4}\/\d{2}#7$/);
});

test("S3: signed receipt with statusList still round-trips through verifier", async () => {
  const env = await mintAbrV2(mkAssessed({ statusList: mkStatusListCfg() }));
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S4: subject pinning preserved on breach.subject_notified through statusList attach", async () => {
  const root = H("9");
  const env = await mintAbrV2(mkSubjectNotified({ subject_batch_root: root, statusList: mkStatusListCfg() }));
  assert.equal(env.subject, root);
  assert.notEqual(env.credentialStatus, null);
});

test("S5: statusList attach does not mutate field_root (body unchanged)", async () => {
  const without = await mintAbrV2(mkAssessed());
  const withStatus = await mintAbrV2(mkAssessed({ statusList: mkStatusListCfg() }));
  const a = (without.body as { field_root: string }).field_root;
  const b = (withStatus.body as { field_root: string }).field_root;
  assert.equal(a, b, "credentialStatus lives on envelope, must not perturb body field_root");
});

test("S6: statusList throws when baseUrl is non-https", async () => {
  await assert.rejects(
    () =>
      mintAbrV2(
        mkAssessed({
          statusList: {
            baseUrl: "http://insecure.example/abr",
            getNextStatusIndex: async () => 0,
          },
        }),
      ),
    /baseUrl must start with https/,
  );
});

// ── X — extra throws + positive validation paths ────────────────────────────

test("X1: throws when anchor is missing", async () => {
  await assert.rejects(
    () =>
      mintAbrV2({
        ...baseCommon,
        anchor: undefined as never,
        signingKey: makeSigningKey(),
        event_type: "breach.assessed",
        severity_class: "risk",
        assessment_method_hash: H("a"),
      }),
    /anchor required/,
  );
});

test("X2: breach.dpa_notified on nis2.art23 with a valid notification_phase succeeds", async () => {
  const env = await mintAbrV2(
    mkAssessed({
      profile: "breach.nis2.art23",
      event_type: "breach.dpa_notified",
      notification_uri: "https://x.example",
      notification_hash: H("a"),
      notification_phase: "early_warning",
      severity_class: undefined,
      assessment_method_hash: undefined,
    }),
  );
  const body = env.body as { notification_phase: string };
  assert.equal(env.claim_type, "ar.breach.v1");
  assert.equal(body.notification_phase, "early_warning");
});

test("X3: subject_notification_exempted on art34_3_c_disproportionate with a public_communication_uri succeeds", async () => {
  const env = await mintAbrV2(
    mkAssessed({
      event_type: "breach.subject_notification_exempted",
      exemption_ground: "art34_3_c_disproportionate",
      justification_hash: H("a"),
      public_communication_uri: "https://example.test/public-comm",
      severity_class: undefined,
      assessment_method_hash: undefined,
    }),
  );
  const body = env.body as { public_communication_uri: string };
  assert.equal(body.public_communication_uri, "https://example.test/public-comm");
});

test("X4: dpa_notified composition fields preserved when supplied", async () => {
  const env = await mintAbrV2(
    mkAssessed({
      event_type: "breach.dpa_notified",
      notification_uri: "https://x.example",
      notification_hash: H("a"),
      dpa_reference_id: "DPA-2026-XYZ",
      qes_aar_id: "AAR-001",
      severity_class: undefined,
      assessment_method_hash: undefined,
    }),
  );
  const body = env.body as { dpa_reference_id: string; qes_aar_id: string };
  assert.equal(body.dpa_reference_id, "DPA-2026-XYZ");
  assert.equal(body.qes_aar_id, "AAR-001");
});

test("X5: breach.closed composition fields preserved when supplied", async () => {
  const env = await mintAbrV2(
    mkAssessed({
      event_type: "breach.closed",
      closed_at: "2026-05-20T09:00:00Z",
      closure_dpa_reference_id: "DPA-CLOSE",
      post_breach_anr_id: "ANR-POST-001",
      severity_class: undefined,
      assessment_method_hash: undefined,
    }),
  );
  const body = env.body as { closure_dpa_reference_id: string; post_breach_anr_id: string };
  assert.equal(body.closure_dpa_reference_id, "DPA-CLOSE");
  assert.equal(body.post_breach_anr_id, "ANR-POST-001");
});

test("X6: contained composition arrays preserved when supplied", async () => {
  const env = await mintAbrV2(
    mkAssessed({
      event_type: "breach.contained",
      containment_at: "2026-05-19T18:00:00Z",
      containment_summary_hash: H("a"),
      containment_attestation: "AAR-CONTAIN-1",
      containment_remediation_arr_ids: ["ARR-1", "ARR-2"],
      transfer_suspension_atr_ids: ["ATR-1"],
      severity_class: undefined,
      assessment_method_hash: undefined,
    }),
  );
  const body = env.body as {
    containment_attestation: string;
    containment_remediation_arr_ids: readonly string[];
    transfer_suspension_atr_ids: readonly string[];
  };
  assert.equal(body.containment_attestation, "AAR-CONTAIN-1");
  assert.deepEqual(body.containment_remediation_arr_ids, ["ARR-1", "ARR-2"]);
  assert.deepEqual(body.transfer_suspension_atr_ids, ["ATR-1"]);
});

// ── BV — boundary inputs ─────────────────────────────────────────────────────

test("BV1: subject_batch_size = 1 accepted (lower boundary)", async () => {
  const env = await mintAbrV2(mkSubjectNotified({ subject_batch_size: 1 }));
  const body = env.body as { subject_batch_size: number };
  assert.equal(body.subject_batch_size, 1);
});

test("BV2: subject_batch_size = 65536 accepted (upper boundary)", async () => {
  const env = await mintAbrV2(mkSubjectNotified({ subject_batch_size: 65536 }));
  const body = env.body as { subject_batch_size: number };
  assert.equal(body.subject_batch_size, 65536);
});

test("BV3: affected_count = 0 accepted (zero affected)", async () => {
  const env = await mintAbrV2(mkDetected({ affected_count: 0 }));
  const body = env.body as { affected_count: number };
  assert.equal(body.affected_count, 0);
});

test("BV4: affected_count = -1 accepted (undetermined sentinel)", async () => {
  const env = await mintAbrV2(mkDetected({ affected_count: -1 }));
  const body = env.body as { affected_count: number };
  assert.equal(body.affected_count, -1);
});
