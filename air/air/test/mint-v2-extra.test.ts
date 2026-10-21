/**
 * Gap-fill tests for mint-v2.ts beyond the V1-V24 throws and P1-P27 invariants
 * already covered in mint-v2.test.ts.
 *
 * Drives air-issuer-kit above the >=99 per-package test floor (Phase 5 §I).
 * Groups:
 *   E*  — envelope passthrough invariants (countersig null, prev explicit-null,
 *         envelope_kind override, predicate passthrough, jurisdiction variants)
 *   F*  — field_root commitment invariants across the 11 AIR event types
 *         (determinism, per-event differentiation, per-input differentiation,
 *         surface placement)
 *   B*  — body construction invariants per event_type (discriminator + at least
 *         one cross-event-pinned null + the event-specific field) for events
 *         not already covered by the P-block
 *   S*  — credentialStatus attach round-trip + subject pinning interaction on
 *         stakeholders_consulted
 *   X*  — extra throws + positive validation paths not covered by V1-V24
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintAirV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import type { JsonLogicAst } from "@dekimuhq/anchors-envelope";
import { baseCommon, H, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

// ── Convenience makers (one per event_type that this file exercises) ──────────

const sk = () => makeSigningKey();

const mkScopeLocked = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "dpia.scope_locked" as const,
    scope_hash: H("scope"),
    ...overrides,
  }) as Parameters<typeof mintAirV2>[0];

const mkThresholdTriggered = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "dpia.threshold_triggered" as const,
    processing_activity_hash: H("pa"),
    processing_start_at: "2026-06-01T00:00:00Z",
    ...overrides,
  }) as Parameters<typeof mintAirV2>[0];

const mkDpoAdvised = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "dpia.dpo_advised" as const,
    dpo_did_or_email_commit: H("dpo-commit"),
    dpo_advice_hash: H("dpo-advice"),
    ...overrides,
  }) as Parameters<typeof mintAirV2>[0];

const mkStakeholdersConsulted = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "dpia.stakeholders_consulted" as const,
    consultation_method: "survey" as const,
    consultation_output_hash: H("consult"),
    ...overrides,
  }) as Parameters<typeof mintAirV2>[0];

const mkCompleted = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "dpia.completed" as const,
    dpia_artifact_hash: H("dpia-art"),
    dpia_uri: "https://controller.example/dpia.pdf",
    residual_risk_level: "low" as const,
    review_due_at: "2027-05-19T00:00:00Z",
    ...overrides,
  }) as Parameters<typeof mintAirV2>[0];

const mkReviewed = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "dpia.reviewed" as const,
    review_outcome: "no_material_change" as const,
    review_evidence_hash: H("review"),
    ...overrides,
  }) as Parameters<typeof mintAirV2>[0];

const mkPriorConsultationInitiated = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "dpia.prior_consultation_initiated" as const,
    dpa_jurisdiction: "ES",
    submission_hash: H("submit"),
    ...overrides,
  }) as Parameters<typeof mintAirV2>[0];

const mkPriorConsultationResolved = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "dpia.prior_consultation_resolved" as const,
    dpa_advice_hash: H("dpa-advice"),
    controller_response_hash: H("ctrl-resp"),
    ...overrides,
  }) as Parameters<typeof mintAirV2>[0];

const mkProcessingAuthorised = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "dpia.processing_authorised" as const,
    ...overrides,
  }) as Parameters<typeof mintAirV2>[0];

const mkProcessingBlocked = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "dpia.processing_blocked" as const,
    ...overrides,
  }) as Parameters<typeof mintAirV2>[0];

const mkTerminated = (overrides: Record<string, unknown> = {}) =>
  ({
    ...baseCommon,
    signingKey: sk(),
    event_type: "dpia.terminated" as const,
    termination_reason_hash: H("term"),
    ...overrides,
  }) as Parameters<typeof mintAirV2>[0];

// ── E — envelope passthrough ─────────────────────────────────────────────────

test("E1: countersig is null at mint", async () => {
  const env = await mintAirV2(mkScopeLocked());
  assert.equal(env.countersig, null);
});

test("E2: explicit prev: null behaves identically to omission", async () => {
  const env = await mintAirV2(mkScopeLocked({ prev: null }));
  assert.equal(env.prev, null);
});

test("E3: envelope_kind 'observation' explicit override preserved on a default-decision event", async () => {
  // dpia.scope_locked defaults to "decision"; caller can override to "observation".
  const env = await mintAirV2(mkScopeLocked({ envelope_kind: "observation" }));
  assert.equal(env.kind, "observation");
});

test("E4: envelope_kind 'decision' explicit override preserved on a default-observation event", async () => {
  // dpia.threshold_triggered defaults to "observation"; caller can override to "decision".
  const env = await mintAirV2(mkThresholdTriggered({ envelope_kind: "decision" }));
  assert.equal(env.kind, "decision");
});

test("E5: predicate defaults null and supplied JSON Logic predicate passes through", async () => {
  const def = await mintAirV2(mkScopeLocked());
  assert.equal(def.predicate, null);
  const predicate = { "===": [1, 1] } as unknown as JsonLogicAst;
  const set = await mintAirV2(mkScopeLocked({ predicate }));
  assert.deepEqual(set.predicate, { "===": [1, 1] });
});

test("E6: dpa_jurisdiction 'DE' (different ISO country) round-trips through body", async () => {
  const env = await mintAirV2(mkPriorConsultationInitiated({ dpa_jurisdiction: "DE" }));
  const body = env.body as { dpa_jurisdiction: string };
  assert.equal(body.dpa_jurisdiction, "DE");
});

test("E7: residual_risk_level 'high' preserved on body", async () => {
  const env = await mintAirV2(mkCompleted({ residual_risk_level: "high" }));
  const body = env.body as { residual_risk_level: string };
  assert.equal(body.residual_risk_level, "high");
});

test("E8: review_outcome 'material_change' preserved on body", async () => {
  const env = await mintAirV2(mkReviewed({ review_outcome: "material_change" }));
  const body = env.body as { review_outcome: string };
  assert.equal(body.review_outcome, "material_change");
});

test("E9: termination_reason_hash preserved on body", async () => {
  const env = await mintAirV2(mkTerminated({ termination_reason_hash: H("voluntary-shutdown") }));
  const body = env.body as { termination_reason_hash: string };
  assert.equal(body.termination_reason_hash, H("voluntary-shutdown"));
});

// ── F — field_root commitment ────────────────────────────────────────────────

test("F1: field_root present on every event_type (all 11)", async () => {
  const inputs: Parameters<typeof mintAirV2>[0][] = [
    mkThresholdTriggered(),
    mkScopeLocked(),
    mkDpoAdvised(),
    mkStakeholdersConsulted(),
    mkCompleted(),
    mkReviewed(),
    mkPriorConsultationInitiated(),
    mkPriorConsultationResolved(),
    mkProcessingAuthorised(),
    mkProcessingBlocked(),
    mkTerminated(),
  ];
  for (const inp of inputs) {
    const env = await mintAirV2(inp);
    const body = env.body as { field_root: string };
    assert.match(
      body.field_root,
      /^sha256:[0-9a-f]{64}$/,
      `event_type ${(inp as { event_type: string }).event_type}`,
    );
  }
});

test("F2: field_root is deterministic for identical body input across mints", async () => {
  // Two separate mints with the same input keys (different signing keys + ids +
  // iats) — but field_root commits over body only, which omits id/iat/sig/iss_key.
  const a = await mintAirV2(mkScopeLocked());
  const b = await mintAirV2(mkScopeLocked());
  const ar = (a.body as { field_root: string }).field_root;
  const br = (b.body as { field_root: string }).field_root;
  assert.equal(ar, br);
});

test("F3: field_root differs across event_types with otherwise-identical context", async () => {
  const a = await mintAirV2(mkScopeLocked());
  const b = await mintAirV2(mkProcessingAuthorised());
  const ar = (a.body as { field_root: string }).field_root;
  const br = (b.body as { field_root: string }).field_root;
  assert.notEqual(ar, br);
});

test("F4: field_root differs when an input field changes", async () => {
  const a = await mintAirV2(mkCompleted({ residual_risk_level: "low" }));
  const b = await mintAirV2(mkCompleted({ residual_risk_level: "high" }));
  const ar = (a.body as { field_root: string }).field_root;
  const br = (b.body as { field_root: string }).field_root;
  assert.notEqual(ar, br);
});

test("F5: field_root lives on body, not on the envelope surface", async () => {
  const env = await mintAirV2(mkScopeLocked());
  assert.ok("field_root" in (env.body as object));
  assert.equal((env as unknown as { field_root?: unknown }).field_root, undefined);
});

// ── B — per-event body construction ──────────────────────────────────────────

test("B1: dpia.threshold_triggered body carries processing_activity_hash + start_at + cross-event nulls", async () => {
  const env = await mintAirV2(mkThresholdTriggered());
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "dpia.threshold_triggered");
  assert.equal(body.processing_activity_hash, H("pa"));
  assert.equal(body.processing_start_at, "2026-06-01T00:00:00Z");
  assert.equal(body.scope_hash, null);
  assert.equal(body.dpia_artifact_hash, null);
  assert.equal(body.termination_reason_hash, null);
});

test("B2: dpia.dpo_advised body carries dpo_did_or_email_commit + advice_hash + cross-event nulls", async () => {
  const env = await mintAirV2(mkDpoAdvised());
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "dpia.dpo_advised");
  assert.equal(body.dpo_did_or_email_commit, H("dpo-commit"));
  assert.equal(body.dpo_advice_hash, H("dpo-advice"));
  assert.equal(body.scope_hash, null);
  assert.equal(body.consultation_output_hash, null);
});

test("B3: dpia.prior_consultation_initiated body carries jurisdiction + submission_hash + nulls", async () => {
  const env = await mintAirV2(mkPriorConsultationInitiated());
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "dpia.prior_consultation_initiated");
  assert.equal(body.dpa_jurisdiction, "ES");
  assert.equal(body.submission_hash, H("submit"));
  assert.equal(body.dpa_advice_hash, null);
  assert.equal(body.controller_response_hash, null);
});

test("B4: dpia.prior_consultation_resolved body carries advice + response hashes + nulls", async () => {
  const env = await mintAirV2(mkPriorConsultationResolved());
  const body = env.body as Record<string, unknown>;
  assert.equal(body.event_type, "dpia.prior_consultation_resolved");
  assert.equal(body.dpa_advice_hash, H("dpa-advice"));
  assert.equal(body.controller_response_hash, H("ctrl-resp"));
  assert.equal(body.dpa_jurisdiction, null);
  assert.equal(body.submission_hash, null);
});

test("B5: terminal-disposition events pin terminal_disposition and null all event-specific fields", async () => {
  const auth = await mintAirV2(mkProcessingAuthorised());
  const block = await mintAirV2(mkProcessingBlocked());
  const term = await mintAirV2(mkTerminated());
  const authBody = auth.body as Record<string, unknown>;
  const blockBody = block.body as Record<string, unknown>;
  const termBody = term.body as Record<string, unknown>;
  assert.equal(authBody.terminal_disposition, "authorised");
  assert.equal(authBody.termination_reason_hash, null);
  assert.equal(blockBody.terminal_disposition, "blocked");
  assert.equal(blockBody.termination_reason_hash, null);
  assert.equal(termBody.terminal_disposition, "terminated");
  assert.equal(termBody.termination_reason_hash, H("term"));
});

// ── S — credentialStatus attach round-trip ───────────────────────────────────

const mkStatusListCfg = () => ({
  baseUrl: "https://status.example/air",
  getNextStatusIndex: async (_bucket: string) => 11,
});

test("S1: statusList attached → credentialStatus block populated with StatusList2021Entry shape", async () => {
  const env = await mintAirV2(mkScopeLocked({ statusList: mkStatusListCfg() }));
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
  assert.equal(cs.statusListIndex, "11");
  assert.match(cs.statusListCredential, /^https:\/\/status\.example\/air\/\d{4}\/\d{2}$/);
  assert.match(cs.id, /^https:\/\/status\.example\/air\/\d{4}\/\d{2}#11$/);
});

test("S2: signed receipt with statusList still round-trips through verifier", async () => {
  const env = await mintAirV2(mkScopeLocked({ statusList: mkStatusListCfg() }));
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("S3: statusList attach does not mutate body field_root (status block lives on envelope)", async () => {
  const without = await mintAirV2(mkScopeLocked());
  const withStatus = await mintAirV2(mkScopeLocked({ statusList: mkStatusListCfg() }));
  const a = (without.body as { field_root: string }).field_root;
  const b = (withStatus.body as { field_root: string }).field_root;
  assert.equal(a, b, "credentialStatus lives on envelope, must not perturb body field_root");
});

test("S4: statusList throws when baseUrl is non-https", async () => {
  await assert.rejects(
    () =>
      mintAirV2(
        mkScopeLocked({
          statusList: {
            baseUrl: "http://insecure.example/air",
            getNextStatusIndex: async () => 0,
          },
        }),
      ),
    /baseUrl must start with https/,
  );
});

test("S5: subject pinning preserved on stakeholders_consulted through statusList attach", async () => {
  const subj = H("rep-org-commit");
  const env = await mintAirV2(
    mkStakeholdersConsulted({
      consultation_method: "representative_org",
      subject: subj,
      statusList: mkStatusListCfg(),
    }),
  );
  assert.equal(env.subject, subj);
  assert.notEqual(env.credentialStatus, null);
});

// ── X — extra throws + positive validation paths ────────────────────────────

test("X1: throws when anchor is missing", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        anchor: undefined as never,
        signingKey: makeSigningKey(),
        event_type: "dpia.scope_locked",
        scope_hash: H("scope"),
      }),
    /anchor required/,
  );
});

test("X2: completed with all four composition arrays preserved verbatim", async () => {
  const env = await mintAirV2(
    mkCompleted({
      aer_receipt_ids: ["AER-1", "AER-2"],
      atr_receipt_ids: ["ATR-1"],
      alr_receipt_ids: ["ALR-1", "ALR-2", "ALR-3"],
      apur_receipt_ids: ["APUR-1"],
    }),
  );
  const body = env.body as {
    aer_receipt_ids: readonly string[];
    atr_receipt_ids: readonly string[];
    alr_receipt_ids: readonly string[];
    apur_receipt_ids: readonly string[];
  };
  assert.deepEqual(body.aer_receipt_ids, ["AER-1", "AER-2"]);
  assert.deepEqual(body.atr_receipt_ids, ["ATR-1"]);
  assert.deepEqual(body.alr_receipt_ids, ["ALR-1", "ALR-2", "ALR-3"]);
  assert.deepEqual(body.apur_receipt_ids, ["APUR-1"]);
});

test("X3: reviewed with abr_receipt_id preserved on body", async () => {
  const env = await mintAirV2(
    mkReviewed({
      review_outcome: "material_change",
      abr_receipt_id: "ABR-2026-0042",
    }),
  );
  const body = env.body as { abr_receipt_id: string };
  assert.equal(body.abr_receipt_id, "ABR-2026-0042");
});

test("X4: stakeholders_consulted with explicit subject: null behaves identically to omission", async () => {
  const env = await mintAirV2(
    mkStakeholdersConsulted({ consultation_method: "representative_org", subject: null }),
  );
  assert.equal(env.subject, null);
});

test("X5: prior_consultation_initiated accepts both EU-EDPB and ISO alpha-2 (positive sweep)", async () => {
  const eu = await mintAirV2(mkPriorConsultationInitiated({ dpa_jurisdiction: "EU-EDPB" }));
  const fr = await mintAirV2(mkPriorConsultationInitiated({ dpa_jurisdiction: "FR" }));
  assert.equal((eu.body as { dpa_jurisdiction: string }).dpa_jurisdiction, "EU-EDPB");
  assert.equal((fr.body as { dpa_jurisdiction: string }).dpa_jurisdiction, "FR");
});

test("X6: round-trip verify on stakeholders_consulted with subject + representative_org + statusList", async () => {
  const env = await mintAirV2(
    mkStakeholdersConsulted({
      consultation_method: "ngo_review",
      subject: H("ngo"),
      statusList: mkStatusListCfg(),
    }),
  );
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});
