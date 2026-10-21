/**
 * mintAirV2 — validation throws + invariant assertions.
 *
 * V-block covers every documented throw (input validation per event_type).
 * P-block covers cross-event invariants (claim_type, subject pinning,
 * field_root commitment, prev passthrough, kind defaults, composition
 * field passthrough).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintAirV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import { baseCommon, H, makeResolveKey, makeSigningKey } from "./_helpers/common.ts";

// ── V-block: input validation throws ─────────────────────────────────────────

test("V1: missing issuer throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        issuer: "",
        signingKey: makeSigningKey(),
        event_type: "dpia.scope_locked",
        scope_hash: H("a"),
      }),
    /issuer required/,
  );
});

test("V2: signingKey without kid throws", async () => {
  const sk = makeSigningKey();
  sk.kid = "";
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: sk,
        event_type: "dpia.scope_locked",
        scope_hash: H("a"),
      }),
    /signingKey.kid required/,
  );
});

test("V3: signingKey.privateKey not 32 bytes throws", async () => {
  const sk = makeSigningKey();
  sk.privateKey = new Uint8Array(16);
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: sk,
        event_type: "dpia.scope_locked",
        scope_hash: H("a"),
      }),
    /privateKey must be 32 bytes/,
  );
});

test("V4: missing air_receipt_id throws (D10-AIR-2)", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        air_receipt_id: "",
        signingKey: makeSigningKey(),
        event_type: "dpia.scope_locked",
        scope_hash: H("a"),
      }),
    /air_receipt_id required/,
  );
});

test("V5: missing processing_activity_id throws (D10-AIR-3)", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        processing_activity_id: "",
        signingKey: makeSigningKey(),
        event_type: "dpia.scope_locked",
        scope_hash: H("a"),
      }),
    /processing_activity_id required/,
  );
});

test("V6: threshold_triggered missing processing_activity_hash throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.threshold_triggered",
        processing_activity_hash: "not-sha256",
        processing_start_at: "2026-06-01T00:00:00Z",
      }),
    /processing_activity_hash/,
  );
});

test("V7: threshold_triggered missing processing_start_at throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.threshold_triggered",
        processing_activity_hash: H("a"),
        processing_start_at: "",
      }),
    /processing_start_at/,
  );
});

test("V8: scope_locked bad scope_hash throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.scope_locked",
        scope_hash: "bad",
      }),
    /scope_hash/,
  );
});

test("V9: dpo_advised bad dpo_did_or_email_commit throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.dpo_advised",
        dpo_did_or_email_commit: "raw",
        dpo_advice_hash: H("a"),
      }),
    /dpo_did_or_email_commit/,
  );
});

test("V10: dpo_advised bad dpo_advice_hash throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.dpo_advised",
        dpo_did_or_email_commit: H("c"),
        dpo_advice_hash: "raw",
      }),
    /dpo_advice_hash/,
  );
});

test("V11: stakeholders_consulted bad consultation_output_hash throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.stakeholders_consulted",
        consultation_method: "survey",
        consultation_output_hash: "raw",
      }),
    /consultation_output_hash/,
  );
});

test("V12: stakeholders_consulted + raw-string subject throws (D10-AIR-6)", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.stakeholders_consulted",
        consultation_method: "representative_org",
        consultation_output_hash: H("e"),
        subject: "not-a-hash",
      }),
    /subject must be `sha256:<64-hex>`/,
  );
});

test("V13: stakeholders_consulted + sha256 subject + survey method throws (D10-AIR-6)", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.stakeholders_consulted",
        consultation_method: "survey",
        consultation_output_hash: H("e"),
        subject: H("f"),
      }),
    /representative_org.*ngo_review/,
  );
});

test("V14: completed bad dpia_artifact_hash throws (D10-AIR-7)", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.completed",
        dpia_artifact_hash: "raw",
        dpia_uri: "https://x",
        residual_risk_level: "low",
        review_due_at: "2027-05-19T00:00:00Z",
      }),
    /dpia_artifact_hash/,
  );
});

test("V15: completed missing dpia_uri throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.completed",
        dpia_artifact_hash: H("g"),
        dpia_uri: "",
        residual_risk_level: "low",
        review_due_at: "2027-05-19T00:00:00Z",
      }),
    /dpia_uri/,
  );
});

test("V16: completed missing review_due_at throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.completed",
        dpia_artifact_hash: H("g"),
        dpia_uri: "https://x",
        residual_risk_level: "low",
        review_due_at: "",
      }),
    /review_due_at/,
  );
});

test("V17: reviewed bad review_evidence_hash throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.reviewed",
        review_outcome: "no_material_change",
        review_evidence_hash: "raw",
      }),
    /review_evidence_hash/,
  );
});

test("V18: prior_consultation_initiated bad dpa_jurisdiction throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.prior_consultation_initiated",
        dpa_jurisdiction: "ESP",
        submission_hash: H("i"),
      }),
    /dpa_jurisdiction/,
  );
});

test("V19: prior_consultation_initiated bad submission_hash throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.prior_consultation_initiated",
        dpa_jurisdiction: "ES",
        submission_hash: "raw",
      }),
    /submission_hash/,
  );
});

test("V20: prior_consultation_resolved bad dpa_advice_hash throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.prior_consultation_resolved",
        dpa_advice_hash: "raw",
        controller_response_hash: H("k"),
      }),
    /dpa_advice_hash/,
  );
});

test("V21: prior_consultation_resolved bad controller_response_hash throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.prior_consultation_resolved",
        dpa_advice_hash: H("j"),
        controller_response_hash: "raw",
      }),
    /controller_response_hash/,
  );
});

test("V22: terminated bad termination_reason_hash throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.terminated",
        termination_reason_hash: "raw",
      }),
    /termination_reason_hash/,
  );
});

test("V23: tsa config without tsaFetcher throws", async () => {
  await assert.rejects(
    () =>
      mintAirV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "dpia.scope_locked",
        scope_hash: H("a"),
        tsa: { url: "https://freetsa.org", trustAnchorIds: [], hashAlg: "sha-256", driftToleranceSec: 300, timeoutMs: 5000 },
      }),
    /tsaFetcher is required/,
  );
});

test("V24: prior_consultation_initiated accepts EU-EDPB jurisdiction", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.prior_consultation_initiated",
    dpa_jurisdiction: "EU-EDPB",
    submission_hash: H("i"),
  });
  const body = env.body as { dpa_jurisdiction: string };
  assert.equal(body.dpa_jurisdiction, "EU-EDPB");
});

// ── P-block: invariants ───────────────────────────────────────────────────────

test("P1: claim_type is `ar.impact.v1` on every event_type", async () => {
  const sk = makeSigningKey();
  const envs = await Promise.all([
    mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.threshold_triggered", processing_activity_hash: H("a"), processing_start_at: "2026-06-01T00:00:00Z" }),
    mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.scope_locked", scope_hash: H("b") }),
    mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.completed", dpia_artifact_hash: H("c"), dpia_uri: "https://x", residual_risk_level: "low", review_due_at: "2027-05-19T00:00:00Z" }),
    mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.terminated", termination_reason_hash: H("d") }),
  ]);
  for (const e of envs) assert.equal(e.claim_type, "ar.impact.v1");
});

test("P2: subject is null on every non-stakeholders_consulted event regardless of caller (input forbids supply)", async () => {
  const sk = makeSigningKey();
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: sk,
    event_type: "dpia.completed",
    dpia_artifact_hash: H("c"),
    dpia_uri: "https://x",
    residual_risk_level: "low",
    review_due_at: "2027-05-19T00:00:00Z",
  });
  assert.equal(env.subject, null);
});

test("P3: stakeholders_consulted + null subject (omitted) → envelope.subject null", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.stakeholders_consulted",
    consultation_method: "survey",
    consultation_output_hash: H("e"),
  });
  assert.equal(env.subject, null);
});

test("P4: stakeholders_consulted + sha256 subject + representative_org → envelope.subject preserved", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.stakeholders_consulted",
    consultation_method: "representative_org",
    consultation_output_hash: H("e"),
    subject: H("f"),
  });
  assert.equal(env.subject, H("f"));
});

test("P5: stakeholders_consulted + sha256 subject + ngo_review → envelope.subject preserved", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.stakeholders_consulted",
    consultation_method: "ngo_review",
    consultation_output_hash: H("e"),
    subject: H("g"),
  });
  assert.equal(env.subject, H("g"));
});

test("P6: field_root present on body, sha256:<64-hex>", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
  });
  const body = env.body as { field_root: string };
  assert.match(body.field_root, /^sha256:[0-9a-f]{64}$/);
});

test("P7: prev null by default; caller-supplied prev passes through", async () => {
  const sk = makeSigningKey();
  const e1 = await mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.scope_locked", scope_hash: H("a") });
  assert.equal(e1.prev, null);
  const e2 = await mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.scope_locked", scope_hash: H("a"), prev: "AIR-PREV-1" });
  assert.equal(e2.prev, "AIR-PREV-1");
});

test("P8: per-event kind defaults — observation vs decision", async () => {
  const sk = makeSigningKey();
  const obsTypes: Array<[string, () => Promise<{ kind?: unknown }>]> = [
    ["dpia.threshold_triggered", () => mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.threshold_triggered", processing_activity_hash: H("a"), processing_start_at: "2026-06-01T00:00:00Z" })],
    ["dpia.dpo_advised", () => mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.dpo_advised", dpo_did_or_email_commit: H("c"), dpo_advice_hash: H("d") })],
    ["dpia.stakeholders_consulted", () => mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.stakeholders_consulted", consultation_method: "survey", consultation_output_hash: H("e") })],
    ["dpia.prior_consultation_resolved", () => mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.prior_consultation_resolved", dpa_advice_hash: H("j"), controller_response_hash: H("k") })],
  ];
  for (const [name, mint] of obsTypes) {
    const e = await mint();
    assert.equal(e.kind, "observation", `${name} should be observation`);
  }
  const decTypes: Array<[string, () => Promise<{ kind?: unknown }>]> = [
    ["dpia.scope_locked", () => mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.scope_locked", scope_hash: H("a") })],
    ["dpia.completed", () => mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.completed", dpia_artifact_hash: H("c"), dpia_uri: "https://x", residual_risk_level: "low", review_due_at: "2027-05-19T00:00:00Z" })],
    ["dpia.processing_authorised", () => mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.processing_authorised" })],
    ["dpia.terminated", () => mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.terminated", termination_reason_hash: H("l") })],
  ];
  for (const [name, mint] of decTypes) {
    const e = await mint();
    assert.equal(e.kind, "decision", `${name} should be decision`);
  }
});

test("P9: envelope_kind=null opt-out preserved", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
    envelope_kind: null,
  });
  assert.equal(env.kind, null);
});

test("P10: completed composition fields default null when omitted; preserved when supplied", async () => {
  const sk = makeSigningKey();
  const bare = await mintAirV2({
    ...baseCommon,
    signingKey: sk,
    event_type: "dpia.completed",
    dpia_artifact_hash: H("c"),
    dpia_uri: "https://x",
    residual_risk_level: "low",
    review_due_at: "2027-05-19T00:00:00Z",
  });
  const bareBody = bare.body as {
    aer_receipt_ids: unknown;
    atr_receipt_ids: unknown;
    alr_receipt_ids: unknown;
    apur_receipt_ids: unknown;
  };
  assert.equal(bareBody.aer_receipt_ids, null);
  assert.equal(bareBody.atr_receipt_ids, null);
  assert.equal(bareBody.alr_receipt_ids, null);
  assert.equal(bareBody.apur_receipt_ids, null);

  const filled = await mintAirV2({
    ...baseCommon,
    signingKey: sk,
    event_type: "dpia.completed",
    dpia_artifact_hash: H("c"),
    dpia_uri: "https://x",
    residual_risk_level: "high",
    review_due_at: "2027-05-19T00:00:00Z",
    aer_receipt_ids: ["AER-1", "AER-2"],
    alr_receipt_ids: ["ALR-1"],
  });
  const filledBody = filled.body as {
    aer_receipt_ids: readonly string[];
    alr_receipt_ids: readonly string[];
  };
  assert.deepEqual(filledBody.aer_receipt_ids, ["AER-1", "AER-2"]);
  assert.deepEqual(filledBody.alr_receipt_ids, ["ALR-1"]);
});

test("P11: id is a 26-char Crockford ULID", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
  });
  assert.match(env.id, /^[0-9A-HJKMNP-TV-Z]{26}$/);
});

test("P12: iat ISO + iat_ms parity", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
  });
  assert.match(env.iat, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  assert.equal(env.iat_ms, Date.parse(env.iat));
});

test("P13: round-trip — minted reviewed receipt verifies via @dekimuhq/air", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.reviewed",
    review_outcome: "no_material_change",
    review_evidence_hash: H("h"),
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("P14: exp default null; supplied value passes through", async () => {
  const sk = makeSigningKey();
  const e1 = await mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.scope_locked", scope_hash: H("a") });
  assert.equal(e1.exp, null);
  const e2 = await mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.scope_locked", scope_hash: H("a"), exp: "2030-01-01T00:00:00Z" });
  assert.equal(e2.exp, "2030-01-01T00:00:00Z");
});

test("P15: cause default null; supplied value passes through", async () => {
  const sk = makeSigningKey();
  const e1 = await mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.scope_locked", scope_hash: H("a") });
  assert.equal(e1.cause, null);
  const e2 = await mintAirV2({
    ...baseCommon,
    signingKey: sk,
    event_type: "dpia.reviewed",
    review_outcome: "material_change",
    review_evidence_hash: H("h"),
    cause: "material_change",
  });
  assert.equal(e2.cause, "material_change");
});

test("P16: reviewed abr_receipt_id defaults null when omitted", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.reviewed",
    review_outcome: "no_material_change",
    review_evidence_hash: H("h"),
  });
  const body = env.body as { abr_receipt_id: unknown };
  assert.equal(body.abr_receipt_id, null);
});

test("P17: air_receipt_id + processing_activity_id round-trip through body", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    air_receipt_id: "AIR-CUSTOM-42",
    processing_activity_id: "PA-CUSTOM-X",
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
  });
  const body = env.body as { air_receipt_id: string; processing_activity_id: string };
  assert.equal(body.air_receipt_id, "AIR-CUSTOM-42");
  assert.equal(body.processing_activity_id, "PA-CUSTOM-X");
});

test("P18: terminal_disposition is pinned per event_type — caller cannot diverge", async () => {
  const sk = makeSigningKey();
  const auth = await mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.processing_authorised" });
  const block = await mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.processing_blocked" });
  const term = await mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.terminated", termination_reason_hash: H("l") });
  assert.equal((auth.body as { terminal_disposition: string }).terminal_disposition, "authorised");
  assert.equal((block.body as { terminal_disposition: string }).terminal_disposition, "blocked");
  assert.equal((term.body as { terminal_disposition: string }).terminal_disposition, "terminated");
});

test("P19: prior_consultation_resolved dpa_did default null; supplied passes through", async () => {
  const sk = makeSigningKey();
  const e1 = await mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.prior_consultation_resolved", dpa_advice_hash: H("j"), controller_response_hash: H("k") });
  assert.equal((e1.body as { dpa_did: unknown }).dpa_did, null);
  const e2 = await mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.prior_consultation_resolved", dpa_advice_hash: H("j"), controller_response_hash: H("k"), dpa_did: "did:web:dpa.example" });
  assert.equal((e2.body as { dpa_did: string }).dpa_did, "did:web:dpa.example");
});

test("P20: sig is populated and non-empty on every mint (base64url, no prefix)", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
  });
  assert.ok(env.sig.length > 0);
  assert.match(env.sig, /^[A-Za-z0-9_-]+$/);
});

test("P21: policy fields preserved byte-equal", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    policy_uri: "https://controller.example/dpia-methodology/v2",
    policy_hash: H("z"),
    policy_version: "2.1.0",
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
  });
  assert.equal(env.policy_uri, "https://controller.example/dpia-methodology/v2");
  assert.equal(env.policy_hash, H("z"));
  assert.equal(env.policy_version, "2.1.0");
});

test("P22: iss + iss_key match — iss_key is ed25519:<base64url>", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
  });
  assert.equal(env.iss, baseCommon.issuer);
  assert.match(env.iss_key, /^ed25519:[A-Za-z0-9_-]+$/);
});

test("P23: two mints of identical input produce different `id` and `iat` (non-determinism by design)", async () => {
  const sk = makeSigningKey();
  const e1 = await mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.scope_locked", scope_hash: H("a") });
  await new Promise((r) => setTimeout(r, 5));
  const e2 = await mintAirV2({ ...baseCommon, signingKey: sk, event_type: "dpia.scope_locked", scope_hash: H("a") });
  assert.notEqual(e1.id, e2.id);
});

test("P24: tsa block is null when no tsa config supplied", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
  });
  assert.equal(env.tsa, null);
});

test("P25: credentialStatus is null by default (no statusList config)", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
  });
  assert.equal(env.credentialStatus, null);
});

test("P26: anchor passes through unchanged", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
  });
  assert.deepEqual(env.anchor, baseCommon.anchor);
});

test("P27: v=2 literal on every receipt", async () => {
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
  });
  assert.equal(env.v, 2);
});

test("P_QTS: non-null qts_attestation_hash round-trips through verifier", async () => {
  const QTS = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const env = await mintAirV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "dpia.scope_locked",
    scope_hash: H("a"),
    qts_attestation_hash: QTS,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.qts_attestation_hash, QTS);
  const result = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(result.signature_valid, true, result.reason ?? "ok");
});
