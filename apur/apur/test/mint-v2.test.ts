/**
 * Tests for mintApurV2 — covers all 3 event types, validation guards,
 * and round-trip verification.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintApurV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import {
  anchor,
  baseCommon,
  bindingFields,
  repurposeFields,
  unbindingFields,
  H,
  makeResolveKey,
  makeSigningKey,
} from "./_helpers/fixtures.ts";

const PREV = "01HBINDING00000000000000";

// ── V1: mint binding produces signed envelope ─────────────────────────────────

test("V1: mint binding produces v=2 envelope with correct claim_type and subject null", async () => {
  const env = await mintApurV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "binding",
    ...bindingFields,
  });
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.purpose.v1");
  assert.equal(env.subject, null);
  assert.equal((env.body as { event_type: string }).event_type, "binding");
  assert.ok(env.sig.length > 0);
});

// ── V2: mint repurpose — with prev set ────────────────────────────────────────

test("V2: mint repurpose with prev set produces signed envelope", async () => {
  const env = await mintApurV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "repurpose",
    prev: PREV,
    ...repurposeFields,
  });
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.purpose.v1");
  assert.equal((env.body as { event_type: string }).event_type, "repurpose");
  assert.ok(env.sig.length > 0);
});

// ── V3: mint unbinding — with prev set ───────────────────────────────────────

test("V3: mint unbinding with prev set produces signed envelope", async () => {
  const env = await mintApurV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "unbinding",
    prev: PREV,
    ...unbindingFields,
  });
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.purpose.v1");
  assert.equal((env.body as { event_type: string }).event_type, "unbinding");
  assert.ok(env.sig.length > 0);
});

// ── V4: binding rejects non-null prev ────────────────────────────────────────

test("V4: binding rejects non-null prev", async () => {
  await assert.rejects(
    () =>
      mintApurV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "binding",
        prev: PREV,
        ...bindingFields,
      }),
    /chain head/,
  );
});

// ── V5: repurpose rejects null prev ──────────────────────────────────────────

test("V5: repurpose rejects null prev", async () => {
  await assert.rejects(
    () =>
      mintApurV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "repurpose",
        ...repurposeFields,
      }),
    /chain continuation/,
  );
});

// ── V6: unbinding rejects null prev ──────────────────────────────────────────

test("V6: unbinding rejects null prev", async () => {
  await assert.rejects(
    () =>
      mintApurV2({
        ...baseCommon,
        signingKey: makeSigningKey(),
        event_type: "unbinding",
        ...unbindingFields,
      }),
    /chain continuation/,
  );
});

// ── V7: missing issuer → throws ───────────────────────────────────────────────

test("V7: throws when issuer missing", async () => {
  await assert.rejects(
    () =>
      mintApurV2({
        ...baseCommon,
        issuer: "",
        signingKey: makeSigningKey(),
        event_type: "binding",
        ...bindingFields,
      }),
    /issuer required/,
  );
});

// ── V8: missing anchor → throws ──────────────────────────────────────────────

test("V8: throws when anchor missing", async () => {
  await assert.rejects(
    () =>
      mintApurV2({
        ...baseCommon,
        anchor: null as unknown as typeof anchor,
        signingKey: makeSigningKey(),
        event_type: "binding",
        ...bindingFields,
      }),
    /anchor required/,
  );
});

// ── V9: subject is always null on all 3 event types ──────────────────────────

test("V9: subject is null on binding", async () => {
  const env = await mintApurV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "binding",
    ...bindingFields,
  });
  assert.equal(env.subject, null);
});

test("V9b: subject is null on repurpose", async () => {
  const env = await mintApurV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "repurpose",
    prev: PREV,
    ...repurposeFields,
  });
  assert.equal(env.subject, null);
});

test("V9c: subject is null on unbinding", async () => {
  const env = await mintApurV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "unbinding",
    prev: PREV,
    ...unbindingFields,
  });
  assert.equal(env.subject, null);
});

// ── V10: field_root present in body ──────────────────────────────────────────

test("V10: field_root present and sha256-prefixed in binding body", async () => {
  const env = await mintApurV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "binding",
    ...bindingFields,
  });
  const body = env.body as Record<string, unknown>;
  assert.ok(typeof body["field_root"] === "string");
  assert.ok((body["field_root"] as string).startsWith("sha256:"));
});

// ── V11: default kind is "decision" ──────────────────────────────────────────

test("V11: default kind is decision", async () => {
  const env = await mintApurV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "binding",
    ...bindingFields,
  });
  assert.equal(env.kind, "decision");
});

// ── V12: body.event_type matches input ───────────────────────────────────────

test("V12: body event_type matches input for all 3 types", async () => {
  const signingKey = makeSigningKey();

  const b = await mintApurV2({ ...baseCommon, signingKey, event_type: "binding", ...bindingFields });
  assert.equal((b.body as { event_type: string }).event_type, "binding");

  const r = await mintApurV2({ ...baseCommon, signingKey, event_type: "repurpose", prev: PREV, ...repurposeFields });
  assert.equal((r.body as { event_type: string }).event_type, "repurpose");

  const u = await mintApurV2({ ...baseCommon, signingKey, event_type: "unbinding", prev: PREV, ...unbindingFields });
  assert.equal((u.body as { event_type: string }).event_type, "unbinding");
});

// ── V13: all binding body fields present ─────────────────────────────────────

test("V13: all binding body fields present in output", async () => {
  const env = await mintApurV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "binding",
    ...bindingFields,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body["activity_id_commit"], bindingFields.activity_id_commit);
  assert.equal(body["purpose_commit"], bindingFields.purpose_commit);
  assert.equal(body["purpose_class"], bindingFields.purpose_class);
  assert.equal(body["lawful_basis"], bindingFields.lawful_basis);
  assert.deepEqual(body["data_categories"], bindingFields.data_categories);
  assert.equal(body["data_subjects_class"], bindingFields.data_subjects_class);
  assert.equal(body["policy_hash"], bindingFields.policy_hash_body);
  assert.equal(body["minimisation_hash"], bindingFields.minimisation_hash);
  assert.equal(body["bound_at"], bindingFields.bound_at);
  assert.equal(body["consent_receipt_hash"], null);
  assert.equal(body["retention_receipt_hash"], null);
  assert.equal(body["transfer_arrangement_hash"], null);
});

// ── V14: all repurpose body fields present ───────────────────────────────────

test("V14: all repurpose body fields present in output", async () => {
  const env = await mintApurV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "repurpose",
    prev: PREV,
    ...repurposeFields,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body["new_purpose_commit"], repurposeFields.new_purpose_commit);
  assert.equal(body["new_purpose_class"], repurposeFields.new_purpose_class);
  assert.equal(body["compat_link_hash"], repurposeFields.compat_link_hash);
  assert.equal(body["compat_context_hash"], repurposeFields.compat_context_hash);
  assert.equal(body["compat_subjects_reasonable_hash"], repurposeFields.compat_subjects_reasonable_hash);
  assert.equal(body["compat_consequences_hash"], repurposeFields.compat_consequences_hash);
  assert.equal(body["compat_safeguards_hash"], repurposeFields.compat_safeguards_hash);
  assert.equal(body["compat_conclusion"], repurposeFields.compat_conclusion);
  assert.equal(body["minimisation_hash"], repurposeFields.minimisation_hash);
  assert.equal(body["tested_at"], repurposeFields.tested_at);
});

// ── V15: all unbinding body fields present ───────────────────────────────────

test("V15: all unbinding body fields present in output", async () => {
  const env = await mintApurV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "unbinding",
    prev: PREV,
    ...unbindingFields,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body["reason"], unbindingFields.reason);
  assert.equal(body["downstream_arr_receipt_hash"], null);
  assert.equal(body["unbound_at"], unbindingFields.unbound_at);
});

// ── T_QTS: non-null qts_attestation_hash round-trips ────────────────────────

test("T_QTS: non-null qts_attestation_hash round-trips through verifier", async () => {
  const QTS = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const env = await mintApurV2({
    ...baseCommon,
    signingKey: makeSigningKey(),
    event_type: "binding",
    ...bindingFields,
    qts_attestation_hash: QTS,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.qts_attestation_hash, QTS);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});
