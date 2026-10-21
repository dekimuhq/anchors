/**
 * AActR mandate-binding: optional `credential_id` + `caveats_consumed`
 * (spec §4.4 — additive, validator + mint round-trip).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyActionBody } from "../src/verify-single.ts";
import { mintActionV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import { validBody, baseInput, makeResolveKey } from "./_helpers/fixtures.ts";

// ── Validator (verifyActionBody) ──────────────────────────────────────────────

test("CB1: valid without the optional binding fields (backward-compatible)", () => {
  const r = verifyActionBody(validBody());
  assert.equal(r.valid, true);
});

test("CB2: valid with well-formed credential_id + caveats_consumed", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    caveats_consumed: { data_scope: "ws:acme", spend_step: 1, capability: "ropa.compile" },
  });
  assert.equal(r.valid, true);
});

test("CB3: rejects empty credential_id", () => {
  const r = verifyActionBody({ ...validBody(), credential_id: "" });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("credential_id.invalid"));
});

test("CB4: rejects malformed caveats_consumed (missing capability)", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    caveats_consumed: { data_scope: "ws:acme", spend_step: 1 },
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("caveats_consumed.invalid"));
});

test("CB5: rejects caveats_consumed.spend_step that is not a finite number", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    caveats_consumed: { data_scope: "ws:acme", spend_step: "1", capability: "x" },
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("caveats_consumed.invalid"));
});

test("CB6: rejects caveats_consumed without credential_id (orphan)", () => {
  const r = verifyActionBody({
    ...validBody(),
    caveats_consumed: { data_scope: "ws:acme", spend_step: 1, capability: "x" },
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("caveats_consumed.orphan"));
});

// ── Mint → verify round-trip (mintActionV2) ───────────────────────────────────

test("CB7: mint carries credential_id + caveats_consumed into the body, round-trips", async () => {
  const env = await mintActionV2({
    ...baseInput(),
    credential_id: "adr-grant-123",
    caveats_consumed: { data_scope: "ws:acme", spend_step: 1, capability: "ropa.compile" },
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.credential_id, "adr-grant-123");
  assert.deepEqual(body.caveats_consumed, {
    data_scope: "ws:acme",
    spend_step: 1,
    capability: "ropa.compile",
  });
  // The body verifier accepts the minted body.
  assert.equal(verifyActionBody(body).valid, true);
  // Full signature round-trip still holds with the additive fields present.
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("CB8: mint omits the binding fields entirely when not provided (no undefined keys)", async () => {
  const env = await mintActionV2(baseInput());
  const body = env.body as Record<string, unknown>;
  assert.ok(!("credential_id" in body), "credential_id key must be absent, not undefined");
  assert.ok(!("caveats_consumed" in body), "caveats_consumed key must be absent");
});

// ── Optional spend_currency unit tag (additive, monetary spend_step) ───────────

test("CB9: valid with a monetary spend_step + spend_currency unit tag", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    caveats_consumed: {
      data_scope: "ws:acme",
      spend_step: 4.5,
      spend_currency: "EUR",
      capability: "invoiceup.remind",
    },
  });
  assert.equal(r.valid, true);
});

test("CB9b: rejects a negative spend_step (a decrement is non-negative in any unit)", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    caveats_consumed: { data_scope: "ws:acme", spend_step: -1, capability: "x" },
  });
  assert.ok(r.errors.includes("caveats_consumed.invalid"));
});

test("CB10: rejects an empty spend_currency (present means it must be a real unit)", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    caveats_consumed: {
      data_scope: "ws:acme",
      spend_step: 4.5,
      spend_currency: "",
      capability: "x",
    },
  });
  assert.ok(r.errors.includes("caveats_consumed.invalid"));
});

test("CB11: mint round-trips a monetary spend_step with its spend_currency", async () => {
  const env = await mintActionV2({
    ...baseInput(),
    credential_id: "adr-grant-123",
    caveats_consumed: {
      data_scope: "ws:acme",
      spend_step: 4.5,
      spend_currency: "EUR",
      capability: "invoiceup.remind",
    },
  });
  const body = env.body as Record<string, unknown>;
  assert.deepEqual(body.caveats_consumed, {
    data_scope: "ws:acme",
    spend_step: 4.5,
    spend_currency: "EUR",
    capability: "invoiceup.remind",
  });
  assert.equal(verifyActionBody(body).valid, true);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── Optional per-agent principal `agent_id` (spec §4.6 — additive) ─────────────

test("CB12: valid with a well-formed agent_id alongside credential_id", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    caveats_consumed: { data_scope: "ws:acme", spend_step: 1, capability: "ropa.compile" },
    agent_id: "agent:billing-bot",
  });
  assert.equal(r.valid, true);
});

test("CB13: rejects an empty agent_id (present means it must be a real principal)", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    agent_id: "",
  });
  assert.ok(r.errors.includes("agent_id.invalid"));
});

test("CB14: rejects a non-string agent_id", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: "adr-grant-123",
    agent_id: 42,
  });
  assert.ok(r.errors.includes("agent_id.invalid"));
});

test("CB15: rejects agent_id without credential_id (orphan)", () => {
  const r = verifyActionBody({
    ...validBody(),
    agent_id: "agent:billing-bot",
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("agent_id.orphan"));
});

test("CB16: mint carries agent_id into the body and round-trips", async () => {
  const env = await mintActionV2({
    ...baseInput(),
    credential_id: "adr-grant-123",
    caveats_consumed: { data_scope: "ws:acme", spend_step: 1, capability: "ropa.compile" },
    agent_id: "agent:billing-bot",
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.agent_id, "agent:billing-bot");
  assert.equal(verifyActionBody(body).valid, true);
  // Signature round-trip still holds with the additive field present.
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("CB17: mint omits agent_id entirely when not provided (no undefined key)", async () => {
  const env = await mintActionV2({
    ...baseInput(),
    credential_id: "adr-grant-123",
    caveats_consumed: { data_scope: "ws:acme", spend_step: 1, capability: "ropa.compile" },
  });
  const body = env.body as Record<string, unknown>;
  assert.ok(!("agent_id" in body), "agent_id key must be absent, not undefined");
});
