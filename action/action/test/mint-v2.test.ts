/**
 * Tests for mintActionV2 (AActR v=2 issue path).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintActionV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import { baseInput, makeResolveKey, H } from "./_helpers/fixtures.ts";

test("M1: mints a valid receipt that round-trips through verifyReceipt", async () => {
  const env = await mintActionV2(baseInput());
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("M2: claim_type is ar.action.v1", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(env.claim_type, "ar.action.v1");
});

test("M3: subject is null (workspace-level, null-subject)", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(env.subject, null);
});

test("M4: envelope version is 2", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(env.v, 2);
});

test("M5: body carries a field_root sha256 commit", async () => {
  const env = await mintActionV2(baseInput());
  const body = env.body as Record<string, unknown>;
  assert.match(body.field_root as string, /^sha256:[0-9a-f]{64}$/);
});

test("M6: body preserves all plaintext action fields", async () => {
  const env = await mintActionV2(baseInput());
  const body = env.body as Record<string, unknown>;
  assert.equal(body.profile, "hub.automation");
  assert.equal(body.verb, "invoiceup.remind");
  assert.equal(body.rule_id, "r1");
  assert.equal(body.recipe_id, "auto-remind-overdue");
  assert.equal(body.outcome, "executed");
  assert.equal(body.executed_at, "2026-06-08T10:00:00.000Z");
});

test("M7: body preserves the three target commits", async () => {
  const env = await mintActionV2(baseInput());
  const body = env.body as Record<string, unknown>;
  assert.equal(body.decision_commit, H("a"));
  assert.equal(body.params_commit, H("b"));
  assert.equal(body.request_id_commit, H("c"));
});

test("M8: outcome=executed round-trips", async () => {
  const env = await mintActionV2({ ...baseInput(), outcome: "executed" });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
  assert.equal((env.body as { outcome: string }).outcome, "executed");
});

test("M9: outcome=failed-gave-up round-trips (spec §11.3)", async () => {
  const env = await mintActionV2({ ...baseInput(), outcome: "failed-gave-up" });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
  assert.equal((env.body as { outcome: string }).outcome, "failed-gave-up");
});

test("M10: default envelope kind is observation", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(env.kind, "observation");
});

test("M11: explicit envelope_kind override is honoured", async () => {
  const env = await mintActionV2({ ...baseInput(), envelope_kind: "decision" });
  assert.equal(env.kind, "decision");
});

test("M12: envelope_kind null is honoured", async () => {
  const env = await mintActionV2({ ...baseInput(), envelope_kind: null });
  assert.equal(env.kind, null);
});

test("M13: default cause is null", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(env.cause, null);
});

test("M14: explicit cause is honoured", async () => {
  const env = await mintActionV2({ ...baseInput(), cause: "scheduled" });
  assert.equal(env.cause, "scheduled");
});

test("M15: default prev is null", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(env.prev, null);
});

test("M16: explicit prev is honoured", async () => {
  const env = await mintActionV2({ ...baseInput(), prev: "r-parent" });
  assert.equal(env.prev, "r-parent");
});

test("M17: default exp is null", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(env.exp, null);
});

test("M18: explicit exp is honoured", async () => {
  const env = await mintActionV2({ ...baseInput(), exp: "2027-01-01T00:00:00.000Z" });
  assert.equal(env.exp, "2027-01-01T00:00:00.000Z");
});

test("M19: policy fields land on the envelope", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(env.policy_uri, "https://app.dekimu.com/automations");
  assert.equal(env.policy_hash, H("e"));
  assert.equal(env.policy_version, "plan-2.v1");
});

test("M20: iss and iss_key are populated", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(env.iss, "did:web:app.dekimu.com");
  assert.match(env.iss_key, /^ed25519:/);
});

test("M21: receipt id is a non-empty string", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(typeof env.id, "string");
  assert.ok(env.id.length > 0);
});

test("M22: two mints produce distinct ids", async () => {
  const a = await mintActionV2(baseInput());
  const b = await mintActionV2(baseInput());
  assert.notEqual(a.id, b.id);
});

test("M23: credentialStatus is null (non-consumer of Status List 2021)", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(env.credentialStatus, null);
});

test("M24: tsa is null when no TSA config given", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(env.tsa, null);
});

test("M25: throws when issuer is missing", async () => {
  await assert.rejects(
    () => mintActionV2({ ...baseInput(), issuer: "" }),
    /issuer required/,
  );
});

test("M26: throws when signingKey.kid is missing", async () => {
  const input = baseInput();
  await assert.rejects(
    () => mintActionV2({ ...input, signingKey: { ...input.signingKey, kid: "" } }),
    /signingKey\.kid required/,
  );
});

test("M27: throws when private key is not 32 bytes", async () => {
  const input = baseInput();
  await assert.rejects(
    () =>
      mintActionV2({
        ...input,
        signingKey: { ...input.signingKey, privateKey: new Uint8Array(16) },
      }),
    /must be 32 bytes/,
  );
});

test("M28: throws when anchor is missing", async () => {
  await assert.rejects(
    () => mintActionV2({ ...baseInput(), anchor: undefined as never }),
    /anchor required/,
  );
});

test("M29: throws when decision_commit is malformed", async () => {
  await assert.rejects(
    () => mintActionV2({ ...baseInput(), decision_commit: "not-a-commit" }),
    /decision_commit must be/,
  );
});

test("M30: throws when params_commit is malformed", async () => {
  await assert.rejects(
    () => mintActionV2({ ...baseInput(), params_commit: "sha256:short" }),
    /params_commit must be/,
  );
});

test("M31: throws when request_id_commit is malformed", async () => {
  await assert.rejects(
    () => mintActionV2({ ...baseInput(), request_id_commit: H("A") }),
    /request_id_commit must be/,
  );
});

test("M32: throws when tsa config supplied without a fetcher", async () => {
  await assert.rejects(
    () =>
      mintActionV2({
        ...baseInput(),
        tsa: { tsa_url: "https://tsa.example" } as never,
      }),
    /tsaFetcher is required/,
  );
});

test("M33: signature is non-empty after signing", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(typeof env.sig, "string");
  assert.ok(env.sig.length > 0);
});

test("M34: anchor proof is preserved on the envelope", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(env.anchor.log, "https://verify.dekimu.com/action/v1");
});

test("M35: iat and iat_ms are consistent", async () => {
  const env = await mintActionV2(baseInput());
  assert.equal(Date.parse(env.iat), env.iat_ms);
});
