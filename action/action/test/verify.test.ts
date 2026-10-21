/**
 * Tests for top-level verifyReceipt (envelope dispatch + end-to-end verify).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintActionV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import { baseInput, makeResolveKey } from "./_helpers/fixtures.ts";

test("V1: non-object input → schema_invalid", async () => {
  const r = await verifyReceipt("not-an-object");
  assert.equal(r.envelope_version, "unknown");
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "schema_invalid");
});

test("V2: null input → schema_invalid", async () => {
  const r = await verifyReceipt(null);
  assert.equal(r.envelope_version, "unknown");
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "schema_invalid");
});

test("V3: v=1 input → unsupported_envelope_version", async () => {
  const r = await verifyReceipt({ v: 1, claim_type: "ar.action.v1" });
  assert.equal(r.envelope_version, "unknown");
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "unsupported_envelope_version");
});

test("V4: missing v field → unsupported_envelope_version", async () => {
  const r = await verifyReceipt({ claim_type: "ar.action.v1" });
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "unsupported_envelope_version");
});

test("V5: v=2 with fake sig → signature_valid false, envelope_version 2", async () => {
  const env = await mintActionV2(baseInput());
  const tampered = { ...env, sig: "ed25519:" + "a".repeat(86) };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.envelope_version, 2);
  assert.equal(r.signature_valid, false);
});

test("V6: mint → verify round-trips valid", async () => {
  const env = await mintActionV2(baseInput());
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
  assert.equal(r.envelope_version, 2);
});

test("V7: tampering with verb breaks the signature", async () => {
  const env = await mintActionV2(baseInput());
  const tampered = { ...env, body: { ...(env.body as object), verb: "evil.verb" } };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});

test("V8: tampering with outcome breaks the signature", async () => {
  const env = await mintActionV2(baseInput());
  const tampered = {
    ...env,
    body: { ...(env.body as object), outcome: "failed-gave-up" },
  };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});

test("V9: setting a non-null subject breaks the signature", async () => {
  const env = await mintActionV2(baseInput());
  const tampered = { ...env, subject: "sha256:" + "b".repeat(64) };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});

test("V10: failed-gave-up receipt verifies", async () => {
  const env = await mintActionV2({ ...baseInput(), outcome: "failed-gave-up" });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("V11: clean round-trip surfaces claim_type ar.action.v1", async () => {
  const env = await mintActionV2(baseInput());
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
  assert.equal(r.claim_type, "ar.action.v1");
});

test("V12: tampering with a target commit breaks the signature", async () => {
  const env = await mintActionV2(baseInput());
  const tampered = {
    ...env,
    body: { ...(env.body as object), decision_commit: "sha256:" + "9".repeat(64) },
  };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});
