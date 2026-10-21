/**
 * Tests for top-level verifyReceipt (envelope dispatch + end-to-end verify).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintTraceV1 } from "../src/issue/mint-v1.ts";
import { verifyReceipt } from "../src/index.ts";
import { goodTraceInput, makeResolveKey } from "./_helpers/fixtures.ts";

test("VR1: non-object input → schema_invalid", async () => {
  const r = await verifyReceipt("not-an-object");
  assert.equal(r.envelope_version, "unknown");
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "schema_invalid");
});

test("VR2: null input → schema_invalid", async () => {
  const r = await verifyReceipt(null);
  assert.equal(r.envelope_version, "unknown");
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "schema_invalid");
});

test("VR3: v=1 input → unsupported_envelope_version", async () => {
  const r = await verifyReceipt({ v: 1, claim_type: "ar.trace.v1" });
  assert.equal(r.envelope_version, "unknown");
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "unsupported_envelope_version");
});

test("VR4: mint → verify round-trips valid", async () => {
  const env = await mintTraceV1(goodTraceInput());
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, (r as { reason?: string }).reason ?? "ok");
  assert.equal(r.envelope_version, 2);
  assert.equal(r.claim_type, "ar.trace.v1");
});

test("VR5: tampering with body.outcome breaks the signature", async () => {
  const env = await mintTraceV1(goodTraceInput());
  const tampered = { ...env, body: { ...(env.body as object), outcome: "error" } };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.envelope_version, 2);
  assert.equal(r.signature_valid, false);
});

test("VR6: tampering with request_id_commit breaks the signature", async () => {
  const env = await mintTraceV1(goodTraceInput());
  const tampered = { ...env, body: { ...(env.body as object), request_id_commit: "sha256:" + "c".repeat(64) } };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});

test("VR7: tampering with trace_commit breaks the signature", async () => {
  const env = await mintTraceV1(goodTraceInput());
  const tampered = { ...env, body: { ...(env.body as object), trace_commit: "sha256:" + "d".repeat(64) } };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});

test("VR8: setting a non-null subject breaks the signature (must-be-null)", async () => {
  const env = await mintTraceV1(goodTraceInput());
  const tampered = { ...env, subject: "sha256:" + "e".repeat(64) };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});

test("VR9: verify with no resolver returns signature_valid:false cleanly (no throw)", async () => {
  const env = await mintTraceV1(goodTraceInput());
  const r = await verifyReceipt(env);
  assert.equal(r.envelope_version, 2);
  assert.equal(r.signature_valid, false);
});

test("VR10: policy-free mint round-trips valid (POLICY_OPTIONAL)", async () => {
  const { policy_uri, policy_hash, policy_version, ...policyFree } = goodTraceInput();
  void policy_uri; void policy_hash; void policy_version;
  const env = await mintTraceV1(policyFree);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, (r as { reason?: string }).reason ?? "ok");
});

test("VR11: mint with capability round-trips valid", async () => {
  const env = await mintTraceV1({ ...goodTraceInput(), capability: "operator.draft-reminder" });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true);
});

test("VR12: mint with error outcome + error_stage round-trips valid", async () => {
  const env = await mintTraceV1({
    ...goodTraceInput(),
    outcome: "error",
    error_stage: "execute",
    stages: [{ stage: "execute", ms: 5, status: "error" }],
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true);
});

test("VR13: mint with denied outcome round-trips valid", async () => {
  const env = await mintTraceV1({ ...goodTraceInput(), outcome: "denied" });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true);
});

test("VR14: mint with checkpoint outcome round-trips valid", async () => {
  const env = await mintTraceV1({ ...goodTraceInput(), outcome: "checkpoint" });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true);
});

test("VR15: mint with caveats_consumed round-trips valid", async () => {
  const env = await mintTraceV1({
    ...goodTraceInput(),
    credential_id: "cred-1",
    caveats_consumed: { data_scope: "messages", spend_step: 1, capability: "operator.draft-reminder" },
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true);
});

test("VR16: claim_type is ar.trace.v1", async () => {
  const env = await mintTraceV1(goodTraceInput());
  assert.equal(env.claim_type, "ar.trace.v1");
});

test("VR17: multi-stage trace mint round-trips valid", async () => {
  const env = await mintTraceV1({
    ...goodTraceInput(),
    stages: [
      { stage: "validate", ms: 3, status: "ok" },
      { stage: "plan", ms: 12, status: "ok" },
      { stage: "execute", ms: 27, status: "ok" },
    ],
    total_ms: 42,
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true);
});

test("VR18: skipped-status stage round-trips valid", async () => {
  const env = await mintTraceV1({
    ...goodTraceInput(),
    stages: [
      { stage: "oversight", ms: 0, status: "skipped" },
      { stage: "execute", ms: 10, status: "ok" },
    ],
    total_ms: 10,
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true);
});
