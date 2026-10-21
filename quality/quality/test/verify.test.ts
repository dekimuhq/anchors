/**
 * Tests for top-level verifyReceipt (envelope dispatch + end-to-end verify).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintQualityV1 } from "../src/issue/mint-v1.ts";
import { verifyReceipt } from "../src/index.ts";
import { baseOutputInput, baseReleaseInput, makeResolveKey } from "./_helpers/fixtures.ts";

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
  const r = await verifyReceipt({ v: 1, claim_type: "ar.quality.v1" });
  assert.equal(r.envelope_version, "unknown");
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "unsupported_envelope_version");
});

test("VR4: mint output → verify round-trips valid", async () => {
  const env = await mintQualityV1(baseOutputInput());
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
  assert.equal(r.envelope_version, 2);
  assert.equal(r.claim_type, "ar.quality.v1");
});

test("VR5: mint release → verify round-trips valid", async () => {
  const env = await mintQualityV1(baseReleaseInput());
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("VR6: tampering with body.suite_id breaks the signature", async () => {
  const env = await mintQualityV1(baseOutputInput());
  const tampered = { ...env, body: { ...(env.body as object), suite_id: "evil.suite" } };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.envelope_version, 2);
  assert.equal(r.signature_valid, false);
});

test("VR7: setting a non-null subject breaks the signature", async () => {
  const env = await mintQualityV1(baseOutputInput());
  const tampered = { ...env, subject: "sha256:" + "b".repeat(64) };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});

test("VR8: policy-free mint (spec default, POLICY_OPTIONAL) round-trips valid", async () => {
  // AQR is POLICY_OPTIONAL — a receipt with no policy_* must mint and verify.
  const { policy_uri, policy_hash, policy_version, ...policyFree } = baseOutputInput();
  void policy_uri;
  void policy_hash;
  void policy_version;
  const env = await mintQualityV1(policyFree);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
  assert.equal(r.envelope_version, 2);
  assert.equal(r.claim_type, "ar.quality.v1");
});

test("VR9: verify with no resolver returns signature_valid:false cleanly (no throw)", async () => {
  const env = await mintQualityV1(baseOutputInput());
  const r = await verifyReceipt(env);
  assert.equal(r.envelope_version, 2);
  assert.equal(r.signature_valid, false);
});
