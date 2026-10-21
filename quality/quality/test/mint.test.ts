/**
 * Tests for mintQualityV1 — the AQR v=2 issuer-kit. Verify-before-sign,
 * subject null, ar.quality.v1. Mirrors the AActR mint contract.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintQualityV1 } from "../src/issue/mint-v1.ts";
import { verifyQualityBody } from "../src/verify-single.ts";
import { baseOutputInput, baseReleaseInput, H } from "./_helpers/fixtures.ts";

test("M1: mint output → v=2 envelope", async () => {
  const env = await mintQualityV1(baseOutputInput());
  assert.equal(env.v, 2);
});

test("M2: mint output → claim_type ar.quality.v1", async () => {
  const env = await mintQualityV1(baseOutputInput());
  assert.equal(env.claim_type, "ar.quality.v1");
});

test("M3: mint output → subject is null", async () => {
  const env = await mintQualityV1(baseOutputInput());
  assert.equal(env.subject, null);
});

test("M4: mint output → sig non-empty", async () => {
  const env = await mintQualityV1(baseOutputInput());
  assert.equal(typeof env.sig, "string");
  assert.ok(env.sig.length > 0);
});

test("M5: mint output → body verifies via verifyQualityBody", async () => {
  const env = await mintQualityV1(baseOutputInput());
  const r = verifyQualityBody(env.body);
  assert.equal(r.valid, true, r.errors.join(","));
});

test("M6: mint output → body carries field_root + profile", async () => {
  const env = await mintQualityV1(baseOutputInput());
  const body = env.body as Record<string, unknown>;
  assert.equal(body.profile, "quality.output");
  assert.equal(typeof body.field_root, "string");
});

test("M7: mint rejects malformed output_commit", async () => {
  await assert.rejects(
    () => mintQualityV1({ ...baseOutputInput(), output_commit: "not-a-commit" }),
    /invalid body/,
  );
});

test("M8: mint rejects missing output_commit on output profile", async () => {
  const input = baseOutputInput();
  delete (input as { output_commit?: string }).output_commit;
  await assert.rejects(() => mintQualityV1(input), /invalid body/);
});

test("M9: mint release round-trips", async () => {
  const env = await mintQualityV1(baseReleaseInput());
  assert.equal(env.claim_type, "ar.quality.v1");
  assert.equal(env.subject, null);
  const body = env.body as Record<string, unknown>;
  assert.equal(body.profile, "quality.release");
  assert.equal(body.gate, "blocking");
  const r = verifyQualityBody(env.body);
  assert.equal(r.valid, true, r.errors.join(","));
});

test("M10: mint with credential_id + caveats_consumed round-trips", async () => {
  const env = await mintQualityV1({
    ...baseOutputInput(),
    credential_id: "cred-abc123",
    caveats_consumed: {
      data_scope: "tenant:acme",
      spend_step: 1,
      capability: "operator.evaluate",
    },
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.credential_id, "cred-abc123");
  assert.deepEqual(body.caveats_consumed, {
    data_scope: "tenant:acme",
    spend_step: 1,
    capability: "operator.evaluate",
  });
  const r = verifyQualityBody(env.body);
  assert.equal(r.valid, true, r.errors.join(","));
});

test("M11: mint rejects empty issuer", async () => {
  await assert.rejects(
    () => mintQualityV1({ ...baseOutputInput(), issuer: "" }),
    /issuer required/,
  );
});

test("M12: mint rejects non-32-byte signing key", async () => {
  const input = baseOutputInput();
  await assert.rejects(
    () =>
      mintQualityV1({
        ...input,
        signingKey: { kid: "k", privateKey: new Uint8Array(16) },
      }),
    /must be 32 bytes/,
  );
});

test("M13: mint rejects tsa config without tsaFetcher", async () => {
  await assert.rejects(
    () =>
      mintQualityV1({
        ...baseOutputInput(),
        tsa: { url: "https://tsa.example", hashAlg: "sha256" } as never,
      }),
    /tsaFetcher required/,
  );
});

test("M14: mint output → samples_commit bound when provided", async () => {
  const env = await mintQualityV1({ ...baseOutputInput(), samples_commit: H("f") });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.samples_commit, H("f"));
});
