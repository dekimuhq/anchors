/**
 * Tests for the three per-event-type convenience wrappers in mint-single.ts.
 * Each wrapper produces a receipt with the correct `event_type` discriminator.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  mintBinding,
  mintRepurpose,
  mintUnbinding,
} from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import {
  baseCommon,
  bindingFields,
  repurposeFields,
  unbindingFields,
  makeResolveKey,
  makeSigningKey,
} from "./_helpers/fixtures.ts";

const PREV = "01HBINDING00000000000000";

// ── S1: mintBinding round-trips ──────────────────────────────────────────────

test("S1: mintBinding produces binding event_type", async () => {
  const env = await mintBinding({
    ...baseCommon,
    signingKey: makeSigningKey(),
    ...bindingFields,
  });
  assert.equal((env.body as { event_type: string }).event_type, "binding");
  assert.equal(env.subject, null);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S2: mintRepurpose round-trips ─────────────────────────────────────────────

test("S2: mintRepurpose produces repurpose event_type", async () => {
  const env = await mintRepurpose({
    ...baseCommon,
    signingKey: makeSigningKey(),
    prev: PREV,
    ...repurposeFields,
  });
  assert.equal((env.body as { event_type: string }).event_type, "repurpose");
  assert.equal(env.subject, null);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S3: mintUnbinding round-trips ─────────────────────────────────────────────

test("S3: mintUnbinding produces unbinding event_type", async () => {
  const env = await mintUnbinding({
    ...baseCommon,
    signingKey: makeSigningKey(),
    prev: PREV,
    ...unbindingFields,
  });
  assert.equal((env.body as { event_type: string }).event_type, "unbinding");
  assert.equal(env.subject, null);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S4: mintBinding claim_type is ar.purpose.v1 ───────────────────────────────

test("S4: mintBinding claim_type is ar.purpose.v1", async () => {
  const env = await mintBinding({
    ...baseCommon,
    signingKey: makeSigningKey(),
    ...bindingFields,
  });
  assert.equal(env.claim_type, "ar.purpose.v1");
});

// ── S5: mintRepurpose + mintUnbinding both reject missing prev ────────────────

test("S5: mintRepurpose rejects missing prev", async () => {
  await assert.rejects(
    () =>
      mintRepurpose({
        ...baseCommon,
        signingKey: makeSigningKey(),
        ...repurposeFields,
      }),
    /chain continuation/,
  );
});
