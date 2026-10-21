/**
 * Tests for the per-event-type convenience wrappers in mint-single.ts.
 * Each wrapper produces a receipt the verifier accepts with the correct
 * `event_type` discriminator in the body.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintConformity, mintTransparency } from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import {
  baseConformityInput,
  baseTransparencyInput,
  makeResolveKey,
  makeSigningKey,
} from "./_helpers/issue-fixtures.ts";

// ── S1: mintConformity produces conformity receipt ────────────────────────────

test("S1: mintConformity produces conformity receipt", async () => {
  const env = await mintConformity({
    ...baseConformityInput,
    signingKey: makeSigningKey(),
  });
  assert.equal((env.body as { event_type: string }).event_type, "conformity");
  assert.equal(env.subject, null, "conformity subject must be null");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S2: mintTransparency produces transparency receipt ────────────────────────

test("S2: mintTransparency produces transparency receipt", async () => {
  const env = await mintTransparency({
    ...baseTransparencyInput,
    signingKey: makeSigningKey(),
  });
  assert.equal((env.body as { event_type: string }).event_type, "transparency");
  assert.equal(env.subject, baseTransparencyInput.subject);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});
