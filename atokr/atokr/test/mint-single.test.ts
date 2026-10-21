/**
 * Tests for the four per-event-type convenience wrappers in mint-single.ts.
 * Each wrapper produces a receipt the verifier accepts and carries the
 * correct `event_type` discriminator in the body.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  mintTokenIssued,
  mintTokenRedeemed,
  mintTokenRevoked,
  mintTokenRotated,
} from "../src/issue/index.ts";
import { mintAtokrV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import { baseCommon, makeResolveKey, makeSigningKey, scope } from "./_helpers/common.ts";

// ── S1: mintTokenIssued round-trips ──────────────────────────────────────────

test("S1: mintTokenIssued round-trips", async () => {
  const env = await mintTokenIssued({
    ...baseCommon,
    signingKey: makeSigningKey(),
    token_id: "tok-s1",
    format_class: "email",
    scope,
  });
  assert.equal((env.body as { event_type: string }).event_type, "token.issued");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S2: mintTokenRedeemed round-trips ─────────────────────────────────────────

test("S2: mintTokenRedeemed round-trips", async () => {
  const env = await mintTokenRedeemed({
    ...baseCommon,
    signingKey: makeSigningKey(),
    token_id: "tok-s2",
    scope,
    prev: "01HISSUED000000000000000",
  });
  assert.equal((env.body as { event_type: string }).event_type, "token.redeemed");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S3: mintTokenRevoked round-trips ──────────────────────────────────────────

test("S3: mintTokenRevoked round-trips", async () => {
  const env = await mintTokenRevoked({
    ...baseCommon,
    signingKey: makeSigningKey(),
    token_id: "tok-s3",
    scope,
    prev: "01HISSUED000000000000000",
  });
  assert.equal((env.body as { event_type: string }).event_type, "token.revoked");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S4: mintTokenRotated sets correct rotation_of ─────────────────────────────

test("S4: mintTokenRotated sets correct rotation_of", async () => {
  const env = await mintTokenRotated({
    ...baseCommon,
    signingKey: makeSigningKey(),
    token_id: "tok-s4-new",
    format_class: "pan",
    scope,
    rotation_of: "01HISSUED000000000000000",
  });
  assert.equal((env.body as { event_type: string }).event_type, "token.rotated");
  assert.equal(
    (env.body as { rotation_of: string }).rotation_of,
    "01HISSUED000000000000000",
  );
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── S5: mintTokenIssued convenience produces same result as mintAtokrV2 ───────

test("S5: mintTokenIssued convenience matches mintAtokrV2 structure", async () => {
  const signingKey = makeSigningKey();

  const envConvenience = await mintTokenIssued({
    ...baseCommon,
    signingKey,
    token_id: "tok-s5",
    format_class: "iban",
    scope,
  });

  const envDirect = await mintAtokrV2({
    ...baseCommon,
    signingKey,
    event_type: "token.issued",
    token_id: "tok-s5",
    format_class: "iban",
    scope,
  });

  // Both should be valid with the same structure (ids differ but claim_type/body shape match).
  assert.equal(envConvenience.claim_type, envDirect.claim_type);
  assert.equal(
    (envConvenience.body as { event_type: string }).event_type,
    (envDirect.body as { event_type: string }).event_type,
  );
  assert.equal(
    (envConvenience.body as { token_id: string }).token_id,
    (envDirect.body as { token_id: string }).token_id,
  );
});
