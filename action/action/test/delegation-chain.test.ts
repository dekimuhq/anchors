/**
 * AActR delegation chain-binding: optional `delegation_chain`
 * (spec §4.5 — additive, validator + mint round-trip). Records the delegation
 * path when the authorizing mandate is a chain (a sub-agent under an attenuated
 * sub-mandate), beyond the single root `credential_id`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyActionBody } from "../src/verify-single.ts";
import { mintActionV2 } from "../src/issue/mint-v2.ts";
import { verifyReceipt } from "../src/index.ts";
import { validBody, baseInput, makeResolveKey } from "./_helpers/fixtures.ts";

const CRED = "adr-grant-123";
const CAVEATS = { data_scope: "ws:acme", spend_step: 1, capability: "ropa.compile" };
const chain = (over: Record<string, unknown> = {}) => ({
  depth: 2,
  leaf_key: "bGVhZi1rZXk",
  root_credential_id: CRED,
  ...over,
});

// ── Validator (verifyActionBody) ──────────────────────────────────────────────

test("DC1: valid with a well-formed delegation_chain + matching credential_id + caveats_consumed", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: CRED,
    caveats_consumed: CAVEATS,
    delegation_chain: chain(),
  });
  assert.equal(r.valid, true);
});

test("DC2: rejects a delegation_chain without credential_id (orphan)", () => {
  const r = verifyActionBody({ ...validBody(), delegation_chain: chain() });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("delegation_chain.orphan"));
});

test("DC3: rejects root_credential_id that does not equal credential_id (root_mismatch)", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: CRED,
    delegation_chain: chain({ root_credential_id: "adr-grant-OTHER" }),
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("delegation_chain.root_mismatch"));
});

test("DC4: rejects depth < 1 (a present chain delegated at least once)", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: CRED,
    delegation_chain: chain({ depth: 0 }),
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("delegation_chain.invalid"));
});

test("DC5: rejects non-integer depth", () => {
  const r = verifyActionBody({
    ...validBody(),
    credential_id: CRED,
    delegation_chain: chain({ depth: 1.5 }),
  });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("delegation_chain.invalid"));
});

test("DC6: rejects missing leaf_key", () => {
  const bad = chain();
  delete (bad as Record<string, unknown>).leaf_key;
  const r = verifyActionBody({ ...validBody(), credential_id: CRED, delegation_chain: bad });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("delegation_chain.invalid"));
});

test("DC7: still valid without delegation_chain (root-only mandate, backward-compatible)", () => {
  const r = verifyActionBody({ ...validBody(), credential_id: CRED });
  assert.equal(r.valid, true);
});

test("DC10: rejects a delegation_chain with no caveats_consumed (no_caveats)", () => {
  const r = verifyActionBody({ ...validBody(), credential_id: CRED, delegation_chain: chain() });
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("delegation_chain.no_caveats"));
});

// ── Mint → verify round-trip (mintActionV2) ───────────────────────────────────

test("DC8: mint carries delegation_chain into the body and round-trips through signature verify", async () => {
  const env = await mintActionV2({
    ...baseInput(),
    credential_id: CRED,
    caveats_consumed: { data_scope: "ws:acme", spend_step: 1, capability: "ropa.compile" },
    delegation_chain: { depth: 2, leaf_key: "bGVhZi1rZXk", root_credential_id: CRED },
  });
  const body = env.body as Record<string, unknown>;
  assert.deepEqual(body.delegation_chain, {
    depth: 2,
    leaf_key: "bGVhZi1rZXk",
    root_credential_id: CRED,
  });
  assert.equal(verifyActionBody(body).valid, true);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("DC9: mint omits delegation_chain entirely when not provided (no undefined key)", async () => {
  const env = await mintActionV2(baseInput());
  const body = env.body as Record<string, unknown>;
  assert.ok(!("delegation_chain" in body), "delegation_chain key must be absent, not undefined");
});
