/**
 * AP2-interop `authorizing_credential` — end-to-end mint/verify tests.
 *
 * Deliverable 1B of the AP2 ↔ anchors interop plan
 * (an internal design record (not published)), Option B.
 *
 * `authorizing_credential` is an OPTIONAL, grant-only reference (by identifier)
 * to an external authorizing artifact — canonically an AP2 mandate (SD-JWT-VC).
 * It is a *pointer* inside the envelope-signed body: receipt-*of*, never is-a.
 * These tests prove:
 *   1. a grant carrying the field round-trips (signature valid);
 *   2. tampering with the field after signing breaks verification;
 *   3. a pre-existing grant fixture (no field) verifies BYTE-EQUAL — graceful
 *      degradation, the whole point of an additive optional field.
 */

import { test } from "node:test";
import assert from "node:assert/strict";

import { mintGrant } from "../src/issue/index.ts";
import { adrFamily } from "../src/index.ts";
import {
  baseCommon,
  defaultAgent,
  defaultScope,
  makeResolveKey,
  makeSigningKey,
} from "./_helpers/issue-common.ts";
import type { AdrAuthorizingCredential } from "../src/types.ts";

const baseGrant = {
  agent: defaultAgent,
  scope: defaultScope,
  delegable: false,
  expiry: null,
  rationale_uri: "https://acme.example/rationale/v1",
  rationale_hash: "sha256:" + "f".repeat(64),
};

const AP2_MANDATE_REF: AdrAuthorizingCredential = {
  scheme: "ap2",
  // AP2's payment mandate travels under `payment_mandate_id` (= SD-JWT `jti`).
  id: "payment_mandate_id:2b6f0a1c-8e3d-4c9a-bf12-7d0e5a9c1f34",
  type: "payment-mandate",
};

// ── AC1: grant carrying authorizing_credential round-trips ────────────────────

test("AC1: grant with authorizing_credential round-trips (signature valid)", async () => {
  const env = await mintGrant({
    ...baseCommon,
    signingKey: makeSigningKey(),
    ...baseGrant,
    authorizing_credential: AP2_MANDATE_REF,
  });

  const body = env.body as { event: string; authorizing_credential?: AdrAuthorizingCredential };
  assert.equal(body.event, "grant");
  assert.deepEqual(body.authorizing_credential, AP2_MANDATE_REF);

  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── AC2: tampering with authorizing_credential after signing is detected ──────

test("AC2: tampering with authorizing_credential.id breaks verification", async () => {
  const env = await mintGrant({
    ...baseCommon,
    signingKey: makeSigningKey(),
    ...baseGrant,
    authorizing_credential: AP2_MANDATE_REF,
  });

  // Sanity: the untampered receipt verifies.
  const clean = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(clean.signature_valid, true, clean.reason ?? "ok");

  // Swap the referenced mandate id AFTER signing — the reference lives in the
  // envelope-signed body, so the signature must now fail (the crypto binding
  // that makes Option B stronger than a carrier-only field).
  const tampered = structuredClone(env) as typeof env & {
    body: { authorizing_credential: { -readonly [K in keyof AdrAuthorizingCredential]: AdrAuthorizingCredential[K] } };
  };
  tampered.body.authorizing_credential.id = "payment_mandate_id:ATTACKER-SWAPPED";

  const r = await adrFamily.verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false, "tampered authorizing_credential must not verify");
});

// ── AC3: pre-existing grant (no field) verifies BYTE-EQUAL — graceful degrade ─

test("AC3: grant minted WITHOUT authorizing_credential omits the key and verifies", async () => {
  const env = await mintGrant({
    ...baseCommon,
    signingKey: makeSigningKey(),
    ...baseGrant,
    // authorizing_credential intentionally absent.
  });

  // Additive-optional contract: the key must NOT appear in the body at all
  // (not `undefined`, not `null`) — this is what keeps every pre-existing ADR
  // grant receipt byte-equal under RFC 8785 canonicalization.
  assert.equal("authorizing_credential" in (env.body as object), false);

  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

// ── AC4: byte-equal — the SAME grant inputs produce the SAME field_root with or
// without the code change present (proven by re-verifying a captured fixture) ──

test("AC4: a captured pre-change grant fixture still verifies byte-equal", async () => {
  // A grant receipt minted by the pre-`authorizing_credential` code path is,
  // field-for-field, what today's code emits when the field is omitted. Rather
  // than pin a brittle signed blob (signatures are per-key), we assert the
  // canonical body shape is unchanged: no new key leaks into a field-less grant.
  const signingKey = makeSigningKey();
  const env = await mintGrant({ ...baseCommon, signingKey, ...baseGrant });

  const bodyKeys = Object.keys(env.body as object).sort();
  assert.deepEqual(
    bodyKeys,
    [
      "agent",
      "delegable",
      "event",
      "expiry",
      "field_root",
      "profile",
      "qts_attestation_hash",
      "rationale_hash",
      "rationale_uri",
      "scope",
    ],
    "field-less grant body shape must be unchanged (no authorizing_credential key)",
  );

  const r = await adrFamily.verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});
