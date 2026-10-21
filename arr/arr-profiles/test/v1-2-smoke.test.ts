/**
 * v1.2 envelope smoke test for arr-profiles.
 *
 * Confirms the v1.2 envelope additions (iat_ms, kind, cause, predicate)
 * roundtrip cleanly through verify on an ARR single-target envelope
 * (ar.erasure.v1) without disturbing existing status-list / TSA / policy
 * checks. ARR profile predicate use is less central than ACR's, so the
 * scope here is a smoke test — full predicate fixtures live alongside ACR.
 *
 * Spec §7 last paragraph: status-list revocation must NOT short-circuit
 * predicate evaluation. This test exercises the no-status-list path only;
 * status-list integration tests live in arr-verifier/test/status/.
 *
 * Phase E4 — @dekimuhq/arr-profiles v1.2 smoke.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope, JsonLogicAst, FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "@dekimuhq/arr";

interface SignedFixture {
  envelope: Envelope;
  publicKey: Uint8Array;
}

async function buildErasure(
  overrides: Partial<Envelope> = {},
): Promise<SignedFixture> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const iat = "2026-05-17T00:00:00Z";
  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ARRPROF",
    iat,
    claim_type: "ar.erasure.v1",
    iss: "did:web:processor.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    exp: null,
    prev: null,
    // Single-target ARR kinds are POLICY_BOUND.
    policy_uri: "https://example.test/retention",
    policy_hash: "sha256:" + "c".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: { profile: "gdpr.art17" },
    ...overrides,
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

test("arr-profiles v1.2 smoke: iat_ms + kind + cause + satisfied predicate roundtrip", async () => {
  const iat = "2026-05-17T00:00:00Z";
  const predicate: JsonLogicAst = { "===": [1, 1] } as unknown as JsonLogicAst;
  const { envelope, publicKey } = await buildErasure({
    iat_ms: Date.parse(iat),
    kind: "decision",
    cause: "erasure_request",
    predicate,
  });

  // The v1.2 fields are part of the signed payload — they survive the
  // sign/verify roundtrip with byte-equal canonicalisation.
  assert.equal(envelope.iat_ms, Date.parse(iat));
  assert.equal(envelope.kind, "decision");
  assert.equal(envelope.cause, "erasure_request");
  assert.deepEqual(envelope.predicate, { "===": [1, 1] });

  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  }) as FamilyVerifyResult;
  assert.equal(result.signature_valid, true, `unexpected reason: ${result.reason}`);
  assert.equal(result.claim_type, "ar.erasure.v1");
  // Status list was not configured → reconciler is "not_attempted" (advisory).
  assert.equal(result.status_state, "not_attempted");
});

test("arr-profiles v1.2 smoke: v1.1-style envelope (no v1.2 fields) verifies", async () => {
  const { envelope, publicKey } = await buildErasure({});
  assert.equal(envelope.iat_ms, undefined);
  assert.equal(envelope.predicate, undefined);
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, true, `unexpected reason: ${result.reason}`);
});
