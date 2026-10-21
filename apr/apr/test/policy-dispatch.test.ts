/**
 * Tests for APR v=2 dispatch policy field enforcement (Phase C Task 14).
 *
 * APR (ar.provenance.v1) is POLICY_FORBIDDEN — envelope-level policy_* MUST
 * all be null/absent. Any set field rejects with policy_fields_forbidden_for_apr.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope, FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "../src/index.ts";
import v2Fixture from "./fixtures/v2-apr-provenance.ts";

/**
 * Build a signed v=2 APR provenance envelope with policy_* overrides.
 * Default fixture has all-null policy fields (APR-compliant).
 */
async function buildAprWithPolicy(
  overrides: Partial<
    Pick<Envelope, "policy_uri" | "policy_hash" | "policy_version">
  >,
): Promise<{ envelope: Envelope; publicKey: Uint8Array }> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000APRPOL1",
    claim_type: "ar.provenance.v1",
    iss: "did:web:commander.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: { artifact_type: "commander.run.output" },
    ...overrides,
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

test("APR v=2: policy_uri set rejects with policy_fields_forbidden_for_apr", async () => {
  const { envelope, publicKey } = await buildAprWithPolicy({
    policy_uri: "https://commander.example/policy",
  });
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "policy_fields_forbidden_for_apr");
});

test("APR v=2: all-null policy_* passes and surfaces null on result", async () => {
  const { envelope, publicKey } = v2Fixture;
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  }) as FamilyVerifyResult;
  assert.equal(result.signature_valid, true);
  assert.equal(result.policy_uri, null);
  assert.equal(result.policy_hash, null);
  assert.equal(result.policy_version, null);
  assert.equal(result.policy_fetched_match, "not_attempted");
});
