/**
 * Tests for ARR v=2 dispatch policy field enforcement (Phase C Task 14).
 *
 * ARR single-target kinds (ar.erasure.v1, ar.expiry.v1, ar.hold.v1,
 * ar.anonymization.v1, ar.archive.v1) are POLICY_BOUND. ar.batch.v1 is
 * exempted at the envelope level (per-item policy lives inside body).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope, FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "../src/index.ts";
import v2Fixture from "./fixtures/v2-arr-erasure.ts";

async function buildArrWithPolicy(
  claim_type: Envelope["claim_type"],
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
    id: "01HXX0000000000000000ARRPOL1",
    claim_type,
    iss: "did:web:processor.example",
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
    body: { target_kind: "subject", trigger: "subject_request" },
    ...overrides,
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

test("ARR v=2 erasure: missing all policy_* rejects with policy_fields_required:policy_uri", async () => {
  const { envelope, publicKey } = await buildArrWithPolicy("ar.erasure.v1", {});
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "policy_fields_required:policy_uri");
});

test("ARR v=2 erasure: valid policy_* passes and surfaces fields on result", async () => {
  const { envelope, publicKey } = v2Fixture;
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  }) as FamilyVerifyResult;
  assert.equal(result.signature_valid, true);
  assert.equal(result.policy_uri, "https://processor.example/policy");
  assert.equal(result.policy_hash, "sha256:" + "b".repeat(64));
  assert.equal(result.policy_version, "1.0.0");
  assert.equal(result.policy_fetched_match, "not_attempted");
});

test("ARR v=2 batch (ar.batch.v1): null envelope policy_* is allowed (per-item lives in body)", async () => {
  // Note: ar.batch.v1 is in the ARR claim_type allowlist; envelope policy
  // matrix exempts it from POLICY_BOUND.
  const { envelope, publicKey } = await buildArrWithPolicy("ar.batch.v1", {});
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  }) as FamilyVerifyResult;
  assert.equal(result.signature_valid, true);
  assert.equal(result.policy_uri, null);
  assert.equal(result.policy_hash, null);
  assert.equal(result.policy_version, null);
});
