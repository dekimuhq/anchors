/**
 * Tests for ACR v=2 dispatch policy field enforcement (Phase C Task 14).
 *
 * ACR claim types are POLICY_BOUND — envelope-level policy_uri + policy_hash
 * + policy_version are required; missing any rejects with
 * policy_fields_required:<field>.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { createHash } from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope, FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "../src/index.ts";
import v2Fixture from "./fixtures/v2-acr-consent.ts";

/** Build a signed v=2 ACR consent envelope with policy_* overrides. */
async function buildAcrWithPolicy(
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
    id: "01HXX0000000000000000ACRPOL1",
    claim_type: "ar.consent.v1",
    iss: "did:web:bank.example",
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
    body: { lawful_basis: "6(1)(a)", purposes: ["test"] },
    ...overrides,
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

test("ACR v=2 consent: missing all policy_* rejects with policy_fields_required:policy_uri", async () => {
  const { envelope, publicKey } = await buildAcrWithPolicy({});
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "policy_fields_required:policy_uri");
});

test("ACR v=2 consent: valid policy_* passes and surfaces fields on result", async () => {
  const { envelope, publicKey } = v2Fixture;
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  }) as FamilyVerifyResult;
  assert.equal(result.signature_valid, true);
  assert.equal(result.policy_uri, "https://bank.example/policy");
  assert.equal(result.policy_hash, "sha256:" + "b".repeat(64));
  assert.equal(result.policy_version, "1.0.0");
  assert.equal(result.policy_fetched_match, "not_attempted");
});

test("ACR v=2 consent: fetchPolicy: true + matching fetch → policy_fetched_match: true", async () => {
  const body = "policy document body — bank.example v1";
  const policyHash =
    "sha256:" + createHash("sha256").update(body).digest("hex");

  const { envelope, publicKey } = await buildAcrWithPolicy({
    policy_uri: "https://bank.example/policy/v1.md",
    policy_hash: policyHash,
    policy_version: "1.0.0",
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(body, { status: 200 })) as typeof fetch;
  try {
    const result = await verifyReceipt(envelope, {
      resolveKey: async () => publicKey,
      fetchPolicy: true,
    }) as FamilyVerifyResult;
    assert.equal(result.signature_valid, true);
    assert.equal(result.policy_fetched_match, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("ACR v=2 consent: fetchPolicy: true + hash mismatch → policy_fetched_match: false", async () => {
  const { envelope, publicKey } = await buildAcrWithPolicy({
    policy_uri: "https://bank.example/policy/v1.md",
    policy_hash: "sha256:" + "f".repeat(64),
    policy_version: "1.0.0",
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response("something else entirely", { status: 200 })) as typeof fetch;
  try {
    const result = await verifyReceipt(envelope, {
      resolveKey: async () => publicKey,
      fetchPolicy: true,
    }) as FamilyVerifyResult;
    assert.equal(result.signature_valid, true);
    assert.equal(result.policy_fetched_match, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
