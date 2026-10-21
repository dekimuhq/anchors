/**
 * Tests for v1.2 envelope additions wired into acr-verifier verifyV2():
 * iat_ms consistency + predicate contract (spec §6 matrix says ACR may
 * carry a predicate; consent receipts recommended).
 *
 * Phase E3 — @dekimuhq/acr-verifier v1.2 envelope-check wiring.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope, JsonLogicAst } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "../src/index.ts";

interface SignedFixture {
  envelope: Envelope;
  publicKey: Uint8Array;
}

async function buildEnvelope(
  overrides: Partial<Envelope> = {},
): Promise<SignedFixture> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const iat = "2026-05-17T00:00:00Z";
  // ACR claim types are POLICY_BOUND — envelope-level policy fields required.
  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ACRV12C",
    iat,
    claim_type: "ar.consent.v1",
    iss: "did:web:consent.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    exp: null,
    prev: null,
    policy_uri: "https://example.test/consent-policy",
    policy_hash: "sha256:" + "c".repeat(64),
    policy_version: "1.0.0",
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: { test: true },
    ...overrides,
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

// ── iat_ms_mismatch ──────────────────────────────────────────────────────────

test("ACR verifyV2 surfaces iat_ms_mismatch when iat_ms != Date.parse(iat)", async () => {
  const correct = Date.parse("2026-05-17T00:00:00Z");
  const { envelope, publicKey } = await buildEnvelope({
    iat_ms: correct + 1, // off by 1 ms
  });
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "iat_ms_mismatch");
});

// ── Predicate: satisfied → verifies cleanly ──────────────────────────────────

test("ACR verifyV2 accepts an envelope with a satisfied predicate", async () => {
  const predicate: JsonLogicAst = { "===": [1, 1] } as unknown as JsonLogicAst;
  const { envelope, publicKey } = await buildEnvelope({
    iat_ms: Date.parse("2026-05-17T00:00:00Z"),
    predicate,
  });
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, true, `unexpected reason: ${result.reason}`);
});

// ── Predicate: evaluation_false ──────────────────────────────────────────────

test("ACR verifyV2 surfaces predicate_evaluation_false when predicate evaluates to false", async () => {
  const predicate: JsonLogicAst = { "===": [1, 2] } as unknown as JsonLogicAst;
  const { envelope, publicKey } = await buildEnvelope({
    iat_ms: Date.parse("2026-05-17T00:00:00Z"),
    predicate,
  });
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "predicate_evaluation_false");
});

// ── v1.1 compat: no iat_ms, no predicate ─────────────────────────────────────

test("ACR verifyV2 accepts a v1.1 envelope (no iat_ms, no predicate)", async () => {
  const { envelope, publicKey } = await buildEnvelope({});
  assert.equal(envelope.iat_ms, undefined);
  assert.equal(envelope.predicate, undefined);
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, true, `unexpected reason: ${result.reason}`);
});
