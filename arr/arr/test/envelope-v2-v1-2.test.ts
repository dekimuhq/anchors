/**
 * Tests for v1.2 envelope additions wired into arr-verifier verifyV2():
 * iat_ms consistency + predicate contract on ARR single-target kinds.
 * Predicate forbidden on ar.batch.v1 (spec §6 + L9) — surfaces
 * predicate_forbidden_on_claim_type.
 *
 * Phase E4 — @dekimuhq/arr v1.2 envelope-check wiring.
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

async function buildSingle(
  overrides: Partial<Envelope> = {},
): Promise<SignedFixture> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const iat = "2026-05-17T00:00:00Z";
  // Single-target ARR kinds are POLICY_BOUND — populate envelope policy_*.
  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ARRV12S",
    iat,
    claim_type: "ar.erasure.v1",
    iss: "did:web:processor.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    exp: null,
    prev: null,
    policy_uri: "https://example.test/retention-policy",
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

async function buildBatch(
  overrides: Partial<Envelope> = {},
): Promise<SignedFixture> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const iat = "2026-05-17T00:00:00Z";
  // ar.batch.v1 is exempted from POLICY_BOUND — policy_* stay null.
  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ARRV12B",
    iat,
    claim_type: "ar.batch.v1",
    iss: "did:web:processor.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
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
    body: { batch: true },
    ...overrides,
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

// ── iat_ms_mismatch on single-target ───────────────────────────────────────────

test("ARR verifyV2: iat_ms_mismatch surfaces on single-target envelope", async () => {
  const correct = Date.parse("2026-05-17T00:00:00Z");
  const { envelope, publicKey } = await buildSingle({ iat_ms: correct + 1000 });
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "iat_ms_mismatch");
});

// ── Predicate satisfied on single-target ──────────────────────────────────────

test("ARR verifyV2: satisfied predicate on ar.erasure.v1 verifies", async () => {
  const predicate: JsonLogicAst = { "===": [1, 1] } as unknown as JsonLogicAst;
  const { envelope, publicKey } = await buildSingle({
    iat_ms: Date.parse("2026-05-17T00:00:00Z"),
    predicate,
  });
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, true, `unexpected reason: ${result.reason}`);
});

// ── Predicate forbidden on ar.batch.v1 ────────────────────────────────────────

test("ARR verifyV2: predicate on ar.batch.v1 surfaces predicate_forbidden_on_claim_type", async () => {
  const predicate: JsonLogicAst = { "===": [1, 1] } as unknown as JsonLogicAst;
  const { envelope, publicKey } = await buildBatch({ predicate });
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "predicate_forbidden_on_claim_type");
});

// ── v1.1 compat: no iat_ms, no predicate ──────────────────────────────────────

test("ARR verifyV2: v1.1 single-target envelope (no v1.2 fields) verifies", async () => {
  const { envelope, publicKey } = await buildSingle({});
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, true, `unexpected reason: ${result.reason}`);
});
