/**
 * Tests for verifyReceipt() v=2 dispatch + v=1 legacy path.
 *
 * Phase A Task 5 — @dekimuhq/acr-verifier 0.2.0
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope, FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { canonicalize, base64UrlEncode as acrBase64Encode } from "../src/canonicalize.ts";
import type { ACRReceipt } from "../src/types.ts";
import { verifyReceipt } from "../src/index.ts";
import v2Fixture from "./fixtures/v2-acr-consent.ts";

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Build a signed v=1 ACR receipt (mirrors verify.test.ts signedReceipt()). */
function buildV1Receipt(): { receipt: ACRReceipt } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const skRaw = (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32);
  const pkRaw = (publicKey.export({ format: "der", type: "spki" }) as Buffer).subarray(-32);
  const pkB64 = acrBase64Encode(new Uint8Array(pkRaw));

  const base: Omit<ACRReceipt, "sig"> & { sig: null } = {
    kind: "ar.consent.v1",
    profile: "gdpr.art7",
    iss: "did:web:bank.example",
    iss_key: `ed25519:${pkB64}`,
    sub_commit: "sha256:" + "a".repeat(64),
    purposes: ["sha256:" + "b".repeat(64)],
    lawful_basis: "6(1)(a)",
    policy_hash: "sha256:" + "c".repeat(64),
    granted_at: "2026-05-15T10:00:00Z",
    prev: null,
    field_root: "sha256:" + "d".repeat(64),
    anchor: null,
    sig: null,
    countersig: null,
    qts_attestation_hash: null,
  };

  const bytes = new TextEncoder().encode(canonicalize(base));
  const skPkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(skRaw),
  ]);
  const skKey = crypto.createPrivateKey({ key: skPkcs8, format: "der", type: "pkcs8" });
  const sig = crypto.sign(null, bytes, skKey);
  const sigB64 = acrBase64Encode(new Uint8Array(sig));

  const receipt: ACRReceipt = { ...base, sig: `ed25519:${sigB64}` };
  return { receipt };
}

/** Build a signed v=2 envelope with a given claim_type and keypair. */
async function buildV2Envelope(
  claimType: string,
  kp?: { privateKey: crypto.KeyObject; publicKey: crypto.KeyObject },
): Promise<{ envelope: Envelope; publicKeyDer: Uint8Array }> {
  const { privateKey, publicKey } = kp ?? crypto.generateKeyPairSync("ed25519");
  const pkDer = (publicKey.export({ format: "der", type: "spki" }) as Buffer);
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000TESTENV",
    claim_type: claimType as Envelope["claim_type"],
    iss: "did:web:test.example",
    iss_key: issKey,
    subject: "sha256:" + "e".repeat(64),
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
    body: { test: true },
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKeyDer: new Uint8Array(pkDer) };
}

// ── Test 1: v=1 ACR consent receipt verifies via legacy path ─────────────────

test("verifyReceipt: v=1 consent receipt dispatches to legacy verifier", async () => {
  const { receipt } = buildV1Receipt();
  const result = await verifyReceipt(receipt);
  assert.equal(result.envelope_version, 1);
  assert.equal(result.signature_valid, true);
});

// ── Test 2: v=2 envelope dispatches to shared envelope verifier ──────────────

test("verifyReceipt: v=2 envelope dispatches to envelope verifier", async () => {
  const { envelope, publicKey } = v2Fixture;
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  }) as FamilyVerifyResult;
  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, true);
  assert.equal(result.claim_type, "ar.consent.v1");
});

// ── Test 3: Unknown v rejects with unsupported_envelope_version ──────────────

test("verifyReceipt: v=99 returns unsupported_envelope_version", async () => {
  const result = await verifyReceipt({ v: 99 } as never);
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "unsupported_envelope_version");
});

// ── Test 4: Non-object input rejects with schema_invalid ─────────────────────

test("verifyReceipt: non-object input returns schema_invalid", async () => {
  const result = await verifyReceipt("not an object" as never);
  assert.equal(result.envelope_version, "unknown");
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "schema_invalid");
});

// ── Test 5: v=2 wrong-protocol claim_type returns wrong_protocol ─────────────

test("verifyReceipt: v=2 with ar.erasure.v1 (ARR domain) returns wrong_protocol", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = (publicKey.export({ format: "der", type: "spki" }) as Buffer);
  const { envelope, publicKeyDer } = await buildV2Envelope("ar.erasure.v1", { privateKey, publicKey });
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKeyDer,
  }) as FamilyVerifyResult;
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "wrong_protocol");
  assert.equal(result.claim_type, "ar.erasure.v1");
});

// ── Test 6: v=2 with stray top-level field returns unknown_field:<name> ──────

test("verifyReceipt: v=2 with stray field returns unknown_field reason", async () => {
  const { envelope, publicKey } = v2Fixture;
  const stray = { ...envelope, foo: "bar" };
  const result = await verifyReceipt(stray as never, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.ok(result.reason?.startsWith("unknown_field:"), `expected reason to start with 'unknown_field:' but got: ${result.reason}`);
});

// ── Test 7: v=2 without resolveKey returns no_key_resolver ───────────────────

test("verifyReceipt: v=2 without resolveKey returns no_key_resolver", async () => {
  const { envelope } = v2Fixture;
  const result = await verifyReceipt(envelope) as FamilyVerifyResult;
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "no_key_resolver");
  assert.equal(result.claim_type, "ar.consent.v1");
});

// ── Test 8: v=2 with tampered body rejects signature ─────────────────────────

test("verifyReceipt: v=2 with tampered body rejects", async () => {
  const { envelope, publicKey } = v2Fixture;
  const tampered = { ...envelope, body: { tampered: true } };
  const result = await verifyReceipt(tampered as never, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, false);
  // reason is NOT asserted for tampered-sig case per spec
});
