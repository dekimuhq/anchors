/**
 * Tests for verifyReceipt() v=2 dispatch + v=1 legacy path.
 *
 * Phase A Task 6 — @dekimuhq/arr 0.1.4
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope, FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { canonicalize } from "../src/index.ts";
import { base64UrlEncode as arrBase64Encode } from "../src/index.ts";
import type { ARRReceipt } from "../src/index.ts";
import { verifyReceipt } from "../src/index.ts";
import v2Fixture from "./fixtures/v2-arr-erasure.ts";

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Build a signed v=1 ARR erasure receipt (mirrors verify-single.test.ts patterns). */
function buildV1Receipt(): { receipt: ARRReceipt } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = (publicKey.export({ format: "der", type: "spki" }) as Buffer);
  const pkRaw = pkDer.subarray(-32);
  const pkB64 = arrBase64Encode(new Uint8Array(pkRaw));

  const base: ARRReceipt = {
    kind: "ar.erasure.v1",
    profile: "gdpr.art17",
    iss: "did:web:processor.example",
    iss_key: `ed25519:${pkB64}`,
    target_kind: "subject",
    target_commit: "sha256:" + "ab".repeat(32),
    salt_epoch: "2026Q2",
    policy_hash: "sha256:" + "cd".repeat(32),
    policy_uri: "https://processor.example/p/v1",
    policy_version: "1.0.0",
    trigger: "subject_request",
    trigger_receipt: "sha256:" + "ef".repeat(32),
    event_at: "2026-05-16T09:12:00Z",
    granted_at: "2026-05-16T09:14:00Z",
    effective_until: null,
    state_snapshot: {
      retention_status: "erased",
      current_policy_hash: "sha256:" + "cd".repeat(32),
      hold_active: false,
      hold_reason_commit: null,
      anonymized: false,
      archived: false,
    },
    prev: null,
    field_root: "sha256:" + "11".repeat(32),
    anchor: null,
    sig: null,
  };

  const bytes = new TextEncoder().encode(canonicalize({ ...base, sig: null, anchor: null }));
  const skPkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32),
  ]);
  const skKey = crypto.createPrivateKey({ key: skPkcs8, format: "der", type: "pkcs8" });
  const sig = crypto.sign(null, bytes, skKey);
  const sigB64 = arrBase64Encode(new Uint8Array(sig));

  const receipt: ARRReceipt = { ...base, sig: `ed25519:${sigB64}` };
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
    iss: "did:web:processor.example",
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

// ── Test 1: v=1 ARR receipt verifies via legacy path ─────────────────────────

test("verifyReceipt: v=1 erasure receipt dispatches to legacy verifier", async () => {
  const { receipt } = buildV1Receipt();
  const result = await verifyReceipt(receipt, {
    v1Opts: { anchorInclusionTime: "2026-05-16T09:15:00Z" },
  });
  assert.equal(result.envelope_version, 1);
  assert.equal(result.signature_valid, true);
});

// ── Test 2: v=2 ARR erasure receipt dispatches to envelope verifier ──────────

test("verifyReceipt: v=2 erasure envelope dispatches to envelope verifier", async () => {
  const { envelope, publicKey } = v2Fixture;
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  }) as FamilyVerifyResult;
  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, true);
  assert.equal(result.claim_type, "ar.erasure.v1");
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

// ── Test 5: v=2 with ACR claim_type returns wrong_protocol ───────────────────

test("verifyReceipt: v=2 with ar.consent.v1 (ACR domain) returns wrong_protocol", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = (publicKey.export({ format: "der", type: "spki" }) as Buffer);
  const { envelope, publicKeyDer } = await buildV2Envelope("ar.consent.v1", { privateKey, publicKey });
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKeyDer,
  }) as FamilyVerifyResult;
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "wrong_protocol");
  assert.equal(result.claim_type, "ar.consent.v1");
});

// ── Test 6: v=2 without resolveKey returns no_key_resolver ───────────────────

test("verifyReceipt: v=2 without resolveKey returns no_key_resolver", async () => {
  const { envelope } = v2Fixture;
  const result = await verifyReceipt(envelope) as FamilyVerifyResult;
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "no_key_resolver");
  assert.equal(result.claim_type, "ar.erasure.v1");
});

// ── Test 7: v=2 with stray top-level field returns unknown_field:<name> ───────

test("verifyReceipt: v=2 with stray field returns unknown_field reason", async () => {
  const { envelope, publicKey } = v2Fixture;
  const stray = { ...envelope, foo: "bar" };
  const result = await verifyReceipt(stray as never, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.ok(
    result.reason?.startsWith("unknown_field:"),
    `expected reason to start with 'unknown_field:' but got: ${result.reason}`,
  );
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

// ── Test 9: v=1 without anchorInclusionTime fails closed ─────────────────────

test("verifyReceipt: v=1 without v1Opts.anchorInclusionTime returns v1_requires_anchor_inclusion_time", async () => {
  const { receipt } = buildV1Receipt();
  const result = await verifyReceipt(receipt);
  assert.equal(result.envelope_version, 1);
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "v1_requires_anchor_inclusion_time");
});

// ── Test 10: v=2 sig_alg crypto-agility surfaces through the family (v1.3 R2) ─
// The family verifier delegates v=2 signature checks to the shared envelope
// pipeline (buildVerifyReceipt → verifyEnvelopeSignature). These two tests prove
// the v1.3 §L8 support gate and §L6 prefix↔alg binding reach a caller through
// arr's verifyReceipt — not just the envelope unit tests. Both run on any Node:
// neither path performs ml-dsa keygen (the gate/mismatch returns first).

test("verifyReceipt: v=2 with an unsupported sig_alg returns unsupported_sig_alg", async () => {
  const { envelope, publicKeyDer } = await buildV2Envelope("ar.erasure.v1");
  // slh-dsa-sha2-128s is a recognised-but-unregistered scheme (no verifier).
  const forward = { ...envelope, sig_alg: "slh-dsa-sha2-128s" };
  const result = await verifyReceipt(forward as never, {
    resolveKey: async () => publicKeyDer,
  }) as FamilyVerifyResult;
  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "unsupported_sig_alg:slh-dsa-sha2-128s");
});

test("verifyReceipt: v=2 with sig_alg not matching the iss_key prefix fails closed (§L6)", async () => {
  const { envelope, publicKeyDer } = await buildV2Envelope("ar.erasure.v1");
  // sig_alg claims ml-dsa-65 (a registered scheme) but iss_key is `ed25519:…`.
  // The prefix↔alg binding rejects this before any key bytes are interpreted —
  // an algorithm-substitution / agility-downgrade attempt.
  const mismatched = { ...envelope, sig_alg: "ml-dsa-65" };
  const result = await verifyReceipt(mismatched as never, {
    resolveKey: async () => publicKeyDer,
  }) as FamilyVerifyResult;
  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "signature_invalid");
});
