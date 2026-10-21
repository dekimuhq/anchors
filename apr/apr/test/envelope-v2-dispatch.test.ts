/**
 * Tests for verifyReceipt() v=2 dispatch + v=1 legacy path.
 *
 * Phase A Task 6b — @dekimuhq/apr-verifier 0.1.1
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope, FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { base64UrlEncode as aprBase64Encode, canonicalize } from "../src/index.ts";
import type { APRClaim, ClaimKeyResolver } from "../src/index.ts";
import { verifyReceipt } from "../src/index.ts";
import v2Fixture from "./fixtures/v2-apr-provenance.ts";

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Build a signed v=1 APR claim + resolver (mirrors verify-claim.ts patterns). */
function buildV1Claim(): { claim: APRClaim; resolver: ClaimKeyResolver } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = (publicKey.export({ format: "der", type: "spki" }) as Buffer);
  const pkRaw = pkDer.subarray(-32);
  const pkB64 = aprBase64Encode(new Uint8Array(pkRaw));

  const kid = "test-kid-1";
  const issuer = "did:web:commander.example";

  const baseRaw = {
    v: 1 as const,
    id: "01HXX0000000000000000APRV1CL",
    kind: "ar.provenance.v1" as const,
    issuer,
    subject: "sha256:" + "f".repeat(64),
    iat: Math.floor(Date.now() / 1000),
    kid,
    body: {
      artifact: {
        type: "commander.run.output" as const,
        id: "artifact-001",
        hash: "sha256:" + "c".repeat(64),
        hashAlgorithm: "sha256" as const,
      },
      agent: { kind: "ai" as const, model: "claude-sonnet-4-6" },
      authorization: { principalId: "user-123" },
      startedAt: Math.floor(Date.now() / 1000) - 5,
      completedAt: Math.floor(Date.now() / 1000),
      disclosure: "public_full" as const,
    },
    sig: null as unknown as string,
  };

  // Canonicalize without sig, then sign.
  const { sig: _sig, ...unsigned } = baseRaw;
  const bytes = new TextEncoder().encode(canonicalize(unsigned));

  const skPkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    (privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32),
  ]);
  const skKey = crypto.createPrivateKey({ key: skPkcs8, format: "der", type: "pkcs8" });
  const sigBytes = crypto.sign(null, bytes, skKey);
  const sigB64 = aprBase64Encode(new Uint8Array(sigBytes));

  // APR v=1 sig field is raw base64url (no algorithm prefix), per apr-spec/v1.md §5.
  const claim: APRClaim = { ...baseRaw, sig: sigB64 } as unknown as APRClaim;

  const resolver: ClaimKeyResolver = (k) => {
    if (k !== kid) return undefined;
    return {
      kid,
      publicKey: new Uint8Array(pkRaw),
      issuer,
    };
  };

  return { claim, resolver };
}

/** Build a signed v=2 envelope with a given claim_type. */
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
    iss: "did:web:commander.example",
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

// ── Test 1: v=1 APR claim verifies via sig-only path ─────────────────────────

test("verifyReceipt: v=1 APR claim verifies via claim-sig-only path", async () => {
  const { claim, resolver } = buildV1Claim();
  const result = await verifyReceipt(claim, {
    v1Opts: { claimKeyResolver: resolver },
  });
  assert.equal(result.envelope_version, 1);
  assert.equal(result.signature_valid, true);
});

// ── Test 2: v=1 without claimKeyResolver returns v1_requires_claim_key_resolver

test("verifyReceipt: v=1 without v1Opts.claimKeyResolver returns v1_requires_claim_key_resolver", async () => {
  const { claim } = buildV1Claim();
  const result = await verifyReceipt(claim);
  assert.equal(result.envelope_version, 1);
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "v1_requires_claim_key_resolver");
});

// ── Test 3: v=2 APR provenance receipt dispatches correctly ──────────────────

test("verifyReceipt: v=2 provenance envelope dispatches to envelope verifier", async () => {
  const { envelope, publicKey } = v2Fixture;
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  }) as FamilyVerifyResult;
  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, true);
  assert.equal(result.claim_type, "ar.provenance.v1");
});

// ── Test 4: Unknown v rejects with unsupported_envelope_version ──────────────

test("verifyReceipt: v=99 returns unsupported_envelope_version", async () => {
  const result = await verifyReceipt({ v: 99 } as never);
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "unsupported_envelope_version");
});

// ── Test 5: Non-object input rejects with schema_invalid ─────────────────────

test("verifyReceipt: non-object input returns schema_invalid", async () => {
  const result = await verifyReceipt("not an object" as never);
  assert.equal(result.envelope_version, "unknown");
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "schema_invalid");
});

// ── Test 6: v=2 with ACR claim_type returns wrong_protocol ───────────────────

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

// ── Test 7: v=2 without resolveKey returns no_key_resolver ───────────────────

test("verifyReceipt: v=2 without resolveKey returns no_key_resolver", async () => {
  const { envelope } = v2Fixture;
  const result = await verifyReceipt(envelope) as FamilyVerifyResult;
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "no_key_resolver");
  assert.equal(result.claim_type, "ar.provenance.v1");
});

// ── Test 8: v=2 with stray top-level field returns unknown_field:<name> ───────

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

// ── Test 9: v=2 with tampered body rejects signature ─────────────────────────

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
