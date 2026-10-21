/**
 * v1.2 predicate fixture — spec §5.5 Example 1 (ACR consent).
 *
 * Predicate: processing permitted iff age ≥ 16 and purpose ∈ {analytics, fraud}.
 *
 * The fixture mints a v=2 consent envelope by hand (body bypasses the standard
 * AcrV2Body shape so we can host the plaintext `subject_age` + `purpose` paths
 * the predicate references — issuer-trusted body paths per spec §7 step 4),
 * signs it with signEnvelope, and runs it through @dekimuhq/acr-verifier's
 * verifyReceipt. This validates:
 *
 *   1. A satisfied predicate verifies cleanly (signature_valid: true).
 *   2. A mutated body that falsifies the predicate surfaces
 *      `predicate_evaluation_false`.
 *   3. A predicate using an operator outside the v1.2 allowlist surfaces
 *      `predicate_operator_not_allowed`.
 *
 * Phase E3 — @dekimuhq/acr-profiles v1.2 predicate fixture.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import {
  signEnvelope,
  base64UrlEncode,
} from "@dekimuhq/anchors-envelope";
import type { Envelope, JsonLogicAst, FamilyVerifyResult } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "@dekimuhq/acr";

// ── Spec §5.5 Example 1 predicate ─────────────────────────────────────────────
//
// {
//   "and": [
//     { ">=": [ { "var": "body.subject_age" }, 16 ] },
//     { "in": [ { "var": "body.purpose" }, [ "analytics", "fraud" ] ] }
//   ]
// }

const AGE_AND_PURPOSE_PREDICATE: JsonLogicAst = {
  and: [
    { ">=": [{ var: "body.subject_age" }, 16] },
    { in: [{ var: "body.purpose" }, ["analytics", "fraud"]] },
  ],
} as unknown as JsonLogicAst;

interface CustomBody {
  subject_age: number;
  purpose: string;
}

interface SignedFixture {
  envelope: Envelope;
  publicKey: Uint8Array;
}

/**
 * Build a v=2 ACR consent envelope with a custom plaintext body and predicate.
 *
 * Bypasses `mintAcrV2` so the body can carry `subject_age` + `purpose` directly
 * (issuer-trusted body paths per spec §7 step 4). The envelope-level policy_*
 * trio is populated because ACR claim types are POLICY_BOUND (Phase C Task 14).
 */
async function buildEnvelope(
  body: CustomBody,
  predicate: JsonLogicAst | null,
): Promise<SignedFixture> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const iat = "2026-05-17T00:00:00Z";
  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ACRPRED",
    iat,
    iat_ms: Date.parse(iat),
    claim_type: "ar.consent.v1",
    iss: "did:web:consent.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    exp: null,
    prev: null,
    policy_uri: "https://example.test/consent-policy",
    policy_hash: "sha256:" + "c".repeat(64),
    policy_version: "1.0.0",
    kind: "decision",
    cause: "manual",
    predicate,
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: body as unknown,
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

// ── Positive: satisfied predicate verifies cleanly ───────────────────────────

test("ACR v1.2 §5.5: age >= 16 AND purpose in {analytics,fraud} — satisfied verifies", async () => {
  const { envelope, publicKey } = await buildEnvelope(
    { subject_age: 18, purpose: "analytics" },
    AGE_AND_PURPOSE_PREDICATE,
  );
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  }) as FamilyVerifyResult;
  assert.equal(result.signature_valid, true, `unexpected reason: ${result.reason}`);
  assert.equal(result.claim_type, "ar.consent.v1");
});

// ── Negative: mutate subject_age to 15 — predicate_evaluation_false ──────────
//
// We cannot mutate the body post-sign without breaking the signature, so we
// build a *fresh* envelope with subject_age=15 and the same predicate. The
// signature is valid but the predicate now evaluates to `false` against the
// new body.

test("ACR v1.2 §5.5: subject_age=15 surfaces predicate_evaluation_false", async () => {
  const { envelope, publicKey } = await buildEnvelope(
    { subject_age: 15, purpose: "analytics" },
    AGE_AND_PURPOSE_PREDICATE,
  );
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "predicate_evaluation_false");
});

// ── Negative: purpose not in allowlist surfaces predicate_evaluation_false ───

test("ACR v1.2 §5.5: purpose='marketing' surfaces predicate_evaluation_false", async () => {
  const { envelope, publicKey } = await buildEnvelope(
    { subject_age: 25, purpose: "marketing" },
    AGE_AND_PURPOSE_PREDICATE,
  );
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "predicate_evaluation_false");
});

// ── Negative: disallowed operator surfaces predicate_operator_not_allowed ────
//
// `regex` (or any non-allowlist op) must be rejected by the static AST
// validator before evaluation runs.

test("ACR v1.2: disallowed operator surfaces predicate_operator_not_allowed", async () => {
  const disallowed = {
    regex: [{ var: "body.purpose" }, "^analytics$"],
  } as unknown as JsonLogicAst;
  const { envelope, publicKey } = await buildEnvelope(
    { subject_age: 25, purpose: "analytics" },
    disallowed,
  );
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "predicate_operator_not_allowed");
});

// ── Backwards compat: v1.1-style envelope without v1.2 fields verifies ───────
//
// No iat_ms, no kind, no cause, no predicate → still verifies (v1.1 receipts
// remain byte-equal verifiable per spec L2).

test("ACR v1.1-compat: envelope without v1.2 fields verifies cleanly", async () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000ACRV11C",
    iat: "2026-05-17T00:00:00Z",
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
    body: { compat: true },
  };
  const signed = await signEnvelope(unsigned, privateKey);

  const result = await verifyReceipt(signed, {
    resolveKey: async () => new Uint8Array(pkDer),
  });
  assert.equal(result.signature_valid, true, `unexpected reason: ${result.reason}`);
});
