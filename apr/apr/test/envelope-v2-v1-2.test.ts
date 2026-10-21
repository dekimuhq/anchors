/**
 * Tests for v1.2 envelope additions wired into apr-verifier verifyV2():
 * iat_ms consistency + predicate-forbidden-for-APR (spec §6 + L9).
 *
 * Phase E1 — @dekimuhq/apr-verifier v1.2 envelope-check wiring.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import { verifyReceipt } from "../src/index.ts";

interface SignedFixture {
  envelope: Envelope;
  publicKey: Uint8Array;
}

/** Build a fresh signed v=2 APR envelope with v1.2 overrides applied pre-sign. */
async function buildEnvelope(
  overrides: Partial<Envelope> = {},
): Promise<SignedFixture> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const iat = "2026-05-17T00:00:00Z";
  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000APRV12",
    iat,
    claim_type: "ar.provenance.v1",
    iss: "did:web:commander.example",
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
    body: { artifact_type: "commander.run.output", agent_kind: "ai" },
    ...overrides,
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

// ── iat_ms_mismatch surfaces when iat_ms != Date.parse(iat) ──────────────────

test("verifyV2 surfaces iat_ms_mismatch when iat_ms != Date.parse(iat)", async () => {
  const correct = Date.parse("2026-05-17T00:00:00Z");
  const { envelope, publicKey } = await buildEnvelope({
    iat_ms: correct + 1000, // off by 1 second
  });
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "iat_ms_mismatch");
});

// ── predicate_forbidden_on_claim_type for APR (spec §6 + L9) ─────────────────

test("verifyV2 rejects an APR envelope carrying a predicate", async () => {
  const { envelope, publicKey } = await buildEnvelope({
    // A trivially-true predicate; the predicate value is irrelevant — APR must
    // not carry one at all.
    predicate: { "===": [1, 1] },
  });
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "predicate_forbidden_on_claim_type");
});

// ── v1.1 compat: iat_ms absent verifies cleanly ──────────────────────────────

test("verifyV2 accepts v1.1 APR envelope without iat_ms (backwards compat)", async () => {
  const { envelope, publicKey } = await buildEnvelope({});
  // Sanity: fixture did not set iat_ms.
  assert.equal(envelope.iat_ms, undefined);
  const result = await verifyReceipt(envelope, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.envelope_version, 2);
  assert.equal(result.signature_valid, true);
  assert.equal(result.claim_type, "ar.provenance.v1");
});
