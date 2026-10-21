/**
 * Status List integration tests for @dekimuhq/apr-verifier — Phase D Task 19.
 *
 * APR receipts MUST NOT carry `credentialStatus` (spec §8.1 / §5.5).
 * This tests the hard-rejection guard and the "no credentialStatus + no rootKey"
 * path (status_state = not_attempted, signature still valid).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import { aprFamily } from "../../src/family.ts";

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Build a signed v=2 APR provenance envelope. `credentialStatus` is settable. */
async function buildAprEnvelope(opts: {
  credentialStatus: Envelope["credentialStatus"];
}): Promise<{ envelope: Envelope; publicKeyDer: Uint8Array }> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000APRSTST",
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
    credentialStatus: opts.credentialStatus,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: { artifact_hash: "sha256:" + "f".repeat(64) },
  };

  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKeyDer: new Uint8Array(pkDer) };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

test("APR status: receipt with credentialStatus is rejected (spec §8.1 / §5.5)", async () => {
  const { envelope, publicKeyDer } = await buildAprEnvelope({
    credentialStatus: {
      id: "https://verify.example/apr/v1/status/2026/05#0",
      type: "StatusList2021Entry",
      statusPurpose: "revocation",
      statusListIndex: "0",
      statusListCredential: "https://verify.example/apr/v1/status/2026/05",
    },
  });

  const result = await aprFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
  });

  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "credentialStatus_unexpected");
  assert.equal(result.claim_type, "ar.provenance.v1");
});

test("APR status: receipt without credentialStatus verifies normally (status_state = not_attempted)", async () => {
  const { envelope, publicKeyDer } = await buildAprEnvelope({
    credentialStatus: null,
  });

  const result = await aprFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "not_attempted");
});

test("APR status: receipt without credentialStatus but with statusListRootKey → no_status_pointer", async () => {
  const { privateKey: skKey, publicKey: pkKey } = crypto.generateKeyPairSync("ed25519");
  const pkKeyDer = pkKey.export({ format: "der", type: "spki" }) as Buffer;
  const { envelope, publicKeyDer } = await buildAprEnvelope({
    credentialStatus: null,
  });

  const result = await aprFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKeyDer,
    statusListRootKey: {
      kid: "did:web:verify.example#root",
      publicKeyDer: base64UrlEncode(new Uint8Array(pkKeyDer)),
    },
  });

  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "no_status_pointer");
});
