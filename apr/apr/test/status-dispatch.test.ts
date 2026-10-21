/**
 * Tests for APR v=2 dispatch status-list integration (Phase D Task 19).
 *
 * APR has the unique constraint that `credentialStatus` MUST be null — the
 * verifier rejects any APR receipt that carries one. Status reconciliation is
 * therefore advisory in the same advisory-only sense as TSA/policy: when
 * `statusListRootKey` is provided and `credentialStatus` is null, the result
 * carries `status_state: "no_status_pointer"`.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { signEnvelope, base64UrlEncode } from "@dekimuhq/anchors-envelope";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import type { RootKeyMaterial } from "@dekimuhq/anchors-envelope/status";
import { aprFamily } from "../src/family.ts";

interface BuildOpts {
  credentialStatus?: Envelope["credentialStatus"];
}

async function buildAprEnvelope(
  opts: BuildOpts = {},
): Promise<{ envelope: Envelope; publicKey: Uint8Array }> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pkDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const pkRaw = pkDer.subarray(-32);
  const issKey = `ed25519:${base64UrlEncode(new Uint8Array(pkRaw))}` as const;

  const unsigned: Envelope = {
    v: 2,
    id: "01HXX0000000000000000APRST01",
    claim_type: "ar.provenance.v1",
    iss: "did:web:source.example",
    iss_key: issKey,
    subject: "sha256:" + "a".repeat(64),
    iat: "2026-05-17T00:00:00Z",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: opts.credentialStatus ?? null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: { source: "ipfs://Qm..." },
  };
  const signed = await signEnvelope(unsigned, privateKey);
  return { envelope: signed, publicKey: new Uint8Array(pkDer) };
}

// Stub root key — never used for any actual reconciliation in these tests
// (APR's credentialStatus is null, so the function returns no_status_pointer
// without touching the rootKey). Shape-valid so the option binds typeck.
const DUMMY_ROOT_KEY: RootKeyMaterial = {
  kid: "did:web:verify.dekimu.com#root",
  publicKeyDer: "A".repeat(43),
};

test("APR v=2: credentialStatus null + statusListRootKey provided → signature_valid, status_state: no_status_pointer", async () => {
  const { envelope, publicKey } = await buildAprEnvelope();
  const result = await aprFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: DUMMY_ROOT_KEY,
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "no_status_pointer");
});

test("APR v=2: credentialStatus null + no statusListRootKey → signature_valid, status_state: not_attempted", async () => {
  const { envelope, publicKey } = await buildAprEnvelope();
  const result = await aprFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, true);
  assert.equal(result.status_state, "not_attempted");
});

test("APR v=2: credentialStatus pointer present (WITH rootKey) → signature_valid: false, reason: credentialStatus_unexpected", async () => {
  const cs = {
    id: "https://verify.dekimu.com/apr/status#1",
    type: "StatusList2021Entry" as const,
    statusPurpose: "revocation" as const,
    statusListIndex: "1",
    statusListCredential: "https://verify.dekimu.com/apr/status",
  };
  const { envelope, publicKey } = await buildAprEnvelope({ credentialStatus: cs });
  const result = await aprFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
    statusListRootKey: DUMMY_ROOT_KEY,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "credentialStatus_unexpected");
});

test("APR v=2: credentialStatus pointer present (NO rootKey) → still rejects with credentialStatus_unexpected", async () => {
  const cs = {
    id: "https://verify.dekimu.com/apr/status#1",
    type: "StatusList2021Entry" as const,
    statusPurpose: "revocation" as const,
    statusListIndex: "1",
    statusListCredential: "https://verify.dekimu.com/apr/status",
  };
  const { envelope, publicKey } = await buildAprEnvelope({ credentialStatus: cs });
  const result = await aprFamily.verifyReceipt(envelope as unknown as Record<string, unknown>, {
    resolveKey: async () => publicKey,
  });
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "credentialStatus_unexpected");
});
