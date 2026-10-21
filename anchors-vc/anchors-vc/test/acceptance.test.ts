/**
 * Crypto acceptance (brief headline criterion):
 *   extractEnvelope(toVerifiableCredential(e)) is byte-equal to `e` AND the
 *   envelope's existing signature still verifies via the envelope verifier, AND
 *   tampering the embedded envelope fails that verifier.
 *
 * This proves carrier-losslessness + that the cryptographic root of trust stays
 * the embedded envelope (the VC wrapper carries no authority over the receipt).
 * Uses real ed25519 minting via `signEnvelope` (requires envelope dist built).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  signEnvelope,
  verifyEnvelopeSignature,
  keyBytesFromKeyRef,
  encodeRaw,
} from "@dekimuhq/anchors-envelope";
import { toVerifiableCredential, extractEnvelope } from "../src/index.ts";

/** Raw 32-byte ed25519 public key from a node KeyObject. */
function rawPub(pk: crypto.KeyObject): Uint8Array {
  return new Uint8Array(
    (pk.export({ format: "der", type: "spki" }) as Buffer).subarray(-32),
  );
}

/** Mint a real ed25519-signed v2 envelope. */
async function mintEnvelope(overrides: Partial<Envelope> = {}): Promise<Envelope> {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const base = {
    v: 2,
    id: "01J0000000000000000000000A",
    iat: "2026-06-30T12:00:00Z",
    iat_ms: Date.parse("2026-06-30T12:00:00Z"),
    claim_type: "ar.consent.v1",
    iss: "did:web:issuer.example",
    iss_key: `ed25519:${encodeRaw(rawPub(publicKey))}`,
    subject: "did:web:subject.example",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    suspensionStatus: null,
    anchor: {
      log: "https://verify.dekimu.com/acr/v1",
      leaf_index: 0,
      inclusion_proof: [],
      tree_head_root: "sha256:00",
      tree_size: 1,
      log_time: "2026-06-30T12:00:01Z",
    },
    sig: "",
    countersig: null,
    body: { purpose: "marketing" },
    ...overrides,
  } as Envelope;
  return signEnvelope(base, privateKey);
}

function verifyEnv(e: Envelope): boolean {
  const der = keyBytesFromKeyRef(e.iss_key);
  assert.ok(der, "iss_key must decode to key bytes");
  return verifyEnvelopeSignature(e, der);
}

test("ACCEPTANCE: extracted envelope is byte-equal AND its signature verifies", async () => {
  const e = await mintEnvelope();
  const vc = toVerifiableCredential(e);
  const recovered = extractEnvelope(vc);
  assert.deepEqual(recovered, e); // carrier losslessness
  assert.equal(verifyEnv(recovered), true); // crypto truth survives the round-trip
});

test("ACCEPTANCE: tampering the embedded envelope fails the envelope verifier", async () => {
  const e = await mintEnvelope();
  const vc = toVerifiableCredential(e);
  vc.evidence[0].envelope = {
    ...vc.evidence[0].envelope,
    subject: "did:web:evil.example",
  };
  assert.equal(verifyEnv(extractEnvelope(vc)), false);
});

test("ACCEPTANCE: subjectless action receipt round-trips, verifies, and frames as an act", async () => {
  const e = await mintEnvelope({
    claim_type: "ar.action.v1",
    subject: null as unknown as string,
  });
  const vc = toVerifiableCredential(e);
  assert.ok(!("id" in vc.credentialSubject)); // Q4: no data subject
  const recovered = extractEnvelope(vc);
  assert.deepEqual(recovered, e);
  assert.equal(verifyEnv(recovered), true);
});

test("ACCEPTANCE: a receipt with revocation status round-trips byte-equal + verifies", async () => {
  const e = await mintEnvelope({
    credentialStatus: {
      id: "https://verify.dekimu.com/status/acr/v1#7",
      type: "StatusList2021Entry",
      statusPurpose: "revocation",
      statusListIndex: "7",
      statusListCredential: "https://verify.dekimu.com/status/acr/v1",
    },
  });
  const vc = toVerifiableCredential(e);
  assert.deepEqual(vc.credentialStatus, e.credentialStatus); // 1:1 lift
  assert.deepEqual(extractEnvelope(vc), e);
  assert.equal(verifyEnv(extractEnvelope(vc)), true);
});
