/**
 * Wrapper Data-Integrity proof (Q2 layer 2) — attach/verify + tamper.
 *
 * Uses the real envelope ed25519 helpers (requires the envelope dist built +
 * workspace installed). The envelope `sig` here is a placeholder — these tests
 * exercise the WRAPPER proof, not the envelope root of trust (that is
 * acceptance.test.ts).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import { generateKeypair, encodeRaw } from "@dekimuhq/anchors-envelope";
import { toVerifiableCredential } from "../src/wrap.ts";
import { attachWrapperProof, verifyWrapperProof } from "../src/proof.ts";

function envWith(pubKeyB64: string): Envelope {
  return {
    v: 2,
    id: "01J0000000000000000000000A",
    iat: "2026-06-30T12:00:00Z",
    iat_ms: Date.parse("2026-06-30T12:00:00Z"),
    claim_type: "ar.consent.v1",
    iss: "did:web:issuer.example",
    iss_key: `ed25519:${pubKeyB64}`,
    subject: "did:web:subject.example",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor: {
      log: "https://verify.dekimu.com/acr/v1",
      leaf_index: 0,
      inclusion_proof: [],
      tree_head_root: "sha256:00",
      tree_size: 1,
      log_time: "2026-06-30T12:00:01Z",
    },
    sig: "ZmFrZQ",
    countersig: null,
    body: { purpose: "marketing" },
  } as Envelope;
}

test("attach + verify wrapper proof round-trips (eddsa-jcs-2022)", () => {
  const kp = generateKeypair("key-1");
  const vc = toVerifiableCredential(envWith(encodeRaw(kp.publicKey)));
  const signed = attachWrapperProof(vc, kp, {
    verificationMethod: "did:web:issuer.example#key-1",
  });
  assert.equal(signed.proof?.type, "DataIntegrityProof");
  assert.equal(signed.proof?.cryptosuite, "eddsa-jcs-2022");
  assert.equal(signed.proof?.created, vc.validFrom);
  assert.deepEqual(verifyWrapperProof(signed, kp.publicKey), { ok: true });
});

test("attachWrapperProof does not mutate the input credential", () => {
  const kp = generateKeypair("key-1");
  const vc = toVerifiableCredential(envWith(encodeRaw(kp.publicKey)));
  attachWrapperProof(vc, kp, { verificationMethod: "did:web:issuer.example#key-1" });
  assert.ok(!("proof" in vc));
});

test("tampering a lifted wrapper field (issuer) fails verification", () => {
  const kp = generateKeypair("key-1");
  const vc = toVerifiableCredential(envWith(encodeRaw(kp.publicKey)));
  const signed = attachWrapperProof(vc, kp, {
    verificationMethod: "did:web:issuer.example#key-1",
  });
  const tampered = { ...signed, issuer: "did:web:evil.example" };
  assert.deepEqual(verifyWrapperProof(tampered, kp.publicKey), {
    ok: false,
    reason: "bad_signature",
  });
});

test("tampering the embedded envelope fails the wrapper proof too (evidence is covered)", () => {
  const kp = generateKeypair("key-1");
  const vc = toVerifiableCredential(envWith(encodeRaw(kp.publicKey)));
  const signed = attachWrapperProof(vc, kp, {
    verificationMethod: "did:web:issuer.example#key-1",
  });
  const tampered = structuredClone(signed);
  tampered.evidence[0].envelope = {
    ...tampered.evidence[0].envelope,
    body: { purpose: "evil" },
  };
  assert.equal(verifyWrapperProof(tampered, kp.publicKey).ok, false);
});

test("a different key fails verification", () => {
  const kp = generateKeypair("key-1");
  const other = generateKeypair("key-2");
  const vc = toVerifiableCredential(envWith(encodeRaw(kp.publicKey)));
  const signed = attachWrapperProof(vc, kp, {
    verificationMethod: "did:web:issuer.example#key-1",
  });
  assert.equal(verifyWrapperProof(signed, other.publicKey).ok, false);
});

test("verifyWrapperProof with no proof returns ok:false reason no_proof", () => {
  const kp = generateKeypair("key-1");
  const vc = toVerifiableCredential(envWith(encodeRaw(kp.publicKey)));
  assert.deepEqual(verifyWrapperProof(vc, kp.publicKey), {
    ok: false,
    reason: "no_proof",
  });
});

test("verifyWrapperProof rejects an unregistered cryptosuite", () => {
  const kp = generateKeypair("key-1");
  const vc = toVerifiableCredential(envWith(encodeRaw(kp.publicKey)));
  const signed = attachWrapperProof(vc, kp, { verificationMethod: "did:web:issuer.example#key-1" });
  const swapped = { ...signed, proof: { ...signed.proof!, cryptosuite: "ecdsa-jcs-2019" } };
  assert.deepEqual(verifyWrapperProof(swapped, kp.publicKey), {
    ok: false,
    reason: "unsupported_cryptosuite",
  });
});
