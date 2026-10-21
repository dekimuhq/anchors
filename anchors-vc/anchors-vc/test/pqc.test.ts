/**
 * Post-quantum end-to-end: the binding is algorithm-agnostic at layer 1. A receipt
 * whose PRIMARY signature is `ml-dsa-65` (FIPS 204) carries through the carrier
 * byte-equal and verifies through `verifyCredential` (the envelope verifier
 * dispatches on `sig_alg`). Requires the native ML-DSA binding (Node ≥ 24.6); the
 * suite SKIPS below that so ed25519 CI on Node 22 stays green.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import {
  generateMlDsaKeypair,
  encodeMlDsaIssKey,
  signEnvelope,
} from "@dekimuhq/anchors-envelope";
import {
  toVerifiableCredential,
  extractEnvelope,
  verifyCredential,
} from "../src/index.ts";

const parts = process.versions.node.split(".").map(Number);
const major = parts[0] ?? 0;
const minor = parts[1] ?? 0;
const HAS_MLDSA = major > 24 || (major === 24 && minor >= 6);
const opts = { skip: HAS_MLDSA ? false : "requires Node >= 24.6 (native ML-DSA)" };

function mlDsaBase(issKey: string): Envelope {
  return {
    v: 2, id: "01JPQC00000000000000000001", iat: "2026-06-30T12:00:00Z",
    iat_ms: Date.parse("2026-06-30T12:00:00Z"), claim_type: "ar.consent.v1",
    iss: "did:web:issuer.example", iss_key: issKey, subject: "sha256:" + "ab".repeat(32),
    exp: null, prev: null, policy_uri: null, policy_hash: null, policy_version: null,
    tsa: null, credentialStatus: null, suspensionStatus: null,
    anchor: { log: "https://verify.dekimu.com/acr/v1", leaf_index: 0, inclusion_proof: [],
      tree_head_root: "sha256:00", tree_size: 1, log_time: "2026-06-30T12:00:01Z" },
    sig: "", countersig: null, sig_alg: "ml-dsa-65", body: { purpose: "marketing" },
  } as Envelope;
}

test("PQC: ml-dsa-65 receipt round-trips byte-equal and verifyCredential validates it", opts, async () => {
  const kp = generateMlDsaKeypair("pqc-1");
  const env = await signEnvelope(mlDsaBase(encodeMlDsaIssKey(kp.publicKeyRaw)), kp.privateKey);
  const vc = toVerifiableCredential(env);

  assert.deepEqual(extractEnvelope(vc), env); // carrier losslessness for a PQC receipt

  // resolveKey serves the raw 1952-byte ml-dsa public key (what the verifier wants).
  const r = await verifyCredential(vc, { resolveKey: async () => kp.publicKeyRaw });
  assert.equal(r.ok, true);
  assert.equal(r.checks.envelopeSignature, true);
  assert.equal(r.envelope?.sig_alg, "ml-dsa-65");
});

test("PQC: tampering an ml-dsa receipt body fails verifyCredential", opts, async () => {
  const kp = generateMlDsaKeypair("pqc-2");
  const env = await signEnvelope(mlDsaBase(encodeMlDsaIssKey(kp.publicKeyRaw)), kp.privateKey);
  const vc = toVerifiableCredential(env);
  vc.evidence[0].envelope = { ...vc.evidence[0].envelope, body: { purpose: "evil" } };

  const r = await verifyCredential(vc, { resolveKey: async () => kp.publicKeyRaw });
  assert.equal(r.ok, false);
  assert.equal(r.checks.envelopeSignature, false);
});
