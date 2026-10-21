/**
 * v1.3 Phase 2 — ml-dsa-65 (FIPS 204) wired into the sig_alg dispatch hook.
 *
 * Spec:     https://github.com/dekimuhq/anchors-spec/blob/main/rfcs/RFC-001-sig-alg-discriminator.md
 * Decision: an internal design record (not published)
 *
 * Provider: native node:crypto on Node ≥24.6 (OpenSSL 3.5, nodejs/node#59259).
 * These tests REQUIRE Node ≥24.6; on an older runtime ml-dsa keygen throws and
 * the suite fails loudly rather than silently skipping (the floor is enforced).
 *
 * Covers:
 *   §3.2 — ml-dsa-65 key sizes (1952 B pub, 3309 B sig) and JWK round-trip.
 *   §L8  — verifyEnvelopeSignature dispatches on sig_alg to the ml-dsa verifier;
 *          a valid ml-dsa receipt verifies, a tampered one does not.
 *   M-1  — signatures are randomized (hedged) yet every signing verifies; the
 *          relaxation is exercised, not just asserted.
 *   §6   — registering ml-dsa-65 does not perturb the ed25519 byte-equal corpus.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";

import type { Envelope, AnchorProof } from "../src/envelope-types.ts";
import {
  preSigCanonical,
  signEnvelope,
  verifyEnvelopeSignature,
  isSupportedSigAlg,
} from "../src/envelope.ts";
import {
  MLDSA65_PUBKEY_BYTES,
  MLDSA65_SIG_BYTES,
  generateMlDsaKeypair,
  publicKeyFromRaw,
  rawPublicKey,
  encodeMlDsaIssKey,
  signMlDsaCanonical,
  verifyMlDsaCanonical,
} from "../src/ml-dsa.ts";

const ANCHOR_FIXTURE: AnchorProof = {
  log: "https://verify.dekimu.com/apr/v1",
  leaf_index: 0,
  inclusion_proof: ["sha256:aabbcc"],
  tree_head_root: "sha256:deadbeef",
  tree_size: 1,
  log_time: "2026-05-16T14:00:00Z",
};

/** A minimal ml-dsa-65 envelope shell (sig filled in by signEnvelope). */
function makeMlDsaEnvelope(issKey: `ml-dsa-65:${string}`, overrides: Partial<Envelope> = {}): Envelope {
  const base: Envelope = {
    v: 2,
    id: "01HZ0000000000000000000001",
    iat: "2026-05-16T14:00:00Z",
    claim_type: "ar.consent.v1",
    iss: "did:key:z6MkPqcIssuer",
    iss_key: issKey,
    subject: "did:key:z6MkTestSubject",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR_FIXTURE,
    sig: "placeholder-sig",
    countersig: null,
    sig_alg: "ml-dsa-65",
    body: { hello: 1 },
  };
  return { ...base, ...overrides };
}

// ── §3.2: key + signature sizes, JWK round-trip ──────────────────────────────

test("ml-dsa-65 keypair: 1952 B raw pub, 3309 B sig, raw round-trips through KeyObject", () => {
  const kp = generateMlDsaKeypair("kid-1");
  assert.equal(kp.publicKeyRaw.length, MLDSA65_PUBKEY_BYTES);

  // raw → KeyObject → raw is identity
  const rebuilt = publicKeyFromRaw(kp.publicKeyRaw);
  assert.deepEqual([...rawPublicKey(rebuilt)], [...kp.publicKeyRaw]);

  const sig = signMlDsaCanonical({ x: 1 }, kp.privateKey);
  assert.equal(sig.length, MLDSA65_SIG_BYTES);
  assert.equal(verifyMlDsaCanonical({ x: 1 }, sig, kp.publicKeyRaw), true);
});

test("encodeMlDsaIssKey produces a well-formed ml-dsa-65: fingerprint", () => {
  const kp = generateMlDsaKeypair("kid-2");
  const issKey = encodeMlDsaIssKey(kp.publicKeyRaw);
  assert.ok(issKey.startsWith("ml-dsa-65:"));
  assert.match(issKey.slice("ml-dsa-65:".length), /^[A-Za-z0-9_-]+$/);
});

// ── §L8: dispatch — a valid ml-dsa receipt verifies, tampering fails ──────────

test("verifyEnvelopeSignature dispatches to ml-dsa-65 and verifies a valid receipt", async () => {
  const kp = generateMlDsaKeypair("kid-3");
  const e = makeMlDsaEnvelope(encodeMlDsaIssKey(kp.publicKeyRaw));

  const signed = await signEnvelope(e, kp.privateKey);
  assert.equal(signed.sig_alg, "ml-dsa-65");
  assert.equal(verifyEnvelopeSignature(signed, kp.publicKeyRaw), true);
});

test("a tampered ml-dsa body fails verification", async () => {
  const kp = generateMlDsaKeypair("kid-4");
  const signed = await signEnvelope(makeMlDsaEnvelope(encodeMlDsaIssKey(kp.publicKeyRaw)), kp.privateKey);

  const tampered = { ...signed, body: { hello: 999 } };
  assert.equal(verifyEnvelopeSignature(tampered, kp.publicKeyRaw), false);
});

test("stripping the signed-in sig_alg from an ml-dsa receipt fails verification", async () => {
  const kp = generateMlDsaKeypair("kid-5");
  const signed = await signEnvelope(makeMlDsaEnvelope(encodeMlDsaIssKey(kp.publicKeyRaw)), kp.privateKey);

  // Removing sig_alg routes it to ed25519 (absent ≡ ed25519) AND changes the
  // signed bytes — both make it fail. Never a silent pass.
  const stripped = { ...signed };
  delete (stripped as { sig_alg?: unknown }).sig_alg;
  assert.equal(verifyEnvelopeSignature(stripped, kp.publicKeyRaw), false);
});

test("a wrong ml-dsa public key fails verification", async () => {
  const kp = generateMlDsaKeypair("kid-6");
  const other = generateMlDsaKeypair("kid-6b");
  const signed = await signEnvelope(makeMlDsaEnvelope(encodeMlDsaIssKey(kp.publicKeyRaw)), kp.privateKey);
  assert.equal(verifyEnvelopeSignature(signed, other.publicKeyRaw), false);
});

test("a malformed (wrong-length) ml-dsa public key fails cleanly, never throws", async () => {
  const kp = generateMlDsaKeypair("kid-7");
  const signed = await signEnvelope(makeMlDsaEnvelope(encodeMlDsaIssKey(kp.publicKeyRaw)), kp.privateKey);
  assert.equal(verifyEnvelopeSignature(signed, new Uint8Array(31)), false);
});

// ── M-1: signatures are randomized (hedged) but every signing verifies ───────

test("M-1 relaxation: ml-dsa signing is randomized yet always verifies (sig is leaf-excluded)", () => {
  const kp = generateMlDsaKeypair("kid-8");
  const s1 = signMlDsaCanonical({ x: 1 }, kp.privateKey);
  const s2 = signMlDsaCanonical({ x: 1 }, kp.privateKey);
  // Hedged mode → two signatures over identical bytes differ…
  assert.notDeepEqual([...s1], [...s2]);
  // …yet both verify. preSigCanonical zeroes `sig`, so the differing bytes never
  // enter the Merkle leaf / anchor — anchoring is unaffected.
  assert.equal(verifyMlDsaCanonical({ x: 1 }, s1, kp.publicKeyRaw), true);
  assert.equal(verifyMlDsaCanonical({ x: 1 }, s2, kp.publicKeyRaw), true);
});

// ── §6: ed25519 corpus byte-equality is untouched by adding ml-dsa-65 ─────────

test("registering ml-dsa-65 leaves the ed25519 path byte-equal (no sig_alg key for ed25519)", () => {
  // An ed25519 receipt that omits sig_alg must still canonicalize with no sig_alg
  // key — proving the dispatch addition did not perturb the existing corpus.
  // (sig_alg is OMITTED entirely, not set to undefined — canonicalize rejects undefined.)
  const edEnvelope: Envelope = {
    v: 2,
    id: "01HZ0000000000000000000009",
    iat: "2026-05-16T14:00:00Z",
    claim_type: "ar.consent.v1",
    iss: "did:key:z6MkEdIssuer",
    iss_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    subject: "did:key:z6MkTestSubject",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR_FIXTURE,
    sig: "placeholder-sig",
    countersig: null,
    body: { hello: 1 },
  };
  const canonical = preSigCanonical(edEnvelope);
  assert.ok(!canonical.includes('"sig_alg"'), "omitted sig_alg must not appear in canonical form");
  assert.equal(isSupportedSigAlg(undefined), true);
});
