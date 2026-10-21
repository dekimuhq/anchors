/**
 * Tests for `ar.continuity.v1` — family-shared continuity attestation.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope
 *
 * Coverage gates (≥4 per spec acceptance criteria):
 *   1. issue → verify round-trip across every family slug
 *   2. tampered field fails sig.invalid
 *   3. stripped sig fails sig.missing
 *   4. corrupt iss_key fails sig.import_error
 *   5. wrong family field after issuing fails sig.invalid (signature covers `family`)
 *   6. kind must be `ar.continuity.v1` (rejects legacy `<family>.continuity.v1`)
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import {
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";

import {
  issueContinuityAttestation,
  verifyContinuityAttestation,
  type ContinuityAttestation,
  type FamilySlug,
} from "../src/continuity.ts";
import { base64UrlEncode } from "../src/base64url.ts";

function freshKeypair(): { publicKey: KeyObject; privateKey: KeyObject } {
  return generateKeyPairSync("ed25519");
}

function encodePublicKey(pub: KeyObject): string {
  const spki = pub.export({ format: "der", type: "spki" }) as Buffer;
  const raw = spki.subarray(spki.length - 32);
  return `ed25519:${base64UrlEncode(new Uint8Array(raw))}`;
}

const FAMILIES: FamilySlug[] = [
  "apr", "acr", "arr", "alr", "atr", "apur", "aer", "aar", "adr",
  "anr", "asr", "abr", "air",
];

test("continuity round-trip across all 13 family slugs", () => {
  for (const family of FAMILIES) {
    const { publicKey, privateKey } = freshKeypair();
    const att = issueContinuityAttestation({
      family,
      iss: `did:web:${family}.example`,
      iss_key: encodePublicKey(publicKey),
      privateKey,
      epoch_from: "2026Q1",
      epoch_to: "2026Q2",
      sealedMapping: "placeholder-sealed",
      sealedMapping_alg: "raw",
      issued_at: "2026-04-01T00:00:00Z",
    });
    assert.equal(att.kind, "ar.continuity.v1", `family ${family}: kind`);
    assert.equal(att.family, family, `family ${family}: family field`);
    assert.match(att.sig!, /^ed25519:/, `family ${family}: sig`);
    const r = verifyContinuityAttestation(att);
    assert.equal(r.valid, true, `family ${family}: ${r.errors.join(",")}`);
  }
});

test("tampered epoch_to fails sig.invalid", () => {
  const { publicKey, privateKey } = freshKeypair();
  const att = issueContinuityAttestation({
    family: "alr",
    iss: "did:web:bank.example",
    iss_key: encodePublicKey(publicKey),
    privateKey,
    epoch_from: "2026Q1",
    epoch_to: "2026Q2",
    sealedMapping: "x",
    sealedMapping_alg: "raw",
    issued_at: "2026-04-01T00:00:00Z",
  });
  const tampered: ContinuityAttestation = { ...att, epoch_to: "2030Q4" };
  const r = verifyContinuityAttestation(tampered);
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ["sig.invalid"]);
});

test("missing sig fails sig.missing", () => {
  const { publicKey, privateKey } = freshKeypair();
  const att = issueContinuityAttestation({
    family: "arr",
    iss: "did:web:processor.example",
    iss_key: encodePublicKey(publicKey),
    privateKey,
    epoch_from: "2026Q1",
    epoch_to: "2026Q2",
    sealedMapping: "x",
    sealedMapping_alg: "raw",
    issued_at: "2026-04-01T00:00:00Z",
  });
  const stripped: ContinuityAttestation = { ...att, sig: null };
  const r = verifyContinuityAttestation(stripped);
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ["sig.missing"]);
});

test("corrupt iss_key fails sig.import_error", () => {
  const { publicKey, privateKey } = freshKeypair();
  const att = issueContinuityAttestation({
    family: "anr",
    iss: "did:web:controller.example",
    iss_key: encodePublicKey(publicKey),
    privateKey,
    epoch_from: "2026Q1",
    epoch_to: "2026Q2",
    sealedMapping: "x",
    sealedMapping_alg: "raw",
    issued_at: "2026-04-01T00:00:00Z",
  });
  const broken: ContinuityAttestation = {
    ...att,
    iss_key: "ed25519:!!!not-base64!!!",
  };
  const r = verifyContinuityAttestation(broken);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("sig.import_error"));
});

test("swapping `family` after issue fails sig.invalid (family is signed)", () => {
  const { publicKey, privateKey } = freshKeypair();
  const att = issueContinuityAttestation({
    family: "alr",
    iss: "did:web:bank.example",
    iss_key: encodePublicKey(publicKey),
    privateKey,
    epoch_from: "2026Q1",
    epoch_to: "2026Q2",
    sealedMapping: "x",
    sealedMapping_alg: "raw",
    issued_at: "2026-04-01T00:00:00Z",
  });
  const cross: ContinuityAttestation = { ...att, family: "arr" };
  const r = verifyContinuityAttestation(cross);
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ["sig.invalid"]);
});

test("legacy <family>.continuity.v1 kind is rejected", () => {
  const { publicKey, privateKey } = freshKeypair();
  // Forge a legacy-shape attestation: sign it with a non-`ar.continuity.v1` kind
  // and hand the verifier the result. The verifier must short-circuit on `kind`.
  const iss_key = encodePublicKey(publicKey);
  const legacy = {
    kind: "alr.continuity.v1",
    iss: "did:web:bank.example",
    iss_key,
    epoch_from: "2026Q1",
    epoch_to: "2026Q2",
    sealedMapping: "x",
    sealedMapping_alg: "raw",
    issued_at: "2026-04-01T00:00:00Z",
    sig: null as string | null,
  };
  const msg = new TextEncoder().encode(JSON.stringify(legacy));
  const sigBytes = nodeSign(null, msg, privateKey);
  legacy.sig = `ed25519:${base64UrlEncode(new Uint8Array(sigBytes))}`;
  const r = verifyContinuityAttestation(legacy as unknown as ContinuityAttestation);
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ["kind.invalid"]);
});
