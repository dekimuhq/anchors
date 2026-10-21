/**
 * `ar.continuity.v1` — ANR issuer-kit smoke tests over the family-shared
 * helper re-exported from `@dekimuhq/anchors-envelope/continuity` (v0.7.0).
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateIssuerKey,
  encodePublicKey,
  issueContinuityAttestation,
  verifyContinuityAttestation,
} from "../src/issue/index.ts";

test("continuity C1: ANR caller pins family=anr and the issued attestation verifies", () => {
  const { publicKey, privateKey } = generateIssuerKey();
  const iss_key = encodePublicKey(publicKey);
  const att = issueContinuityAttestation({
    family: "anr",
    iss: "did:web:controller.example",
    iss_key,
    privateKey,
    epoch_from: "2026-05-01T00:00:00Z",
    epoch_to: "2026-05-19T00:00:00Z",
    sealedMapping: "base64url-sealedbytes",
    sealedMapping_alg: "raw",
    issued_at: "2026-05-19T00:00:00Z",
  });
  assert.equal(att.kind, "ar.continuity.v1");
  assert.equal(att.family, "anr");
  assert.ok(att.sig);
  const r = verifyContinuityAttestation(att);
  assert.equal(r.valid, true, r.errors.join(","));
});

test("continuity C2: tampered sealedMapping fails sig.invalid", () => {
  const { publicKey, privateKey } = generateIssuerKey();
  const iss_key = encodePublicKey(publicKey);
  const att = issueContinuityAttestation({
    family: "anr",
    iss: "did:web:controller.example",
    iss_key,
    privateKey,
    epoch_from: "2026-05-01T00:00:00Z",
    epoch_to: "2026-05-19T00:00:00Z",
    sealedMapping: "original",
    sealedMapping_alg: "raw",
    issued_at: "2026-05-19T00:00:00Z",
  });
  const tampered = { ...att, sealedMapping: "tampered" };
  const r = verifyContinuityAttestation(tampered);
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ["sig.invalid"]);
});

test("continuity C3: missing sig flagged sig.missing", () => {
  const { publicKey, privateKey } = generateIssuerKey();
  const iss_key = encodePublicKey(publicKey);
  const att = issueContinuityAttestation({
    family: "anr",
    iss: "did:web:controller.example",
    iss_key,
    privateKey,
    epoch_from: "2026-05-01T00:00:00Z",
    epoch_to: "2026-05-19T00:00:00Z",
    sealedMapping: "x",
    sealedMapping_alg: "raw",
    issued_at: "2026-05-19T00:00:00Z",
  });
  const stripped = { ...att, sig: null };
  const r = verifyContinuityAttestation(stripped);
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ["sig.missing"]);
});

test("continuity C4: corrupt iss_key raises sig.import_error", () => {
  const { publicKey, privateKey } = generateIssuerKey();
  const iss_key = encodePublicKey(publicKey);
  const att = issueContinuityAttestation({
    family: "anr",
    iss: "did:web:controller.example",
    iss_key,
    privateKey,
    epoch_from: "2026-05-01T00:00:00Z",
    epoch_to: "2026-05-19T00:00:00Z",
    sealedMapping: "x",
    sealedMapping_alg: "raw",
    issued_at: "2026-05-19T00:00:00Z",
  });
  const broken = { ...att, iss_key: "ed25519:!!!not-base64!!!" };
  const r = verifyContinuityAttestation(broken);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("sig.import_error"));
});
