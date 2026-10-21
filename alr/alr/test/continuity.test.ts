/**
 * `ar.continuity.v1` — ALR issuer-kit smoke tests over the family-shared
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

const KP = generateIssuerKey();

test("ALR caller pins family=alr and produces a verifiable ar.continuity.v1", () => {
  const att = issueContinuityAttestation({
    family: "alr",
    iss: "did:web:processor.example",
    iss_key: encodePublicKey(KP.publicKey),
    privateKey: KP.privateKey,
    epoch_from: "2026Q1",
    epoch_to: "2026Q2",
    sealedMapping: Buffer.from("placeholder-sealed-bytes").toString("base64url"),
    sealedMapping_alg: "raw",
    issued_at: "2026-04-01T00:00:00Z",
  });

  assert.equal(att.kind, "ar.continuity.v1");
  assert.equal(att.family, "alr");
  assert.equal(att.epoch_from, "2026Q1");
  assert.equal(att.epoch_to, "2026Q2");
  assert.match(att.sig!, /^ed25519:/);

  const out = verifyContinuityAttestation(att);
  assert.equal(out.valid, true);
});

test("tampered attestation fails verification", () => {
  const att = issueContinuityAttestation({
    family: "alr",
    iss: "did:web:processor.example",
    iss_key: encodePublicKey(KP.publicKey),
    privateKey: KP.privateKey,
    epoch_from: "2026Q1",
    epoch_to: "2026Q2",
    sealedMapping: Buffer.from("placeholder-sealed-bytes").toString("base64url"),
    sealedMapping_alg: "raw",
    issued_at: "2026-04-01T00:00:00Z",
  });
  const tampered = { ...att, epoch_to: "2030Q4" };
  const out = verifyContinuityAttestation(tampered);
  assert.equal(out.valid, false);
});

test("attestation without sig fails verification", () => {
  const att = issueContinuityAttestation({
    family: "alr",
    iss: "did:web:processor.example",
    iss_key: encodePublicKey(KP.publicKey),
    privateKey: KP.privateKey,
    epoch_from: "2026Q1",
    epoch_to: "2026Q2",
    sealedMapping: Buffer.from("placeholder-sealed-bytes").toString("base64url"),
    sealedMapping_alg: "raw",
    issued_at: "2026-04-01T00:00:00Z",
  });
  const stripped = { ...att, sig: null };
  const out = verifyContinuityAttestation(stripped);
  assert.equal(out.valid, false);
  assert.deepEqual(out.errors, ["sig.missing"]);
});
