/**
 * `ar.continuity.v1` — APR issuer-kit smoke tests over the family-shared
 * helper re-exported from `@dekimuhq/anchors-envelope/continuity`.
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

test("APR caller pins family=apr and produces a verifiable attestation", () => {
  const att = issueContinuityAttestation({
    family: "apr",
    iss: "did:web:agent.example",
    iss_key: encodePublicKey(KP.publicKey),
    privateKey: KP.privateKey,
    epoch_from: "2026Q1",
    epoch_to: "2026Q2",
    sealedMapping: Buffer.from("placeholder-sealed-bytes").toString("base64url"),
    sealedMapping_alg: "raw",
    issued_at: "2026-04-01T00:00:00Z",
  });

  assert.equal(att.kind, "ar.continuity.v1");
  assert.equal(att.family, "apr");
  assert.match(att.sig!, /^ed25519:/);

  const out = verifyContinuityAttestation(att);
  assert.equal(out.valid, true, out.errors.join(","));
});

test("tampered attestation fails verification", () => {
  const att = issueContinuityAttestation({
    family: "apr",
    iss: "did:web:agent.example",
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
    family: "apr",
    iss: "did:web:agent.example",
    iss_key: encodePublicKey(KP.publicKey),
    privateKey: KP.privateKey,
    epoch_from: "2026Q1",
    epoch_to: "2026Q2",
    sealedMapping: "x",
    sealedMapping_alg: "raw",
    issued_at: "2026-04-01T00:00:00Z",
  });
  const stripped = { ...att, sig: null };
  const out = verifyContinuityAttestation(stripped);
  assert.equal(out.valid, false);
  assert.deepEqual(out.errors, ["sig.missing"]);
});

test("corrupt iss_key raises sig.import_error", () => {
  const att = issueContinuityAttestation({
    family: "apr",
    iss: "did:web:agent.example",
    iss_key: encodePublicKey(KP.publicKey),
    privateKey: KP.privateKey,
    epoch_from: "2026Q1",
    epoch_to: "2026Q2",
    sealedMapping: "x",
    sealedMapping_alg: "raw",
    issued_at: "2026-04-01T00:00:00Z",
  });
  const broken = { ...att, iss_key: "ed25519:!!!not-base64!!!" };
  const out = verifyContinuityAttestation(broken);
  assert.equal(out.valid, false);
  assert.ok(out.errors.includes("sig.import_error"));
});
