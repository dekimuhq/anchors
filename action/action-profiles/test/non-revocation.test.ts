import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair } from "@dekimuhq/anchors-envelope";
import {
  buildNonRevocationProof,
  verifyNonRevocationProof,
} from "../src/non-revocation.ts";

// Deterministic issuer key for tests.
function issuerKey() {
  const kp = generateKeypair("a4-test");
  return { seed: kp.privateKey, pub: kp.publicKey };
}

const RECEIPT_COMMIT = "sha256:" + "c".repeat(64);

const base = {
  credentialId: "cred_abc",
  asOf: "2026-06-30T10:00:01Z",
  statusListRef: "https://verify.dekimu.com/mandate-status/2026-06",
  receiptCommit: RECEIPT_COMMIT,
};

/** The required body-binding opts that every valid verify call must carry. */
const binding = {
  executedAt: "2026-06-30T10:00:00Z",
  expectCredentialId: "cred_abc",
  expectReceiptCommit: RECEIPT_COMMIT,
};

test("round-trip: built proof verifies against the issuer public key", () => {
  const { seed, pub } = issuerKey();
  const proof = buildNonRevocationProof(base, seed);
  assert.equal(proof.status, "active");
  assert.equal(proof.credential_id, "cred_abc");
  assert.equal(proof.receipt_commit, RECEIPT_COMMIT);
  const r = verifyNonRevocationProof(proof, pub, binding);
  assert.equal(r.valid, true);
});

test("receipt_commit mismatch with body fails (fail-closed)", () => {
  const { seed, pub } = issuerKey();
  const proof = buildNonRevocationProof(base, seed);
  const r = verifyNonRevocationProof(proof, pub, {
    ...binding,
    expectReceiptCommit: "sha256:" + "d".repeat(64), // body request_id_commit differs
  });
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /receipt_commit/);
});

test("tamper: mutated receipt_commit on a signed proof fails the signature", () => {
  const { seed, pub } = issuerKey();
  const proof = { ...buildNonRevocationProof(base, seed), receipt_commit: "sha256:" + "e".repeat(64) };
  // Pass the tampered commit as the expected one too, so binding passes and the
  // failure can only come from the signature over the (now different) payload.
  const r = verifyNonRevocationProof(proof, pub, {
    ...binding,
    expectReceiptCommit: "sha256:" + "e".repeat(64),
  });
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /signature/);
});

test("tamper: mutated credential_id fails", () => {
  const { seed, pub } = issuerKey();
  const proof = { ...buildNonRevocationProof(base, seed), credential_id: "cred_evil" };
  const r = verifyNonRevocationProof(proof, pub, { ...binding, expectCredentialId: "cred_evil" });
  assert.equal(r.valid, false);
});

test("tamper: wrong public key fails", () => {
  const { seed } = issuerKey();
  const other = issuerKey();
  const proof = buildNonRevocationProof(base, seed);
  const r = verifyNonRevocationProof(proof, other.pub, binding);
  assert.equal(r.valid, false);
});

test("as_of before executed_at fails (fail-closed)", () => {
  const { seed, pub } = issuerKey();
  const proof = buildNonRevocationProof({ ...base, asOf: "2026-06-30T09:59:59Z" }, seed);
  const r = verifyNonRevocationProof(proof, pub, binding);
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /as_of/);
});

test("as_of beyond MAX lag fails (fail-closed)", () => {
  const { seed, pub } = issuerKey();
  // default MAX_ATTESTATION_LAG_MS = 5 min; 10 min later → reject
  const proof = buildNonRevocationProof({ ...base, asOf: "2026-06-30T10:10:01Z" }, seed);
  const r = verifyNonRevocationProof(proof, pub, binding);
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /lag/);
});

test("credential_id consistency check against the receipt body", () => {
  const { seed, pub } = issuerKey();
  const proof = buildNonRevocationProof(base, seed);
  const r = verifyNonRevocationProof(proof, pub, {
    ...binding,
    expectCredentialId: "cred_xyz", // mismatch with proof.credential_id
  });
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /credential_id/);
});

test("boundary: as_of === executed_at is valid", () => {
  const { seed, pub } = issuerKey();
  const proof = buildNonRevocationProof({ ...base, asOf: "2026-06-30T10:00:00Z" }, seed);
  const r = verifyNonRevocationProof(proof, pub, binding);
  assert.equal(r.valid, true);
});

test("boundary: lag exactly == maxLag is valid (> check)", () => {
  const { seed, pub } = issuerKey();
  // exactly 60s after executedAt, non-default maxLagMs = 60000
  const proof = buildNonRevocationProof({ ...base, asOf: "2026-06-30T10:01:00Z" }, seed);
  const r = verifyNonRevocationProof(proof, pub, {
    ...binding,
    maxLagMs: 60000,
  });
  assert.equal(r.valid, true);
});

test("non-default maxLagMs smaller than gap fails", () => {
  const { seed, pub } = issuerKey();
  // base.asOf is 1s after executedAt; maxLagMs of 500ms < 1000ms gap → reject
  const proof = buildNonRevocationProof(base, seed);
  const r = verifyNonRevocationProof(proof, pub, {
    ...binding,
    maxLagMs: 500,
  });
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /lag/);
});

test("empty sig fails (malformed)", () => {
  const { seed, pub } = issuerKey();
  const proof = { ...buildNonRevocationProof(base, seed), sig: "" };
  const r = verifyNonRevocationProof(proof, pub, binding);
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /malformed/);
});

test("non-RFC3339 as_of fails (fail-closed)", () => {
  const { seed, pub } = issuerKey();
  // space instead of T, no timezone → not RFC3339
  const proof = { ...buildNonRevocationProof(base, seed), as_of: "2026-06-30 10:00:00" };
  const r = verifyNonRevocationProof(proof, pub, binding);
  assert.equal(r.valid, false);
  assert.match(r.reason ?? "", /RFC3339|timestamp/i);
});
