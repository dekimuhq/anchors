// A4 composition test: the mint-gate + non-revocation-proof flow end-to-end.
//
// This exercises the REAL Phase-1 crypto (buildNonRevocationProof /
// verifyNonRevocationProof) against a minimal in-memory revocation oracle that
// stands in for @dekimuhq/mandate-status (whose bitstring + resolver are
// contract-tested separately in dekimu-packages). It proves the three
// composition properties the design hinges on:
//   1. active mandate  -> issuer mints a proof that verifies
//   2. revoked mandate -> mint gate refuses, no proof issued
//   3. immutability    -> a proof minted while active STILL verifies after the
//      mandate is later revoked (verify never consults the live status list —
//      the whole point of stapling: the receipt honestly attests the PAST state)
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeypair } from "@dekimuhq/anchors-envelope";
import {
  buildNonRevocationProof,
  verifyNonRevocationProof,
} from "../src/non-revocation.ts";

const STATUS_LIST_REF = "https://verify.dekimu.com/mandate-status/2026-06";
const RECEIPT_COMMIT = "sha256:" + "a".repeat(64);

// Revocation oracle: true = revoked. Stands in for the mandate-status resolver.
type RevokedOracle = (credentialId: string) => boolean;

/**
 * Issuer mint-gate: only mints a non-revocation proof if the mandate is NOT
 * revoked at mint time. Returns null when the gate refuses.
 */
function mintProof(
  credentialId: string,
  asOf: string,
  receiptCommit: string,
  seed: Uint8Array,
  isRevoked: RevokedOracle,
) {
  if (isRevoked(credentialId)) return null; // gate: revoked -> no receipt
  return buildNonRevocationProof(
    { credentialId, asOf, statusListRef: STATUS_LIST_REF, receiptCommit },
    seed,
  );
}

test("active mandate: mint produces a proof that verifies", () => {
  const kp = generateKeypair("issuer");
  const revoked = new Set<string>(); // nothing revoked
  const proof = mintProof("cred_live", "2026-06-30T10:00:01Z", RECEIPT_COMMIT, kp.privateKey, (id) => revoked.has(id));
  assert.ok(proof, "expected a proof to be minted for an active mandate");
  const v = verifyNonRevocationProof(proof, kp.publicKey, {
    executedAt: "2026-06-30T10:00:00Z",
    expectCredentialId: "cred_live",
    expectReceiptCommit: RECEIPT_COMMIT,
  });
  assert.equal(v.valid, true);
});

test("revoked mandate: mint gate blocks, no proof issued", () => {
  const kp = generateKeypair("issuer");
  const revoked = new Set<string>(["cred_live"]); // already revoked
  const proof = mintProof("cred_live", "2026-06-30T10:00:01Z", RECEIPT_COMMIT, kp.privateKey, (id) => revoked.has(id));
  assert.equal(proof, null);
});

test("historical proof keeps verifying after the mandate is later revoked (immutability)", () => {
  const kp = generateKeypair("issuer");
  const revoked = new Set<string>();
  const proof = mintProof("cred_live", "2026-06-30T10:00:01Z", RECEIPT_COMMIT, kp.privateKey, (id) => revoked.has(id));
  assert.ok(proof);
  // Time passes; the mandate is revoked now.
  revoked.add("cred_live");
  // The already-minted proof still verifies — it attests the PAST state honestly.
  const v = verifyNonRevocationProof(proof, kp.publicKey, {
    executedAt: "2026-06-30T10:00:00Z",
    expectCredentialId: "cred_live",
    expectReceiptCommit: RECEIPT_COMMIT,
  });
  assert.equal(v.valid, true);
});
