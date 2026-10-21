/**
 * Phase D Task 18 — Status List Credential signature verify.
 *
 * Covers W3C VC Ed25519Signature2020 over RFC 8785 canonical form:
 *   - accepts credential signed by the published verify.dekimu.com root key
 *   - rejects credential signed by a different key (kid mismatch)
 *   - rejects tampered credentialSubject.encodedList (signature break)
 *   - rejects missing proof block
 *   - rejects wrong proof.type
 *   - rejects malformed proofValue (non-base64url / wrong length)
 *   - rejects non-object credential (null, string, number)
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyStatusListCredentialSignature } from "../../src/status/verify.ts";
import type {
  StatusListCredential,
  RootKeyMaterial,
} from "../../src/status/types.ts";

import signedCredential from "./fixtures/status-list-signed.json" with { type: "json" };
import rootKey from "./fixtures/verify.dekimu.com-root.json" with { type: "json" };
import otherKey from "./fixtures/some-other-root.json" with { type: "json" };

const credential = signedCredential as unknown as StatusListCredential;
const rootPubKey = rootKey as unknown as RootKeyMaterial;
const wrongPubKey = otherKey as unknown as RootKeyMaterial;

test("accepts a credential signed with the published verify.dekimu.com root key", async () => {
  const ok = await verifyStatusListCredentialSignature(credential, rootPubKey);
  assert.equal(ok, true);
});

test("rejects credential signed with a different key", async () => {
  const ok = await verifyStatusListCredentialSignature(credential, wrongPubKey);
  assert.equal(ok, false);
});

test("rejects tampered credentialSubject.encodedList", async () => {
  const tampered: StatusListCredential = {
    ...credential,
    credentialSubject: {
      ...credential.credentialSubject,
      encodedList: "tampered",
    },
  };
  const ok = await verifyStatusListCredentialSignature(tampered, rootPubKey);
  assert.equal(ok, false);
});

test("rejects credential with no proof block", async () => {
  const { proof: _proof, ...unsigned } = credential;
  const ok = await verifyStatusListCredentialSignature(
    unsigned as unknown,
    rootPubKey,
  );
  assert.equal(ok, false);
});

test("rejects credential with wrong proof.type", async () => {
  const wrongType = {
    ...credential,
    proof: { ...credential.proof, type: "RsaSignature2018" },
  };
  const ok = await verifyStatusListCredentialSignature(wrongType, rootPubKey);
  assert.equal(ok, false);
});

test("rejects credential with malformed proofValue (wrong byte length)", async () => {
  // base64url-decodes cleanly but to < 64 bytes
  const malformed: StatusListCredential = {
    ...credential,
    proof: { ...credential.proof, proofValue: "AAAA" },
  };
  const ok = await verifyStatusListCredentialSignature(malformed, rootPubKey);
  assert.equal(ok, false);
});

test("rejects non-object credentials (null, string, number)", async () => {
  assert.equal(
    await verifyStatusListCredentialSignature(null, rootPubKey),
    false,
  );
  assert.equal(
    await verifyStatusListCredentialSignature("not a credential", rootPubKey),
    false,
  );
  assert.equal(
    await verifyStatusListCredentialSignature(42, rootPubKey),
    false,
  );
});

test("rejects credential whose verificationMethod doesn't match rootKey.kid", async () => {
  const mismatched: StatusListCredential = {
    ...credential,
    proof: {
      ...credential.proof,
      verificationMethod: "did:web:other.example#root",
    },
  };
  const ok = await verifyStatusListCredentialSignature(mismatched, rootPubKey);
  assert.equal(ok, false);
});
