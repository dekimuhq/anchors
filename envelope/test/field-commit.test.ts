import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { base64UrlEncode } from "../src/base64url.ts";
import { issueFieldCommit, verifyFieldCommit } from "../src/field-commit.ts";

function newIssuer() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const raw = spki.subarray(spki.length - 32); // last 32 bytes = raw ed25519 pubkey
  return { privateKey, iss_key: `ed25519:${base64UrlEncode(new Uint8Array(raw))}` };
}

const FIELD_ROOT = `sha256:${"a".repeat(64)}`;

test("issue + verify round-trip", () => {
  const { privateKey, iss_key } = newIssuer();
  const att = issueFieldCommit(
    { family: "acr", id: "rcpt-1", field_root: FIELD_ROOT, leaf_count: 4, iss_key, issued_at: "2026-06-01T00:00:00Z" },
    privateKey,
  );
  assert.equal(att.kind, "ar.field_commit.v1");
  assert.equal(verifyFieldCommit(att).valid, true);
});

test("tampering field_root after signing breaks the sig", () => {
  const { privateKey, iss_key } = newIssuer();
  const att = issueFieldCommit(
    { family: "acr", id: "rcpt-1", field_root: FIELD_ROOT, leaf_count: 4, iss_key, issued_at: "2026-06-01T00:00:00Z" },
    privateKey,
  );
  const tampered = { ...att, field_root: `sha256:${"b".repeat(64)}` };
  assert.equal(verifyFieldCommit(tampered).valid, false);
});

test("missing sig is invalid", () => {
  const { privateKey, iss_key } = newIssuer();
  const att = issueFieldCommit(
    { family: "acr", id: "rcpt-1", field_root: FIELD_ROOT, leaf_count: 4, iss_key, issued_at: "2026-06-01T00:00:00Z" },
    privateKey,
  );
  assert.equal(verifyFieldCommit({ ...att, sig: null }).valid, false);
});

test("leaf_count is signed-in: mutating it after signing breaks the sig", () => {
  const { privateKey, iss_key } = newIssuer();
  const att = issueFieldCommit(
    { family: "acr", id: "rcpt-1", field_root: FIELD_ROOT, leaf_count: 4, iss_key, issued_at: "2026-06-01T00:00:00Z" },
    privateKey,
  );
  assert.equal(att.leaf_count, 4);
  assert.equal(verifyFieldCommit(att).valid, true);
  assert.equal(verifyFieldCommit({ ...att, leaf_count: 99 }).valid, false);
});

test("wrong id after sign → invalid", () => {
  const { privateKey, iss_key } = newIssuer();
  const att = issueFieldCommit(
    { family: "acr", id: "rcpt-1", field_root: FIELD_ROOT, leaf_count: 4, iss_key, issued_at: "2026-06-01T00:00:00Z" },
    privateKey,
  );
  const tampered = { ...att, id: "rcpt-9999" };
  const r = verifyFieldCommit(tampered);
  assert.equal(r.valid, false);
});

test("wrong iss_key after sign (keep old sig) → invalid", () => {
  const { privateKey, iss_key } = newIssuer();
  const { iss_key: iss_key_b } = newIssuer();
  const att = issueFieldCommit(
    { family: "acr", id: "rcpt-1", field_root: FIELD_ROOT, leaf_count: 4, iss_key, issued_at: "2026-06-01T00:00:00Z" },
    privateKey,
  );
  // Swap in key B's iss_key but leave the sig produced by key A's private key.
  const tampered = { ...att, iss_key: iss_key_b };
  const r = verifyFieldCommit(tampered);
  assert.equal(r.valid, false);
});

test("wrong kind is rejected with kind.invalid", () => {
  const { privateKey, iss_key } = newIssuer();
  const att = issueFieldCommit(
    { family: "acr", id: "rcpt-1", field_root: FIELD_ROOT, leaf_count: 4, iss_key, issued_at: "2026-06-01T00:00:00Z" },
    privateKey,
  );
  const tampered = { ...att, kind: "ar.field_commit.v99" };
  const r = verifyFieldCommit(tampered as Parameters<typeof verifyFieldCommit>[0]);
  assert.equal(r.valid, false);
  assert.ok(r.errors.includes("kind.invalid"));
});

test("cross-issuer: sign with key A, set iss_key to key B → invalid", () => {
  const { privateKey: privA, iss_key: issA } = newIssuer();
  const { iss_key: issB } = newIssuer();
  const att = issueFieldCommit(
    { family: "acr", id: "rcpt-cross", field_root: FIELD_ROOT, leaf_count: 4, iss_key: issA, issued_at: "2026-06-01T00:00:00Z" },
    privA,
  );
  // Replace iss_key with B's public key; sig was made with A's private key.
  const tampered = { ...att, iss_key: issB };
  assert.equal(verifyFieldCommit(tampered).valid, false);
});

test("issued_at mutated after sign → invalid", () => {
  const { privateKey, iss_key } = newIssuer();
  const att = issueFieldCommit(
    { family: "acr", id: "rcpt-1", field_root: FIELD_ROOT, leaf_count: 4, iss_key, issued_at: "2026-06-01T00:00:00Z" },
    privateKey,
  );
  const tampered = { ...att, issued_at: "2099-01-01T00:00:00Z" };
  assert.equal(verifyFieldCommit(tampered).valid, false);
});
