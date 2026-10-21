import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeypair,
  publicKeyFromSeed,
  encodeRaw,
  decodeRaw32,
  signCanonical,
  verifyCanonical,
  type Keypair,
} from "../src/ed25519.ts";

test("generateKeypair returns 32-byte Ed25519 keys with kid", () => {
  const kp = generateKeypair("test-kid");
  assert.equal(kp.kid, "test-kid");
  assert.equal(kp.privateKey.length, 32);
  assert.equal(kp.publicKey.length, 32);
});

test("generateKeypair rejects empty kid", () => {
  assert.throws(() => generateKeypair(""), /kid required/);
});

test("publicKeyFromSeed derives same public key as generateKeypair", () => {
  const kp = generateKeypair("derive-test");
  const derived = publicKeyFromSeed(kp.privateKey);
  assert.deepEqual(Array.from(derived), Array.from(kp.publicKey));
});

test("publicKeyFromSeed rejects non-32-byte seed", () => {
  assert.throws(() => publicKeyFromSeed(new Uint8Array(16)), /32 bytes/);
});

test("encodeRaw + decodeRaw32 round-trip", () => {
  const kp = generateKeypair("roundtrip");
  const encoded = encodeRaw(kp.publicKey);
  const decoded = decodeRaw32(encoded);
  assert.deepEqual(Array.from(decoded), Array.from(kp.publicKey));
});

test("decodeRaw32 rejects wrong-length input", () => {
  assert.throws(() => decodeRaw32(encodeRaw(new Uint8Array(16))), /expected 32 bytes/);
});

test("signCanonical signs JCS-canonicalized body, round-trips via verifyCanonical", () => {
  const kp = generateKeypair("sign-test");
  const body = { z: 1, a: 2, nested: { b: 3, a: 4 } };
  const sig = signCanonical(body, kp.privateKey);
  assert.ok(sig instanceof Uint8Array);
  assert.equal(sig.length, 64); // Ed25519 signature is always 64 bytes
  assert.equal(verifyCanonical(body, sig, kp.publicKey), true);
});

test("verifyCanonical rejects tampered body", () => {
  const kp = generateKeypair("tamper");
  const sig = signCanonical({ a: 1 }, kp.privateKey);
  assert.equal(verifyCanonical({ a: 2 }, sig, kp.publicKey), false);
});

test("verifyCanonical is canonicalization-stable across key reordering", () => {
  const kp = generateKeypair("stable");
  const sig = signCanonical({ a: 1, b: 2 }, kp.privateKey);
  assert.equal(verifyCanonical({ b: 2, a: 1 }, sig, kp.publicKey), true);
});

test("signCanonical rejects non-32-byte private key", () => {
  assert.throws(() => signCanonical({ a: 1 }, new Uint8Array(16)), /32 bytes/);
});
