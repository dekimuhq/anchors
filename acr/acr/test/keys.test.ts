import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeypair,
  publicKeyFromSeed,
  encodeRaw,
  decodeRaw32,
} from "../src/issue/keys.ts";

test("generateKeypair returns a fresh 32+32 byte keypair", () => {
  const k = generateKeypair("issuer-key-1");
  assert.equal(k.kid, "issuer-key-1");
  assert.equal(k.privateKey.length, 32);
  assert.equal(k.publicKey.length, 32);
});

test("publicKeyFromSeed is deterministic and matches generated pubkey", () => {
  const k = generateKeypair("k1");
  const derived = publicKeyFromSeed(k.privateKey);
  assert.deepEqual([...derived], [...k.publicKey]);
});

test("encodeRaw/decodeRaw32 round-trip a 32-byte key", () => {
  const k = generateKeypair("k1");
  const enc = encodeRaw(k.publicKey);
  const dec = decodeRaw32(enc);
  assert.deepEqual([...dec], [...k.publicKey]);
});

test("generateKeypair rejects empty kid", () => {
  assert.throws(() => generateKeypair(""), /kid required/);
});

test("publicKeyFromSeed rejects non-32-byte seed", () => {
  assert.throws(() => publicKeyFromSeed(new Uint8Array(16)), /32 bytes/);
});

test("decodeRaw32 rejects wrong-length input", () => {
  const short = encodeRaw(new Uint8Array(16));
  assert.throws(() => decodeRaw32(short), /expected 32 bytes/);
});
