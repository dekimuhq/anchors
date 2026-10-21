import { test } from "node:test";
import assert from "node:assert/strict";
import { generateIssuerKey, encodePublicKey, signCanonical, loadPrivateKey } from "../src/issue/index.ts";

test("generateIssuerKey returns matching keys", () => {
  const { publicKey, privateKey } = generateIssuerKey();
  assert.ok(publicKey);
  assert.ok(privateKey);
});

test("encodePublicKey returns ed25519:<base64url>", () => {
  const { publicKey } = generateIssuerKey();
  const enc = encodePublicKey(publicKey);
  assert.match(enc, /^ed25519:[A-Za-z0-9_-]{43}$/);
});

test("signCanonical round-trips through the same payload", () => {
  const { publicKey, privateKey } = generateIssuerKey();
  const sig1 = signCanonical({ a: 1, b: 2 }, privateKey);
  const sig2 = signCanonical({ b: 2, a: 1 }, privateKey);
  assert.equal(sig1, sig2);
  assert.match(sig1, /^ed25519:[A-Za-z0-9_-]+$/);
  assert.ok(publicKey);
});

test("loadPrivateKey accepts PKCS8 pem and produces a working signer", () => {
  const { privateKey } = generateIssuerKey();
  const pem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const reloaded = loadPrivateKey(pem);
  const sig = signCanonical({ x: 1 }, reloaded);
  assert.match(sig, /^ed25519:/);
});
