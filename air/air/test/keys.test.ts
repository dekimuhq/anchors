/**
 * Tests for keys.ts — generate / encode / signCanonical round-trip.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { verify as nodeVerify, createPublicKey } from "node:crypto";
import { canonicalize, base64UrlDecode } from "@dekimuhq/anchors-envelope";
import {
  generateIssuerKey,
  encodePublicKey,
  signCanonical,
  loadPrivateKey,
} from "../src/issue/keys.ts";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

test("keys K1: generateIssuerKey returns a usable Ed25519 keypair", () => {
  const { publicKey, privateKey } = generateIssuerKey();
  assert.equal(publicKey.asymmetricKeyType, "ed25519");
  assert.equal(privateKey.asymmetricKeyType, "ed25519");
});

test("keys K2: encodePublicKey emits the ed25519:<base64url> prefix", () => {
  const { publicKey } = generateIssuerKey();
  const enc = encodePublicKey(publicKey);
  assert.ok(enc.startsWith("ed25519:"));
  const raw = base64UrlDecode(enc.replace(/^ed25519:/, ""));
  assert.equal(raw.length, 32);
});

test("keys K3: signCanonical round-trips against the public key", () => {
  const { publicKey, privateKey } = generateIssuerKey();
  const payload = { kind: "air.test", n: 1 };
  const sig = signCanonical(payload, privateKey);
  assert.ok(sig.startsWith("ed25519:"));
  const sigRaw = base64UrlDecode(sig.replace(/^ed25519:/, ""));
  const msg = new TextEncoder().encode(canonicalize(payload));
  assert.equal(
    nodeVerify(null, msg, publicKey, Buffer.from(sigRaw)),
    true,
  );
});

test("keys K4: loadPrivateKey resolves a PKCS#8 PEM", () => {
  const { privateKey } = generateIssuerKey();
  const pem = (privateKey.export({ format: "pem", type: "pkcs8" }) as string);
  const re = loadPrivateKey(pem);
  assert.equal(re.asymmetricKeyType, "ed25519");
});

test("keys K5: encoded public key resolves back to the same SPKI bytes", () => {
  const { publicKey } = generateIssuerKey();
  const enc = encodePublicKey(publicKey);
  const raw = base64UrlDecode(enc.replace(/^ed25519:/, ""));
  const pub = createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]),
    format: "der",
    type: "spki",
  });
  const enc2 = encodePublicKey(pub);
  assert.equal(enc, enc2);
});
