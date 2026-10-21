/**
 * Offline issuer-key resolver tests.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  generateKeypair,
  generateMlDsaKeypair,
  encodeMlDsaIssKey,
  base64UrlEncode,
  MLDSA65_PUBKEY_BYTES,
} from "@dekimuhq/anchors-envelope";
import {
  derFromFingerprint,
  rawFromMlDsaFingerprint,
  keyBytesFromFingerprint,
  selfCertifyingResolveKey,
  makeTrustedKeysResolveKey,
} from "../src/resolve-key.ts";

const kp = generateKeypair("resolve-key-test");
const fingerprint = `ed25519:${base64UrlEncode(kp.publicKey)}`;

// ML-DSA-65 keygen needs Node ≥24.6 — these run green on the v1.3 CI floor.
const mlKp = generateMlDsaKeypair("resolve-key-mldsa-test");
const mlFingerprint = encodeMlDsaIssKey(mlKp.publicKeyRaw);

test("derFromFingerprint: valid ed25519 fingerprint -> 44-byte SPKI DER", () => {
  const der = derFromFingerprint(fingerprint);
  assert.ok(der !== null);
  assert.equal(der.length, 44); // 12-byte SPKI prefix + 32-byte key
  // Tail must equal the raw public key.
  assert.deepEqual(der.slice(12), kp.publicKey);
});

test("derFromFingerprint: non-ed25519 algorithm -> null", () => {
  assert.equal(derFromFingerprint("ml-dsa-65:AAAA"), null);
});

test("derFromFingerprint: malformed base64 -> null", () => {
  assert.equal(derFromFingerprint("ed25519:!!!not-base64!!!"), null);
});

test("derFromFingerprint: wrong key length -> null", () => {
  assert.equal(derFromFingerprint(`ed25519:${base64UrlEncode(new Uint8Array(16))}`), null);
});

test("selfCertifyingResolveKey: reads envelope.iss_key", () => {
  const der = selfCertifyingResolveKey({ iss_key: fingerprint });
  assert.ok(der !== null);
  assert.deepEqual(der.slice(12), kp.publicKey);
});

test("selfCertifyingResolveKey: missing/non-object -> null", () => {
  assert.equal(selfCertifyingResolveKey({}), null);
  assert.equal(selfCertifyingResolveKey(null), null);
  assert.equal(selfCertifyingResolveKey("nope"), null);
});

test("makeTrustedKeysResolveKey: resolves only allowlisted fingerprints", () => {
  const resolve = makeTrustedKeysResolveKey(new Set([fingerprint]));
  assert.ok(resolve({ iss_key: fingerprint }) !== null);
});

test("makeTrustedKeysResolveKey: rejects unknown fingerprint -> null", () => {
  const other = `ed25519:${base64UrlEncode(generateKeypair("other").publicKey)}`;
  const resolve = makeTrustedKeysResolveKey(new Set([fingerprint]));
  assert.equal(resolve({ iss_key: other }), null);
});

// ── ML-DSA-65 (v1.3 rollout R2) ──────────────────────────────────────────────

test("rawFromMlDsaFingerprint: valid ml-dsa-65 fingerprint -> 1952-byte raw key", () => {
  const raw = rawFromMlDsaFingerprint(mlFingerprint);
  assert.ok(raw !== null);
  assert.equal(raw.length, MLDSA65_PUBKEY_BYTES);
  assert.deepEqual(raw, mlKp.publicKeyRaw);
});

test("rawFromMlDsaFingerprint: ed25519 algorithm -> null", () => {
  assert.equal(rawFromMlDsaFingerprint(fingerprint), null);
});

test("rawFromMlDsaFingerprint: malformed base64 -> null", () => {
  assert.equal(rawFromMlDsaFingerprint("ml-dsa-65:!!!not-base64!!!"), null);
});

test("rawFromMlDsaFingerprint: wrong key length -> null", () => {
  assert.equal(rawFromMlDsaFingerprint(`ml-dsa-65:${base64UrlEncode(new Uint8Array(1951))}`), null);
});

test("keyBytesFromFingerprint: dispatches ed25519 -> 44-byte SPKI DER, ml-dsa-65 -> 1952 raw", () => {
  const der = keyBytesFromFingerprint(fingerprint);
  assert.ok(der !== null);
  assert.equal(der.length, 44);
  const raw = keyBytesFromFingerprint(mlFingerprint);
  assert.ok(raw !== null);
  assert.equal(raw.length, MLDSA65_PUBKEY_BYTES);
});

test("keyBytesFromFingerprint: unregistered algorithm -> null", () => {
  assert.equal(keyBytesFromFingerprint("slh-dsa-sha2-128s:AAAA"), null);
});

test("selfCertifyingResolveKey: reads ml-dsa-65 iss_key -> 1952 raw", () => {
  const raw = selfCertifyingResolveKey({ iss_key: mlFingerprint });
  assert.ok(raw !== null);
  assert.deepEqual(raw, mlKp.publicKeyRaw);
});

test("makeTrustedKeysResolveKey: resolves allowlisted ml-dsa-65 fingerprint", () => {
  const resolve = makeTrustedKeysResolveKey(new Set([mlFingerprint]));
  const raw = resolve({ iss_key: mlFingerprint });
  assert.ok(raw !== null);
  assert.equal(raw.length, MLDSA65_PUBKEY_BYTES);
});
