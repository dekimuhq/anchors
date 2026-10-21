/**
 * Tests for envelope canonicalize + signEnvelope — Phase A Task 3.
 *
 * Covers:
 *   1. preSigCanonical zeroes the 4 signed-out fields, retains credentialStatus.
 *   2. signEnvelope round-trips with Ed25519 (sig is non-empty, 64 bytes decoded).
 *   3. Determinism: sign same envelope twice → byte-equal sigs.
 *   4. Key-order independence: JCS canonicalisation sorts keys, sigs are byte-equal.
 *   5. canonicalize(e) returns UTF-8 bytes that reproduce preSigCanonical output.
 *   6. signEnvelope populates sig and keeps all other fields intact.
 *   7. preSigCanonical is stable (calling twice gives byte-equal output).
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import type { Envelope, AnchorProof, CredentialStatus } from "../src/envelope-types.ts";
import { preSigCanonical, canonicalizeEnvelope, signEnvelope, verifyEnvelopeSignature } from "../src/envelope.ts";
import { base64UrlDecode } from "../src/base64url.ts";

// ── Fixture helpers ───────────────────────────────────────────────────────────

const ANCHOR_FIXTURE: AnchorProof = {
  log: "https://verify.dekimu.com/apr/v1",
  leaf_index: 0,
  inclusion_proof: ["sha256:aabbcc"],
  tree_head_root: "sha256:deadbeef",
  tree_size: 1,
  log_time: "2026-05-16T14:00:00Z",
};

const STATUS_FIXTURE: CredentialStatus = {
  id: "https://verify.dekimu.com/status/1#42",
  type: "StatusList2021Entry",
  statusPurpose: "revocation",
  statusListIndex: "42",
  statusListCredential: "https://verify.dekimu.com/status/1",
};

function makeEnvelope(overrides: Partial<Envelope> = {}): Envelope {
  const base: Envelope = {
    v: 2,
    id: "01HZ0000000000000000000000",
    iat: "2026-05-16T14:00:00Z",
    claim_type: "ar.consent.v1",
    iss: "did:key:z6MkTestIssuer",
    iss_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    subject: "did:key:z6MkTestSubject",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: {
      v: 1,
      tsr: "AQIDBA==",
      alg: "sha-256",
      tsa_url: "https://freetsa.org/tsr",
      tsa_cert_chain_sha256: ["sha256:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"],
      issued_at: "2026-05-16T14:00:00Z",
    },
    credentialStatus: STATUS_FIXTURE,
    anchor: ANCHOR_FIXTURE,
    sig: "placeholder-sig",
    countersig: "placeholder-countersig",
    body: { hello: 1 },
  };
  return { ...base, ...overrides };
}

// ── Test 1: preSigCanonical zeroes 4 signed-out fields, retains credentialStatus ─

test("preSigCanonical zeroes anchor/sig/countersig/tsa, retains credentialStatus", () => {
  const e = makeEnvelope();
  const canonical = preSigCanonical(e);
  const parsed = JSON.parse(canonical) as Record<string, unknown>;

  assert.strictEqual(parsed["anchor"], null, "anchor must be null in pre-sig form");
  assert.strictEqual(parsed["sig"], null, "sig must be null in pre-sig form");
  assert.strictEqual(parsed["countersig"], null, "countersig must be null in pre-sig form");
  assert.strictEqual(parsed["tsa"], null, "tsa must be null in pre-sig form");

  // credentialStatus is SIGNED-IN — must be retained
  assert.ok(parsed["credentialStatus"] !== null, "credentialStatus must be retained");
  const cs = parsed["credentialStatus"] as Record<string, unknown>;
  assert.strictEqual(cs["statusListIndex"], "42", "credentialStatus.statusListIndex must be intact");
});

// ── Test 2: signEnvelope round-trips with Ed25519 ────────────────────────────

test("signEnvelope produces 64-byte Ed25519 signature", async () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const e = makeEnvelope();

  const signed = await signEnvelope(e, privateKey);

  assert.ok(typeof signed.sig === "string", "sig must be a string");
  assert.ok(signed.sig.length > 0, "sig must be non-empty");

  const sigBytes = base64UrlDecode(signed.sig);
  assert.strictEqual(sigBytes.length, 64, "Ed25519 signature must be 64 bytes");
});

// ── Test 3: Determinism — sign same envelope twice → byte-equal sigs ─────────

test("signEnvelope is deterministic: same key + same input → byte-equal sig", async () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const e = makeEnvelope();

  const signed1 = await signEnvelope(e, privateKey);
  const signed2 = await signEnvelope(e, privateKey);

  assert.strictEqual(signed1.sig, signed2.sig, "signatures must be byte-equal on repeated sign");
});

// ── Test 4: Key-order independence — JCS sorts keys ──────────────────────────

test("signEnvelope is key-order independent: envelopes with same data but different insertion order produce equal sigs", async () => {
  const { privateKey } = generateKeyPairSync("ed25519");

  // Two envelopes with body objects whose keys appear in different insertion order.
  const e1 = makeEnvelope({ body: { z: 1, a: 2 } });
  const e2 = makeEnvelope({ body: { a: 2, z: 1 } });

  const signed1 = await signEnvelope(e1, privateKey);
  const signed2 = await signEnvelope(e2, privateKey);

  assert.strictEqual(
    signed1.sig,
    signed2.sig,
    "JCS must sort keys — different insertion order must produce equal sigs",
  );
});

// ── Test 5: canonicalizeEnvelope(e) returns UTF-8 bytes matching preSigCanonical ─────

test("canonicalizeEnvelope(e) returns UTF-8 bytes that reproduce preSigCanonical output", () => {
  const e = makeEnvelope();

  const bytes = canonicalizeEnvelope(e);
  assert.ok(bytes instanceof Uint8Array, "canonicalizeEnvelope must return Uint8Array");

  const decoded = new TextDecoder().decode(bytes);
  assert.strictEqual(decoded, preSigCanonical(e), "decoded bytes must equal preSigCanonical output");
});

// ── Test 6: signEnvelope populates sig and keeps all other fields intact ─────

test("signEnvelope sets sig field and does not mutate other fields", async () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const e = makeEnvelope();

  const signed = await signEnvelope(e, privateKey);

  // sig is now real — not the placeholder
  assert.notStrictEqual(signed.sig, "placeholder-sig", "sig must be replaced");

  // All other fields unchanged
  assert.strictEqual(signed.v, e.v);
  assert.strictEqual(signed.id, e.id);
  assert.strictEqual(signed.iat, e.iat);
  assert.strictEqual(signed.claim_type, e.claim_type);
  assert.strictEqual(signed.countersig, e.countersig, "countersig must be untouched");
  assert.deepStrictEqual(signed.anchor, e.anchor, "anchor must be untouched");
  assert.deepStrictEqual(signed.credentialStatus, e.credentialStatus, "credentialStatus must be untouched");
  assert.deepStrictEqual(signed.body, e.body, "body must be untouched");
});

// ── Test 7: preSigCanonical stability ─────────────────────────────────────────

test("preSigCanonical is stable: calling twice on the same envelope produces identical output", () => {
  const e = makeEnvelope();

  const out1 = preSigCanonical(e);
  const out2 = preSigCanonical(e);

  assert.strictEqual(out1, out2, "preSigCanonical must be stable");
});

// ── Test 8: incl is signed-out ────────────────────────────────────────────────
// incl is signed-out — attaching it after signing must not invalidate the sig.

test("incl is signed-out: adding it after signing keeps the sig valid", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signed = await signEnvelope(makeEnvelope(), privateKey);
  const withIncl = {
    ...signed,
    incl: { log_id: "L", leaf: "sha256:00", promise: { timestamp: "2026-01-01T00:00:00Z", sig: "AAAA" } },
  };
  const pubDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  assert.strictEqual(verifyEnvelopeSignature(withIncl as unknown as Envelope, new Uint8Array(pubDer)), true);
});
