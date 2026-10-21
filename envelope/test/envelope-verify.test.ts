/**
 * Tests for verifyEnvelopeSignature + isKnownClaimType + rejectUnknownFields
 * — Phase A Task 4.
 *
 * Covers:
 *   1.  Accept a freshly-signed envelope (sign then verify → true).
 *   2.  Reject tampered body post-sign (body mutated → false).
 *   3.  Ignore signed-out field mutations (anchor/countersig post-mutated → true).
 *   4.  Reject credentialStatus mutation post-sign (signed-in field → false).
 *   5.  Reject empty sig ("" → false, no exception).
 *   6.  Reject wrong-length sig (decodes to <64 bytes → false, no exception).
 *   7.  Reject malformed sig (non-base64url chars → false, no exception).
 *   8.  isKnownClaimType: all 21 members true; unknown + random false.
 *   9.  rejectUnknownFields: null on a valid envelope record.
 *   10. rejectUnknownFields: "unknown_field:foo" on stray key.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import type { Envelope, AnchorProof, CredentialStatus } from "../src/envelope-types.ts";
import { CLAIM_TYPES } from "../src/envelope-types.ts";
import { signEnvelope, verifyEnvelopeSignature, isKnownClaimType, rejectUnknownFields } from "../src/envelope.ts";

// ── Fixture helpers ───────────────────────────────────────────────────────────

const ANCHOR_FIXTURE: AnchorProof = {
  log: "https://verify.dekimu.com/apr/v1",
  leaf_index: 0,
  inclusion_proof: ["sha256:aabbcc"],
  tree_head_root: "sha256:deadbeef",
  tree_size: 1,
  log_time: "2026-05-17T00:00:00Z",
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
    id: "01HZ0000000000000000000099",
    iat: "2026-05-17T00:00:00Z",
    claim_type: "ar.consent.v1",
    iss: "did:key:z6MkTestIssuer",
    iss_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    subject: "did:key:z6MkTestSubject",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: STATUS_FIXTURE,
    anchor: ANCHOR_FIXTURE,
    sig: "",
    countersig: null,
    body: { op: "grant", scope: "read" },
  };
  return { ...base, ...overrides };
}

// ── Test 1: Accept freshly-signed envelope ────────────────────────────────────

test("verifyEnvelopeSignature returns true for freshly-signed envelope", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const e = makeEnvelope();
  const signed = await signEnvelope(e, privateKey);

  const pubDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const result = verifyEnvelopeSignature(signed, new Uint8Array(pubDer));

  assert.strictEqual(result, true, "verify must return true for a freshly-signed envelope");
});

// ── Test 2: Reject tampered body post-sign ────────────────────────────────────

test("verifyEnvelopeSignature returns false when body is mutated after signing", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const e = makeEnvelope();
  const signed = await signEnvelope(e, privateKey);

  // Mutate body post-sign
  const tampered: Envelope = { ...signed, body: { op: "grant", scope: "write" } };

  const pubDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const result = verifyEnvelopeSignature(tampered, new Uint8Array(pubDer));

  assert.strictEqual(result, false, "verify must return false when body is tampered");
});

// ── Test 3: Ignore signed-out field mutations ─────────────────────────────────
// anchor and countersig are zeroed in preSigCanonical — mutating them post-sign
// must NOT invalidate the signature.

test("verifyEnvelopeSignature returns true when signed-out fields (anchor, countersig) are mutated post-sign", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  // Sign with anchor=null, countersig=null (null is their zeroed value, same as canonical)
  const e = makeEnvelope({ anchor: ANCHOR_FIXTURE, countersig: null });
  const signed = await signEnvelope(e, privateKey);

  // Now "set" anchor and countersig post-sign — these should be ignored by verifier
  const mutated: Envelope = {
    ...signed,
    anchor: { ...ANCHOR_FIXTURE, leaf_index: 999 },
    countersig: "some-countersig-b64url",
  };

  const pubDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const result = verifyEnvelopeSignature(mutated, new Uint8Array(pubDer));

  assert.strictEqual(result, true, "signed-out field mutations must not invalidate the signature");
});

// ── Test 4: Reject credentialStatus mutation post-sign ────────────────────────
// credentialStatus is SIGNED-IN — mutating it post-sign must invalidate.

test("verifyEnvelopeSignature returns false when credentialStatus is mutated after signing", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const e = makeEnvelope({ credentialStatus: STATUS_FIXTURE });
  const signed = await signEnvelope(e, privateKey);

  // Mutate statusListIndex post-sign
  const mutated: Envelope = {
    ...signed,
    credentialStatus: { ...STATUS_FIXTURE, statusListIndex: "9999" },
  };

  const pubDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const result = verifyEnvelopeSignature(mutated, new Uint8Array(pubDer));

  assert.strictEqual(result, false, "verify must return false when credentialStatus is mutated");
});

// ── Test 5: Reject empty sig ──────────────────────────────────────────────────

test("verifyEnvelopeSignature returns false (no exception) when sig is empty string", () => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const e = makeEnvelope({ sig: "" });

  const pubDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;

  assert.doesNotThrow(() => {
    const result = verifyEnvelopeSignature(e, new Uint8Array(pubDer));
    assert.strictEqual(result, false, "empty sig must return false");
  });
});

// ── Test 6: Reject wrong-length sig ──────────────────────────────────────────
// "AAAA" decodes to 3 bytes, not 64.

test("verifyEnvelopeSignature returns false (no exception) when sig decodes to fewer than 64 bytes", () => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const e = makeEnvelope({ sig: "AAAA" });

  const pubDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;

  assert.doesNotThrow(() => {
    const result = verifyEnvelopeSignature(e, new Uint8Array(pubDer));
    assert.strictEqual(result, false, "wrong-length sig must return false");
  });
});

// ── Test 7: Reject malformed sig (non-base64url characters) ──────────────────

test("verifyEnvelopeSignature returns false (no exception) when sig contains non-base64url characters", () => {
  const { publicKey } = generateKeyPairSync("ed25519");
  const e = makeEnvelope({ sig: "@@@" });

  const pubDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;

  assert.doesNotThrow(() => {
    const result = verifyEnvelopeSignature(e, new Uint8Array(pubDer));
    assert.strictEqual(result, false, "malformed sig must return false");
  });
});

// ── Test 8: isKnownClaimType ──────────────────────────────────────────────────

test("isKnownClaimType returns true for all 21 active members, false for unknown", () => {
  // All 20 active members must return true
  for (const ct of CLAIM_TYPES) {
    assert.strictEqual(isKnownClaimType(ct), true, `${ct} should be recognized`);
  }

  // Random strings / future hypothetical not in the union
  assert.strictEqual(isKnownClaimType("ar.unknown.v1"), false, "ar.unknown.v1 must return false");
  assert.strictEqual(isKnownClaimType("random.string"), false, "random string must return false");
  assert.strictEqual(isKnownClaimType(""), false, "empty string must return false");
});

// ── Test 9: rejectUnknownFields returns null for a valid envelope record ──────

test("rejectUnknownFields returns null when all keys are in the allowed set", () => {
  const e = makeEnvelope() as unknown as Record<string, unknown>;
  const result = rejectUnknownFields(e);
  assert.strictEqual(result, null, "valid envelope must return null from rejectUnknownFields");
});

// ── Test 10: rejectUnknownFields returns error string for stray key ───────────

test('rejectUnknownFields returns "unknown_field:foo" for a stray top-level key', () => {
  const record: Record<string, unknown> = { v: 2, foo: "bar" };
  const result = rejectUnknownFields(record);
  assert.strictEqual(result, "unknown_field:foo", "stray key must produce unknown_field:<name>");
});

// ── Test 11: countersig_key is accepted by rejectUnknownFields ───────────────

test("rejectUnknownFields accepts countersig_key as a known field", () => {
  const e = { ...makeEnvelope(), countersig_key: "ed25519:AAAA" } as unknown as Record<string, unknown>;
  const result = rejectUnknownFields(e);
  assert.strictEqual(result, null, "countersig_key must be accepted as a known field");
});

// ── Test 12: countersig_key is signed-in — mutating it invalidates sig ───────

test("verifyEnvelopeSignature returns false when countersig_key is mutated after signing", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const e = makeEnvelope({ countersig_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } as Partial<Envelope>);
  const signed = await signEnvelope(e, privateKey);

  // Mutate countersig_key post-sign — this should invalidate the signature
  // because countersig_key is signed-in (not in SIGNED_OUT_FIELDS).
  const tampered = { ...signed, countersig_key: "ed25519:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" };

  const pubDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const result = verifyEnvelopeSignature(tampered as Envelope, new Uint8Array(pubDer));

  assert.strictEqual(result, false, "countersig_key mutation must invalidate the signature (signed-in field)");
});

// ── Test 13: countersig_key presence does not break existing verification ────

test("verifyEnvelopeSignature returns true when countersig_key is set at sign time and unchanged", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const e = makeEnvelope({ countersig_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" } as Partial<Envelope>);
  const signed = await signEnvelope(e, privateKey);

  const pubDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const result = verifyEnvelopeSignature(signed, new Uint8Array(pubDer));

  assert.strictEqual(result, true, "envelope with countersig_key must verify when unchanged");
});

// ── Test 14: rejectUnknownFields accepts incl ─────────────────────────────────

test("rejectUnknownFields accepts incl as a known top-level field", () => {
  const result = rejectUnknownFields({ v: 2, incl: { log_id: "L", leaf: "sha256:00" } });
  assert.strictEqual(result, null, "incl must be accepted as a known top-level field");
});
