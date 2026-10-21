/**
 * v1.3 issuer-kit ML-DSA-65 minting + seed serialization.
 *
 * Spec:     https://github.com/dekimuhq/anchors-spec/blob/main/rfcs/RFC-001-sig-alg-discriminator.md
 * Decision: an internal design record (not published)
 *
 * Provider: native node:crypto on Node ≥24.6 (OpenSSL 3.5, nodejs/node#59259).
 * REQUIRES Node ≥24.6; on older runtimes ml-dsa keygen throws and the suite
 * fails loudly rather than silently skipping (the floor is enforced).
 *
 * Two halves:
 *   A) Seed serialization — node:crypto cannot reconstruct an ML-DSA private
 *      key from the 32-byte seed alone (seed-only JWK import throws); the
 *      persisted secret carries seed + 1952-byte raw public key. Round-trips +
 *      malformation rejection.
 *   B) buildMintV2 PQC path — minting with `mlDsaKey` sets `sig_alg`
 *      (signed-in), derives the `ml-dsa-65:` iss_key, and produces a receipt
 *      that verifies; the XOR key gate; the Ed25519 path stays byte-equal.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import * as crypto from "node:crypto";

import {
  generateMlDsaKeypair,
  toMlDsaSecret,
  seedFromPrivateKey,
  privateKeyFromSecret,
  serializeMlDsaSecret,
  deserializeMlDsaSecret,
  signMlDsaCanonical,
  verifyMlDsaCanonical,
  encodeMlDsaIssKey,
  MLDSA65_SEED_BYTES,
  MLDSA65_PUBKEY_BYTES,
} from "../src/ml-dsa.ts";
import { keyObjectFromMlDsaSecret } from "../src/mint-helpers.ts";
import {
  buildMintV2,
  type FamilyMintPredicates,
  type FamilyMintV2Input,
} from "../src/family-mint-pipeline.ts";
import { defineFamily, type BodyValidator } from "../src/define-family.ts";
import { verifyEnvelopeSignature } from "../src/envelope.ts";
import type { AnchorProof, ClaimType } from "../src/envelope-types.ts";
import { generateKeypair } from "../src/ed25519.ts";

// ── A. Seed serialization ─────────────────────────────────────────────────────

test("generateMlDsaKeypair returns a 32-byte seed alongside the 1952-byte pub", () => {
  const kp = generateMlDsaKeypair("kid-seed");
  assert.equal(kp.seed.length, MLDSA65_SEED_BYTES);
  assert.equal(kp.publicKeyRaw.length, MLDSA65_PUBKEY_BYTES);
  // The reported seed matches what the KeyObject yields.
  assert.deepEqual([...kp.seed], [...seedFromPrivateKey(kp.privateKey)]);
});

test("privateKeyFromSecret reconstructs a signing key that verifies under the original pub", () => {
  const kp = generateMlDsaKeypair("kid-recon");
  const secret = toMlDsaSecret(kp);

  const reborn = privateKeyFromSecret(secret);
  const sig = signMlDsaCanonical({ msg: "hello" }, reborn);
  // Verifies against the ORIGINAL public key — proves the seed reconstructed
  // the exact keypair, not a fresh one.
  assert.equal(verifyMlDsaCanonical({ msg: "hello" }, sig, kp.publicKeyRaw), true);
});

test("serialize → deserialize round-trips the secret byte-for-byte", () => {
  const kp = generateMlDsaKeypair("kid-string");
  const secret = toMlDsaSecret(kp);

  const s = serializeMlDsaSecret(secret);
  assert.ok(s.startsWith("ml-dsa-65-sk:"));

  const back = deserializeMlDsaSecret(s);
  assert.deepEqual([...back.seed], [...secret.seed]);
  assert.deepEqual([...back.publicKeyRaw], [...secret.publicKeyRaw]);

  // And the deserialized secret still signs+verifies.
  const sig = signMlDsaCanonical({ x: 1 }, privateKeyFromSecret(back));
  assert.equal(verifyMlDsaCanonical({ x: 1 }, sig, kp.publicKeyRaw), true);
});

test("deserializeMlDsaSecret rejects malformed inputs", () => {
  const kp = generateMlDsaKeypair("kid-bad");
  const good = serializeMlDsaSecret(toMlDsaSecret(kp));

  assert.throws(() => deserializeMlDsaSecret("ed25519:abc"), /missing 'ml-dsa-65-sk:' prefix/);
  assert.throws(() => deserializeMlDsaSecret("ml-dsa-65-sk:onlyonepart"), /expected '<seed>\.<pub>'/);
  // Swap seed and pub halves → both length checks fail (seed too long).
  const [seedB64, pubB64] = good.slice("ml-dsa-65-sk:".length).split(".");
  assert.throws(
    () => deserializeMlDsaSecret(`ml-dsa-65-sk:${pubB64}.${seedB64}`),
    /seed must be 32 bytes/,
  );
});

test("privateKeyFromSecret rejects a length-valid but MISMATCHED seed+pub", () => {
  const a = generateMlDsaKeypair("kid-mismatch-a");
  const b = generateMlDsaKeypair("kid-mismatch-b");
  // seed from A, pub from B — both correct length, but unrelated.
  assert.throws(
    () => privateKeyFromSecret({ seed: a.seed, publicKeyRaw: b.publicKeyRaw }),
    /seed does not correspond to publicKeyRaw/,
  );
});

test("seedFromPrivateKey rejects a non-ml-dsa key", () => {
  const ed = generateKeypair("ed-key");
  const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
  const edKeyObj = crypto.createPrivateKey({
    key: Buffer.concat([PKCS8, Buffer.from(ed.privateKey)]),
    format: "der",
    type: "pkcs8",
  });
  assert.throws(() => seedFromPrivateKey(edKeyObj), /not ml-dsa-65/);
});

test("keyObjectFromMlDsaSecret yields a signing key + ml-dsa-65 iss_key", () => {
  const kp = generateMlDsaKeypair("kid-helper");
  const { privateKey, issKey } = keyObjectFromMlDsaSecret(toMlDsaSecret(kp));
  assert.equal(issKey, encodeMlDsaIssKey(kp.publicKeyRaw));
  const sig = signMlDsaCanonical({ a: 1 }, privateKey);
  assert.equal(verifyMlDsaCanonical({ a: 1 }, sig, kp.publicKeyRaw), true);
});

// ── B. buildMintV2 PQC path ────────────────────────────────────────────────────

const ANCHOR: AnchorProof = {
  log: "https://verify.dekimu.com/apr/v1",
  leaf_index: 0,
  inclusion_proof: ["sha256:aabbcc"],
  tree_head_root: "sha256:deadbeef",
  tree_size: 1,
  log_time: "2026-05-19T00:00:00Z",
};

interface TestBody {
  kind: string;
  events: unknown[];
}

const testBodySchema: BodyValidator<TestBody> = {
  validate(body) {
    if (
      typeof body === "object" &&
      body !== null &&
      "kind" in body &&
      "events" in body &&
      Array.isArray((body as { events: unknown }).events)
    ) {
      return { ok: true, value: body as TestBody };
    }
    return { ok: false, reason: "body.schema_invalid" };
  },
};

function aprFamilyManifest() {
  return defineFamily({
    acronym: "APR",
    name: "Agent Provenance Receipts",
    claim_types: ["ar.provenance.v1"] satisfies readonly ClaimType[],
    spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/apr",
    chip: 1,
    status_list_slot: null,
    subject_presence: "must-be-present",
    tsa_upgrade_path: "free",
    body_schema: testBodySchema,
  });
}

function toMintPredicates<B>(
  family: ReturnType<typeof defineFamily<B>>,
): FamilyMintPredicates<B> {
  return {
    meta: family.meta,
    validateBody: (b) => family.validateBody(b),
    checkSubjectPresence: (s, b) => family.checkSubjectPresence(s, b),
    isOwnedClaimType: (ct) => family.isOwnedClaimType(ct),
  };
}

const VALID_BODY = { kind: "ar.provenance.v1", events: [] };

function pqcInput(
  kpSecret: ReturnType<typeof toMlDsaSecret>,
  overrides: Partial<FamilyMintV2Input> = {},
): FamilyMintV2Input {
  return {
    body: VALID_BODY,
    mlDsaKey: kpSecret,
    issuerDid: "did:web:pqc.example.com",
    subject: "sha256:aabbccddeeff",
    anchor: ANCHOR,
    ...overrides,
  };
}

test("§B mint with mlDsaKey → sig_alg set, ml-dsa-65 iss_key, receipt verifies", async () => {
  const kp = generateMlDsaKeypair("kid-mint");
  const family = aprFamilyManifest();
  const mint = buildMintV2(toMintPredicates(family));

  const env = await mint(pqcInput(toMlDsaSecret(kp)));

  assert.equal(env.sig_alg, "ml-dsa-65");
  assert.equal(env.iss_key, encodeMlDsaIssKey(kp.publicKeyRaw));
  assert.ok(env.iss_key.startsWith("ml-dsa-65:"));
  assert.ok(typeof env.sig === "string" && env.sig.length > 0);
  // End-to-end: dispatches on sig_alg → ml-dsa verifier → valid.
  assert.equal(verifyEnvelopeSignature(env, kp.publicKeyRaw), true);
});

test("§B tampering a minted ml-dsa receipt fails verification", async () => {
  const kp = generateMlDsaKeypair("kid-tamper");
  const mint = buildMintV2(toMintPredicates(aprFamilyManifest()));
  const env = await mint(pqcInput(toMlDsaSecret(kp)));

  const tampered = { ...env, body: { kind: "ar.provenance.v1", events: [{ evil: 1 }] } };
  assert.equal(verifyEnvelopeSignature(tampered, kp.publicKeyRaw), false);
});

test("§B XOR key gate — providing both issuerPrivateKey and mlDsaKey throws", async () => {
  const kp = generateMlDsaKeypair("kid-both");
  const ed = generateKeypair("ed-both");
  const mint = buildMintV2(toMintPredicates(aprFamilyManifest()));

  await assert.rejects(
    mint(pqcInput(toMlDsaSecret(kp), { issuerPrivateKey: ed.privateKey })),
    /exactly one of issuerPrivateKey .* or mlDsaKey/,
  );
});

test("§B providing neither key throws the Ed25519 gate", async () => {
  const mint = buildMintV2(toMintPredicates(aprFamilyManifest()));
  await assert.rejects(
    // Neither issuerPrivateKey nor mlDsaKey.
    mint({
      body: VALID_BODY,
      issuerDid: "did:web:none.example.com",
      subject: "sha256:aabbccddeeff",
      anchor: ANCHOR,
    } as FamilyMintV2Input),
    /issuerPrivateKey must be a 32-byte Ed25519 seed/,
  );
});

test("§B malformed mlDsaKey (short seed) throws before any crypto", async () => {
  const kp = generateMlDsaKeypair("kid-short");
  const mint = buildMintV2(toMintPredicates(aprFamilyManifest()));
  await assert.rejects(
    mint(pqcInput({ seed: kp.seed.subarray(0, 16), publicKeyRaw: kp.publicKeyRaw })),
    /mlDsaKey requires a 32-byte seed and 1952-byte publicKeyRaw/,
  );
});

test("§B mint with a mismatched seed+pub secret throws (no dead-on-arrival receipt)", async () => {
  const a = generateMlDsaKeypair("kid-mint-mismatch-a");
  const b = generateMlDsaKeypair("kid-mint-mismatch-b");
  const mint = buildMintV2(toMintPredicates(aprFamilyManifest()));
  await assert.rejects(
    mint(pqcInput({ seed: a.seed, publicKeyRaw: b.publicKeyRaw })),
    /seed does not correspond to publicKeyRaw/,
  );
});

test("§B Ed25519 path is unperturbed — no sig_alg, ed25519: iss_key", async () => {
  const ed = generateKeypair("ed-default");
  const mint = buildMintV2(toMintPredicates(aprFamilyManifest()));
  const env = await mint({
    body: VALID_BODY,
    issuerPrivateKey: ed.privateKey,
    issuerDid: "did:web:ed.example.com",
    subject: "sha256:aabbccddeeff",
    anchor: ANCHOR,
  });

  assert.equal(env.sig_alg, undefined, "ed25519 receipts must omit sig_alg (byte-equal to v1.2)");
  assert.ok(env.iss_key.startsWith("ed25519:"));
});
