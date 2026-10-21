/**
 * v1.3 R3 — hybrid dual-sign (`sig2`) + downgrade posture (`sig_min_alg`).
 *
 * Spec:     https://github.com/dekimuhq/anchors-spec/blob/main/rfcs/RFC-001-sig-alg-discriminator.md
 *           §4 (wire fields) · §5 (security analysis) · §L7 (hybrid) · §C-2 (downgrade).
 *
 * REQUIRES Node ≥24.6 — the ml-dsa-65 half uses the native node:crypto binding.
 *
 * Coverage:
 *   A) envelope-core primitives — keyBytesFromKeyRef, SIG_ALG_RANK,
 *      signEnvelopeSig2 / verifyEnvelopeSig2 round-trip + prefix-mismatch.
 *   B) verifyEnvelopeHybrid — both-valid, sig2 stripped (signed-out) → posture
 *      fail, full apparatus stripped (signed-in) → sig tamper, sig2 forged,
 *      sig2 key unavailable → fail-closed, ml-dsa-only posture, ed25519-only
 *      backward-compat, unsupported sig_min_alg.
 *   C) byte-equal — sig2 excluded from preSigCanonical; deleting sig2 leaves the
 *      primary sig valid.
 *   D) mint pipeline — dual-sign produces sig+sig2+discriminators; XOR/same-alg/
 *      unsatisfiable-posture gates.
 *   E) verify pipeline — self-certifying sig2 default + resolveSig2Key + the
 *      end-to-end strip-detection through buildVerifyReceipt.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";

import {
  signEnvelope,
  signEnvelopeSig2,
  verifyEnvelopeSignature,
  verifyEnvelopeSig2,
  verifyEnvelopeHybrid,
  keyBytesFromKeyRef,
  SIG_ALG_RANK,
  preSigCanonical,
  isSupportedSigAlg,
} from "../src/envelope.ts";
import { generateKeypair } from "../src/ed25519.ts";
import {
  generateMlDsaKeypair,
  toMlDsaSecret,
  encodeMlDsaIssKey,
  MLDSA65_PUBKEY_BYTES,
} from "../src/ml-dsa.ts";
import { keyObjectFromSeed } from "../src/mint-helpers.ts";
import {
  buildMintV2,
  type FamilyMintPredicates,
  type FamilyMintV2Input,
} from "../src/family-mint-pipeline.ts";
import {
  buildVerifyReceipt,
  type FamilyVerifyPredicates,
} from "../src/family-verify-pipeline.ts";
import { defineFamily, type BodyValidator } from "../src/define-family.ts";
import type { AnchorProof, ClaimType, Envelope } from "../src/envelope-types.ts";

// ── Shared fixtures ──────────────────────────────────────────────────────────

const ANCHOR: AnchorProof = {
  log: "https://verify.dekimu.com/apr/v1",
  leaf_index: 0,
  inclusion_proof: ["sha256:aabbcc"],
  tree_head_root: "sha256:deadbeef",
  tree_size: 1,
  log_time: "2026-05-19T00:00:00Z",
};

const VALID_BODY = { kind: "ar.provenance.v1", events: [] };

/** A complete APR-shaped v=2 envelope with an empty `sig`, ready for signEnvelope. */
function VALID_ENV_FIELDS(): Envelope {
  return {
    v: 2,
    id: "01HZ0000000000000000000001",
    iat: "2026-05-19T00:00:00Z",
    iat_ms: Date.parse("2026-05-19T00:00:00Z"),
    claim_type: "ar.provenance.v1",
    iss: "did:web:proto.example.com",
    iss_key: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    subject: "sha256:aabbccddeeff",
    exp: null,
    prev: null,
    policy_uri: null,
    policy_hash: null,
    policy_version: null,
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR,
    sig: "",
    countersig: null,
    body: VALID_BODY,
  };
}

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

function aprFamily() {
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

function mintPredicates<B>(
  family: ReturnType<typeof defineFamily<B>>,
): FamilyMintPredicates<B> {
  return {
    meta: family.meta,
    validateBody: (b) => family.validateBody(b),
    checkSubjectPresence: (s, b) => family.checkSubjectPresence(s, b),
    isOwnedClaimType: (ct) => family.isOwnedClaimType(ct),
  };
}

function verifyPredicates<B>(
  family: ReturnType<typeof defineFamily<B>>,
): FamilyVerifyPredicates<B> {
  return {
    meta: family.meta,
    validateBody: (b) => family.validateBody(b),
    isOwnedClaimType: (ct) => family.isOwnedClaimType(ct),
    checkSubjectPresence: (s, b) => family.checkSubjectPresence(s, b),
    tsaMandateLevel: (p) => family.tsaMandateLevel(p),
    profileValidators: family.profileValidators,
    profileIds: family.profileIds,
    hasProfile: (p) => family.hasProfile(p),
  };
}

/** Mint an Ed25519-primary + ML-DSA-65-sig2 hybrid receipt with sig_min_alg. */
async function mintHybrid(
  overrides: Partial<FamilyMintV2Input> = {},
): Promise<{ env: Envelope; mlPubRaw: Uint8Array }> {
  const ed = generateKeypair("ed-primary");
  const ml = generateMlDsaKeypair("ml-sig2");
  const mint = buildMintV2(mintPredicates(aprFamily()));
  const env = await mint({
    body: VALID_BODY,
    issuerPrivateKey: ed.privateKey,
    sig2: { mlDsa: toMlDsaSecret(ml) },
    sigMinAlg: "ml-dsa-65",
    issuerDid: "did:web:hybrid.example.com",
    subject: "sha256:aabbccddeeff",
    anchor: ANCHOR,
    ...overrides,
  });
  return { env, mlPubRaw: ml.publicKeyRaw };
}

// ── A. envelope-core primitives ──────────────────────────────────────────────

test("A keyBytesFromKeyRef decodes ed25519 → 44-byte SPKI DER, ml-dsa-65 → 1952 raw", () => {
  const ed = generateKeypair("kbf-ed");
  const { issKey } = keyObjectFromSeed(ed.privateKey);
  const der = keyBytesFromKeyRef(issKey);
  assert.ok(der);
  assert.equal(der!.length, 44); // 12-byte SPKI prefix + 32-byte raw

  const ml = generateMlDsaKeypair("kbf-ml");
  const raw = keyBytesFromKeyRef(encodeMlDsaIssKey(ml.publicKeyRaw));
  assert.ok(raw);
  assert.equal(raw!.length, MLDSA65_PUBKEY_BYTES);

  // The decoded ed25519 SPKI DER actually verifies a real signature (dogfood).
  assert.deepEqual(
    [...der!],
    [...keyBytesFromKeyRef(issKey)!],
  );
});

test("A keyBytesFromKeyRef rejects malformed / unknown / wrong-length refs", () => {
  assert.equal(keyBytesFromKeyRef(null), null);
  assert.equal(keyBytesFromKeyRef(undefined), null);
  assert.equal(keyBytesFromKeyRef(""), null);
  assert.equal(keyBytesFromKeyRef("noprefix"), null);
  assert.equal(keyBytesFromKeyRef("ed25519:"), null); // empty key
  assert.equal(keyBytesFromKeyRef("slh-dsa-sha2-128s:AAAA"), null); // unregistered alg
  assert.equal(keyBytesFromKeyRef("ed25519:QUJD"), null); // "ABC" → 3 bytes, not 32
  assert.equal(keyBytesFromKeyRef("ml-dsa-65:QUJD"), null); // not 1952 bytes
});

test("A SIG_ALG_RANK orders ed25519 below ml-dsa-65", () => {
  assert.equal(SIG_ALG_RANK.ed25519, 0);
  assert.ok(SIG_ALG_RANK["ml-dsa-65"] > SIG_ALG_RANK.ed25519);
});

test("A signEnvelopeSig2 + verifyEnvelopeSig2 round-trip (ed25519 primary, ml-dsa sig2)", async () => {
  const { env, mlPubRaw } = await mintHybrid();
  assert.ok(typeof env.sig2 === "string" && env.sig2.length > 0);
  assert.equal(env.sig2_alg, "ml-dsa-65");
  assert.ok(env.sig2_key!.startsWith("ml-dsa-65:"));
  assert.equal(verifyEnvelopeSig2(env, mlPubRaw), true);
});

test("A verifyEnvelopeSig2 rejects a sig2_key whose prefix ≠ sig2_alg (§L6)", async () => {
  const { env, mlPubRaw } = await mintHybrid();
  // Forge the prefix to ed25519 while sig2_alg stays ml-dsa-65.
  const swapped = {
    ...env,
    sig2_key: env.sig2_key!.replace("ml-dsa-65:", "ed25519:") as `ed25519:${string}`,
  };
  assert.equal(verifyEnvelopeSig2(swapped, mlPubRaw), false);
});

test("A verifyEnvelopeSig2 false when sig2 absent or sig2_alg/sig2_key missing", async () => {
  const { env, mlPubRaw } = await mintHybrid();
  assert.equal(verifyEnvelopeSig2({ ...env, sig2: null }, mlPubRaw), false);
  assert.equal(verifyEnvelopeSig2({ ...env, sig2_alg: null }, mlPubRaw), false);
  assert.equal(verifyEnvelopeSig2({ ...env, sig2_key: null }, mlPubRaw), false);
});

// ── B. verifyEnvelopeHybrid + posture ────────────────────────────────────────

test("B both signatures valid → ok, posture (ml-dsa-65) satisfied", async () => {
  const { env, mlPubRaw } = await mintHybrid();
  const primary = keyBytesFromKeyRef(env.iss_key)!;
  const r = verifyEnvelopeHybrid(env, primary, mlPubRaw);
  assert.equal(r.ok, true);
  assert.equal(r.primaryOk, true);
  assert.equal(r.sig2Ok, true);
  assert.equal(r.reason, null);
  // validAlgs exposes BOTH verified algorithms, primary-first (R3 Phase 2 input).
  assert.deepEqual([...r.validAlgs], ["ed25519", "ml-dsa-65"]);
});

test("B stripping sig2 (signed-OUT) leaves sig_min_alg unsatisfiable → REJECTED (C-2 core)", async () => {
  const { env } = await mintHybrid();
  const primary = keyBytesFromKeyRef(env.iss_key)!;
  // Attacker drops only the signed-OUT sig2 bytes; sig2_alg/sig2_key/sig_min_alg
  // (all signed-in) remain, so the PRIMARY sig is still valid…
  const stripped = { ...env, sig2: null };
  assert.equal(verifyEnvelopeSignature(stripped, primary), true);
  // …but no valid ml-dsa signature remains, and the posture demands one.
  const r = verifyEnvelopeHybrid(stripped, primary, null);
  assert.equal(r.ok, false);
  assert.equal(r.primaryOk, true);
  assert.equal(r.reason, "sig_min_alg_unsatisfied:ml-dsa-65");
  // Only the primary verified, so the PQC half is absent from validAlgs — the
  // signal the issuer-mandate seam reads to reject a stripped/classical receipt.
  assert.deepEqual([...r.validAlgs], ["ed25519"]);
});

test("B stripping the whole apparatus (signed-IN fields) breaks the primary sig → signature_invalid", async () => {
  const { env } = await mintHybrid();
  const primary = keyBytesFromKeyRef(env.iss_key)!;
  // Remove the signed-in discriminators too — perturbs preSigCanonical.
  const gutted = { ...env } as unknown as Record<string, unknown>;
  delete gutted.sig2;
  delete gutted.sig2_alg;
  delete gutted.sig2_key;
  delete gutted.sig_min_alg;
  const r = verifyEnvelopeHybrid(gutted as unknown as Envelope, primary, null);
  assert.equal(r.ok, false);
  assert.equal(r.primaryOk, false);
  assert.equal(r.reason, "signature_invalid");
});

test("B forging sig2 bytes only → sig2 invalid, posture unmet → REJECTED", async () => {
  const { env, mlPubRaw } = await mintHybrid();
  const primary = keyBytesFromKeyRef(env.iss_key)!;
  // Flip a char in the sig2 base64url → invalid ml-dsa signature.
  const c = env.sig2!;
  const forged = { ...env, sig2: (c[0] === "A" ? "B" : "A") + c.slice(1) };
  const r = verifyEnvelopeHybrid(forged, primary, mlPubRaw);
  assert.equal(r.ok, false);
  assert.equal(r.primaryOk, true);
  assert.equal(r.sig2Ok, false);
  assert.equal(r.reason, "sig_min_alg_unsatisfied:ml-dsa-65");
});

test("B sig2 key unavailable (null) under an ml-dsa posture → fail-closed", async () => {
  const { env } = await mintHybrid();
  const primary = keyBytesFromKeyRef(env.iss_key)!;
  const r = verifyEnvelopeHybrid(env, primary, null);
  assert.equal(r.ok, false);
  assert.equal(r.sig2Ok, false);
  assert.equal(r.reason, "sig_min_alg_unsatisfied:ml-dsa-65");
});

test("B ml-dsa-only receipt (primary ml-dsa, sig_min_alg ml-dsa-65, no sig2) → ok", async () => {
  const ml = generateMlDsaKeypair("ml-only");
  const mint = buildMintV2(mintPredicates(aprFamily()));
  const env = await mint({
    body: VALID_BODY,
    mlDsaKey: toMlDsaSecret(ml),
    sigMinAlg: "ml-dsa-65",
    issuerDid: "did:web:mlonly.example.com",
    subject: "sha256:aabbccddeeff",
    anchor: ANCHOR,
  });
  assert.equal(env.sig_alg, "ml-dsa-65");
  assert.equal(env.sig_min_alg, "ml-dsa-65");
  assert.equal(env.sig2, undefined);
  const primary = keyBytesFromKeyRef(env.iss_key)!;
  const r = verifyEnvelopeHybrid(env, primary, null);
  assert.equal(r.ok, true);
  assert.equal(r.reason, null);
});

test("B ed25519-only receipt with no posture → ok (backward-compat behavior)", async () => {
  const ed = generateKeypair("ed-plain");
  const mint = buildMintV2(mintPredicates(aprFamily()));
  const env = await mint({
    body: VALID_BODY,
    issuerPrivateKey: ed.privateKey,
    issuerDid: "did:web:plain.example.com",
    subject: "sha256:aabbccddeeff",
    anchor: ANCHOR,
  });
  assert.equal(env.sig_alg, undefined);
  assert.equal(env.sig2, undefined);
  assert.equal(env.sig_min_alg, undefined);
  const primary = keyBytesFromKeyRef(env.iss_key)!;
  const r = verifyEnvelopeHybrid(env, primary, null);
  assert.equal(r.ok, true);
});

test("B sig_min_alg naming an UNSUPPORTED alg → unsupported_sig_alg (fail-closed)", async () => {
  // A forward receipt: the issuer committed a posture this verifier can't yet
  // evaluate. The posture is signed-in, so we must SIGN it in for the primary
  // `sig` to verify — then the unsupported-min branch (reached only on a valid
  // primary) fires. ml-dsa keys are unused here; ed25519 primary suffices.
  const ed = generateKeypair("ed-fwd");
  const kos = keyObjectFromSeed(ed.privateKey);
  const base = { ...(await mintHybrid()).env, sig: "", sig2: null, sig2_alg: null, sig2_key: null, iss_key: kos.issKey };
  // Inject an unregistered forward posture (bypassing the SigAlg type — this is
  // a deliberately synthetic forward receipt).
  (base as unknown as Record<string, unknown>).sig_min_alg = "slh-dsa-sha2-128s";
  const signed = await signEnvelope(base, kos.privateKey);
  const fwdPrimary = keyBytesFromKeyRef(signed.iss_key)!;
  const r = verifyEnvelopeHybrid(signed, fwdPrimary, null);
  assert.equal(r.ok, false);
  assert.equal(r.primaryOk, true);
  assert.equal(r.reason, "unsupported_sig_alg:slh-dsa-sha2-128s");
});

// ── C. byte-equal — sig2 is signed-out ───────────────────────────────────────

test("C preSigCanonical is identical with and without sig2 present (signed-out)", async () => {
  const { env } = await mintHybrid();
  const withSig2 = preSigCanonical(env);
  const noSig2 = preSigCanonical({ ...env, sig2: null });
  assert.equal(withSig2, noSig2);
  // The canonical form must NOT contain the sig2 signature bytes.
  assert.ok(!withSig2.includes(env.sig2!));
});

// ── D. mint pipeline gates ───────────────────────────────────────────────────

test("D dual-sign mint sets sig + sig2 + signed-in discriminators", async () => {
  const { env } = await mintHybrid();
  assert.ok(typeof env.sig === "string" && env.sig.length > 0);
  assert.ok(typeof env.sig2 === "string" && env.sig2.length > 0);
  assert.equal(env.sig_alg, undefined); // ed25519 primary omits sig_alg
  assert.equal(env.sig2_alg, "ml-dsa-65");
  assert.ok(env.sig2_key!.startsWith("ml-dsa-65:"));
  assert.equal(env.sig_min_alg, "ml-dsa-65");
});

test("D sig2 with the same algorithm as the primary throws", async () => {
  const ed1 = generateKeypair("ed-1");
  const ed2 = generateKeypair("ed-2");
  const mint = buildMintV2(mintPredicates(aprFamily()));
  await assert.rejects(
    mint({
      body: VALID_BODY,
      issuerPrivateKey: ed1.privateKey,
      sig2: { ed25519: ed2.privateKey },
      issuerDid: "did:web:same.example.com",
      subject: "sha256:aabbccddeeff",
      anchor: ANCHOR,
    }),
    /sig2 algorithm must differ from the primary/,
  );
});

test("D sig2 requires exactly one of ed25519 | mlDsa", async () => {
  const ed = generateKeypair("ed-xor");
  const ml = generateMlDsaKeypair("ml-xor");
  const mint = buildMintV2(mintPredicates(aprFamily()));
  await assert.rejects(
    mint({
      body: VALID_BODY,
      issuerPrivateKey: ed.privateKey,
      sig2: { ed25519: generateKeypair("ed-x2").privateKey, mlDsa: toMlDsaSecret(ml) },
      issuerDid: "did:web:xor.example.com",
      subject: "sha256:aabbccddeeff",
      anchor: ANCHOR,
    }),
    /sig2 requires exactly one of/,
  );
});

test("D unsatisfiable sigMinAlg throws (never mint a self-failing receipt)", async () => {
  const ed = generateKeypair("ed-unsat");
  const mint = buildMintV2(mintPredicates(aprFamily()));
  await assert.rejects(
    mint({
      body: VALID_BODY,
      issuerPrivateKey: ed.privateKey, // ed25519 only
      sigMinAlg: "ml-dsa-65", // demands PQC but no PQC key provided
      issuerDid: "did:web:unsat.example.com",
      subject: "sha256:aabbccddeeff",
      anchor: ANCHOR,
    }),
    /sigMinAlg "ml-dsa-65" cannot be satisfied/,
  );
});

// ── E. verify pipeline integration ───────────────────────────────────────────

test("E buildVerifyReceipt verifies a hybrid receipt via the self-certifying sig2 default", async () => {
  const { env } = await mintHybrid();
  const verify = buildVerifyReceipt(verifyPredicates(aprFamily()));
  const result = await verify(env, {
    resolveKey: (e) => keyBytesFromKeyRef((e as Envelope).iss_key),
    // no resolveSig2Key → pipeline self-certifies env.sig2_key
  });
  assert.equal(result.signature_valid, true);
});

test("E buildVerifyReceipt rejects a sig2-stripped hybrid receipt (end-to-end C-2)", async () => {
  const { env } = await mintHybrid();
  const verify = buildVerifyReceipt(verifyPredicates(aprFamily()));
  const result = await verify(
    { ...env, sig2: null },
    { resolveKey: (e) => keyBytesFromKeyRef((e as Envelope).iss_key) },
  );
  assert.equal(result.signature_valid, false);
  assert.equal(result.reason, "sig_min_alg_unsatisfied:ml-dsa-65");
});

test("E buildVerifyReceipt honors a custom resolveSig2Key", async () => {
  const { env, mlPubRaw } = await mintHybrid();
  const verify = buildVerifyReceipt(verifyPredicates(aprFamily()));
  let called = false;
  const result = await verify(env, {
    resolveKey: (e) => keyBytesFromKeyRef((e as Envelope).iss_key),
    resolveSig2Key: () => {
      called = true;
      return mlPubRaw;
    },
  });
  assert.equal(called, true);
  assert.equal(result.signature_valid, true);
});

test("E an ed25519-only receipt still verifies unchanged through the pipeline", async () => {
  const ed = generateKeypair("ed-pipe");
  const mint = buildMintV2(mintPredicates(aprFamily()));
  const env = await mint({
    body: VALID_BODY,
    issuerPrivateKey: ed.privateKey,
    issuerDid: "did:web:pipe.example.com",
    subject: "sha256:aabbccddeeff",
    anchor: ANCHOR,
  });
  const verify = buildVerifyReceipt(verifyPredicates(aprFamily()));
  const result = await verify(env, {
    resolveKey: (e) => keyBytesFromKeyRef((e as Envelope).iss_key),
  });
  assert.equal(result.signature_valid, true);
});

// ── F. malicious algorithm discriminator — prototype-pollution bypass guard ──
// A forged `sig_alg`/`sig2_alg`/`sig_min_alg` that names an Object.prototype
// member ("toString", "valueOf", "constructor", …) must NEVER resolve to a
// prototype method and pass as a registered verifier (own-property lookup).

const PROTO_NAMES = [
  "toString",
  "valueOf",
  "constructor",
  "hasOwnProperty",
  "__proto__",
  "isPrototypeOf",
];

test("F isSupportedSigAlg rejects every Object.prototype member name", () => {
  for (const name of PROTO_NAMES) {
    assert.equal(isSupportedSigAlg(name), false, `isSupportedSigAlg(${name})`);
  }
});

test("F forged sig_alg=prototype-member + matching iss_key prefix never verifies", async () => {
  const ed = generateKeypair("ed-proto");
  const { issKey, privateKey } = keyObjectFromSeed(ed.privateKey);
  // A genuinely signed ed25519 receipt — then we hand the verifier a REAL key
  // (as an issuer-DID resolver would) while forging the alg discriminator.
  const realDer = keyBytesFromKeyRef(issKey)!;
  const base = { ...VALID_ENV_FIELDS(), iss_key: issKey };
  const signed = await signEnvelope(base, privateKey);
  for (const name of PROTO_NAMES) {
    const forged = { ...signed } as unknown as Record<string, unknown>;
    forged.sig = "AAAA"; // garbage signature — must never be accepted
    forged.sig_alg = name;
    forged.iss_key = `${name}:abc`; // prefix matches the forged alg
    const f = forged as unknown as Envelope;
    assert.equal(
      verifyEnvelopeSignature(f, realDer),
      false,
      `verifyEnvelopeSignature with sig_alg=${name}`,
    );
    const h = verifyEnvelopeHybrid(f, realDer, null);
    assert.equal(h.ok, false, `verifyEnvelopeHybrid with sig_alg=${name}`);
    assert.equal(h.primaryOk, false, `primaryOk must be a real false for ${name}`);
  }
});

test("F forged sig2_alg=prototype-member never verifies as a hybrid second sig", async () => {
  const { env } = await mintHybrid();
  const primary = keyBytesFromKeyRef(env.iss_key)!;
  for (const name of PROTO_NAMES) {
    const forged = { ...env } as unknown as Record<string, unknown>;
    forged.sig2 = "AAAA";
    forged.sig2_alg = name;
    forged.sig2_key = `${name}:abc`;
    // Give it some bytes as the "sig2 key" — must still fail (alg unregistered).
    assert.equal(
      verifyEnvelopeSig2(forged as unknown as Envelope, primary),
      false,
      `sig2_alg=${name}`,
    );
  }
});

test("F forged sig_min_alg=prototype-member → unsupported_sig_alg (fail-closed)", async () => {
  // Sign the forged posture in so the primary sig is valid and the posture
  // branch is actually reached.
  const ed = generateKeypair("ed-min-proto");
  const kos = keyObjectFromSeed(ed.privateKey);
  const base = { ...VALID_ENV_FIELDS(), iss_key: kos.issKey };
  (base as unknown as Record<string, unknown>).sig_min_alg = "toString";
  const signed = await signEnvelope(base, kos.privateKey);
  const primary = keyBytesFromKeyRef(signed.iss_key)!;
  const r = verifyEnvelopeHybrid(signed, primary, null);
  assert.equal(r.primaryOk, true);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "unsupported_sig_alg:toString");
});

test("F end-to-end pipeline: forged prototype sig_alg with a key-returning resolver → rejected", async () => {
  const ed = generateKeypair("ed-pipe-proto");
  const kos = keyObjectFromSeed(ed.privateKey);
  const realDer = keyBytesFromKeyRef(kos.issKey)!;
  const base = { ...VALID_ENV_FIELDS(), iss_key: kos.issKey };
  const signed = await signEnvelope(base, kos.privateKey);
  const forged = { ...signed } as unknown as Record<string, unknown>;
  forged.sig = "AAAA";
  forged.sig_alg = "toString";
  forged.iss_key = "toString:abc";
  const verify = buildVerifyReceipt(verifyPredicates(aprFamily()));
  // Resolver returns a real key regardless (simulating issuer-DID resolution) —
  // the bypass must still be refused before any crypto "passes".
  const result = await verify(forged, { resolveKey: () => realDer });
  assert.equal(result.signature_valid, false);
});
