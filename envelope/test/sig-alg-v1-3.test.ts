/**
 * v1.3 sig_alg agility hook + v1.4 `incl` byte-equality regression.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/blob/main/rfcs/RFC-001-sig-alg-discriminator.md
 *
 * Covers:
 *   C-1 / §6 — the optional signed-out `incl` field is EXCLUDED (deleted), not
 *              zeroed. A receipt that never carried `incl` canonicalizes with no
 *              `incl` key, so the existing receipt corpus stays byte-equal. This
 *              is the frozen-vector guard: an envelope signed before `incl`
 *              existed still verifies, and attaching `incl` post-sign does not
 *              perturb the signature.
 *   §L2     — absent `sig_alg` ≡ "ed25519": omitting it is byte-equal to a v1.2
 *              receipt; an Ed25519 receipt verifies whether or not it sets it.
 *   §L3     — `sig_alg` is SIGNED-IN: changing it after signing breaks the sig.
 *   §L8     — an unsupported `sig_alg` is refused (isSupportedSigAlg / pipeline
 *              `unsupported_sig_alg`), never attempted as ed25519, never passed.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import type { Envelope, AnchorProof } from "../src/envelope-types.ts";
import { SIG_ALGS } from "../src/envelope-types.ts";
import {
  preSigCanonical,
  signEnvelope,
  verifyEnvelopeSignature,
  isSupportedSigAlg,
} from "../src/envelope.ts";

const ANCHOR_FIXTURE: AnchorProof = {
  log: "https://verify.dekimu.com/apr/v1",
  leaf_index: 0,
  inclusion_proof: ["sha256:aabbcc"],
  tree_head_root: "sha256:deadbeef",
  tree_size: 1,
  log_time: "2026-05-16T14:00:00Z",
};

/** A minimal v1.1/v1.2-shape receipt — carries NO `incl`, NO `sig_alg`. */
function makeOldEnvelope(overrides: Partial<Envelope> = {}): Envelope {
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
    tsa: null,
    credentialStatus: null,
    anchor: ANCHOR_FIXTURE,
    sig: "placeholder-sig",
    countersig: null,
    body: { hello: 1 },
  };
  return { ...base, ...overrides };
}

const INCL_FIXTURE: NonNullable<Envelope["incl"]> = {
  log_id: "https://verify.dekimu.com/log/v1",
  leaf: "sha256:cafef00d",
  promise: { timestamp: "2026-05-16T14:00:01Z", sig: "AQID" },
};

// ── C-1 / §6: incl is EXCLUDED, not zeroed ───────────────────────────────────

test("preSigCanonical of a receipt WITHOUT incl contains no `incl` key (byte-equal corpus)", () => {
  const canonical = preSigCanonical(makeOldEnvelope());
  assert.ok(
    !canonical.includes('"incl"'),
    `incl must not appear in canonical form of an incl-less receipt; got: ${canonical}`,
  );
});

test("attaching incl AFTER signing does not change preSigCanonical bytes", () => {
  const e = makeOldEnvelope();
  const before = preSigCanonical(e);
  const withIncl = { ...e, incl: INCL_FIXTURE };
  const after = preSigCanonical(withIncl);
  assert.equal(after, before, "incl is signed-out — its presence must not perturb the signed bytes");
});

test("a signature minted before incl existed still verifies after incl is attached", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pubDer = new Uint8Array(publicKey.export({ format: "der", type: "spki" }) as Buffer);

  // Sign the receipt with no incl (the historical state).
  const signed = await signEnvelope(makeOldEnvelope(), privateKey);
  assert.equal(verifyEnvelopeSignature(signed, pubDer), true);

  // The log later attaches an inclusion block. Signature must still verify.
  const logged = { ...signed, incl: INCL_FIXTURE };
  assert.equal(verifyEnvelopeSignature(logged, pubDer), true);

  // Upgrading the incl block (promise → full proof) must also not break it.
  const upgraded = {
    ...logged,
    incl: { ...INCL_FIXTURE, proof: { index: 0, tree_size: 1, path: ["sha256:00"], checkpoint: "cp" } },
  };
  assert.equal(verifyEnvelopeSignature(upgraded, pubDer), true);
});

// ── §L2: absent sig_alg ≡ "ed25519" ──────────────────────────────────────────

test("omitting sig_alg is byte-equal to a v1.2 receipt (no `sig_alg` key in canonical)", () => {
  const canonical = preSigCanonical(makeOldEnvelope());
  assert.ok(!canonical.includes('"sig_alg"'), "an issuer that omits sig_alg must not emit the key");
});

test("an Ed25519 receipt verifies whether sig_alg is omitted or set explicitly", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pubDer = new Uint8Array(publicKey.export({ format: "der", type: "spki" }) as Buffer);

  const omitted = await signEnvelope(makeOldEnvelope(), privateKey);
  assert.equal(verifyEnvelopeSignature(omitted, pubDer), true);

  const explicit = await signEnvelope(makeOldEnvelope({ sig_alg: "ed25519" }), privateKey);
  assert.equal(verifyEnvelopeSignature(explicit, pubDer), true);
});

test("setting sig_alg explicitly changes the signed bytes (it is SIGNED-IN)", () => {
  const omitted = preSigCanonical(makeOldEnvelope());
  const explicit = preSigCanonical(makeOldEnvelope({ sig_alg: "ed25519" }));
  assert.notEqual(explicit, omitted, "sig_alg is signed-in: present vs absent must differ");
  assert.ok(explicit.includes('"sig_alg":"ed25519"'));
});

// ── §L3: sig_alg is signed-in — tampering breaks the signature ────────────────

test("verifyEnvelopeSignature fails if sig_alg is altered after signing", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pubDer = new Uint8Array(publicKey.export({ format: "der", type: "spki" }) as Buffer);

  const signed = await signEnvelope(makeOldEnvelope({ sig_alg: "ed25519" }), privateKey);
  assert.equal(verifyEnvelopeSignature(signed, pubDer), true);

  // Strip the signed-in sig_alg → canonical bytes change → sig must fail.
  const stripped = { ...signed };
  delete (stripped as { sig_alg?: unknown }).sig_alg;
  assert.equal(verifyEnvelopeSignature(stripped, pubDer), false);
});

// ── §L8: unsupported algorithm is refused, never silently passed ──────────────

test("Phase 2 registers ed25519 + ml-dsa-65 (slh-dsa still spec-only)", () => {
  assert.deepEqual([...SIG_ALGS], ["ed25519", "ml-dsa-65"]);
});

test("isSupportedSigAlg: undefined/ed25519/ml-dsa-65 supported, slh-dsa + junk not", () => {
  assert.equal(isSupportedSigAlg(undefined), true);
  assert.equal(isSupportedSigAlg("ed25519"), true);
  assert.equal(isSupportedSigAlg("ml-dsa-65"), true);
  assert.equal(isSupportedSigAlg("slh-dsa-sha2-128s"), false);
  assert.equal(isSupportedSigAlg("nonsense"), false);
});

test("verifyEnvelopeSignature refuses an unsupported sig_alg even with a valid-looking sig", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pubDer = new Uint8Array(publicKey.export({ format: "der", type: "spki" }) as Buffer);

  // Sign normally, then forge a forward sig_alg the verifier cannot evaluate.
  // `slh-dsa-sha2-128s` is spec'd (L5) but not yet registered → still unsupported.
  const signed = await signEnvelope(makeOldEnvelope(), privateKey);
  const forward = { ...signed, sig_alg: "slh-dsa-sha2-128s" } as unknown as Envelope;
  assert.equal(verifyEnvelopeSignature(forward, pubDer), false);
});
