/**
 * Combined verifyCredential — the safe path. Proves issuer authenticity is rooted
 * in the did:web-resolved envelope signature, NOT the self-asserted wrapper proof,
 * and that a forged receipt (issuer key not in the real did:web doc) is rejected.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import { signEnvelope, encodeRaw } from "@dekimuhq/anchors-envelope";
import {
  toVerifiableCredential,
  attachWrapperProof,
  verificationMethodFor,
  verifyCredential,
} from "../src/index.ts";

const ISSUER = "did:web:issuer.example";

function newKey() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const spkiDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const rawPub = new Uint8Array(spkiDer.subarray(-32));
  const seed = new Uint8Array((privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32));
  return { privateKey, spkiDer, rawPub, seed, issKey: `ed25519:${encodeRaw(rawPub)}` };
}

async function mint(k: ReturnType<typeof newKey>, iss = ISSUER, overrides: Partial<Envelope> = {}): Promise<Envelope> {
  const base = {
    v: 2, id: "01JVERIFY000000000000000001", iat: "2026-06-30T12:00:00Z",
    iat_ms: Date.parse("2026-06-30T12:00:00Z"), claim_type: "ar.consent.v1",
    iss, iss_key: k.issKey, subject: "sha256:" + "ab".repeat(32), exp: null,
    prev: null, policy_uri: null, policy_hash: null, policy_version: null, tsa: null,
    credentialStatus: null, suspensionStatus: null,
    anchor: { log: "https://verify.dekimu.com/acr/v1", leaf_index: 0, inclusion_proof: [],
      tree_head_root: "sha256:00", tree_size: 1, log_time: "2026-06-30T12:00:01Z" },
    sig: "", countersig: null, body: { purpose: "marketing" }, ...overrides,
  } as Envelope;
  return signEnvelope(base, k.privateKey);
}

/** A did:web fetcher that serves `servedKey`'s DER under its own iss_key. */
function docFetcher(servedKey: ReturnType<typeof newKey>): typeof fetch {
  const doc = {
    version: 1,
    keys: [{
      iss_key: servedKey.issKey,
      public_key_der_base64: servedKey.spkiDer.toString("base64"),
      valid_from: "2020-01-01T00:00:00Z",
      valid_until: null,
    }],
  };
  return (async () => new Response(JSON.stringify(doc), { status: 200 })) as unknown as typeof fetch;
}

const NOW = () => new Date("2026-06-30T00:00:00Z");

test("valid receipt (no wrapper proof): envelope signature is the root of trust", async () => {
  const k = newKey();
  const vc = toVerifiableCredential(await mint(k));
  const r = await verifyCredential(vc, { fetcher: docFetcher(k), now: NOW });
  assert.equal(r.ok, true);
  assert.equal(r.checks.issuerMatch, true);
  assert.equal(r.checks.envelopeSignature, true);
  assert.equal(r.checks.wrapperProof, "absent");
});

test("valid receipt + wrapper proof verifies both layers", async () => {
  const k = newKey();
  const env = await mint(k);
  const vc = attachWrapperProof(toVerifiableCredential(env), { kid: "k", privateKey: k.seed, publicKey: k.rawPub }, {
    verificationMethod: verificationMethodFor(env.iss, env.iss_key),
  });
  const r = await verifyCredential(vc, { fetcher: docFetcher(k), now: NOW });
  assert.equal(r.ok, true);
  assert.equal(r.checks.wrapperProof, "valid");
});

test("SECURITY: a forged receipt whose key is not in the issuer's did:web doc is rejected", async () => {
  const attacker = newKey();
  const victimServes = newKey(); // the real key published at did:web:issuer.example
  // Attacker mints under the victim's issuer DID but with their OWN key.
  const vc = toVerifiableCredential(await mint(attacker, ISSUER));
  const r = await verifyCredential(vc, { fetcher: docFetcher(victimServes), now: NOW });
  assert.equal(r.ok, false);
  assert.ok(r.reason?.startsWith("key_resolution_failed"), r.reason);
  assert.equal(r.checks.envelopeSignature, false);
});

test("SECURITY: wrapper proof alone cannot rescue a bad envelope signature", async () => {
  const k = newKey();
  const env = await mint(k);
  const vc = attachWrapperProof(toVerifiableCredential(env), { kid: "k", privateKey: k.seed, publicKey: k.rawPub }, {
    verificationMethod: verificationMethodFor(env.iss, env.iss_key),
  });
  // Tamper the embedded envelope AFTER both signatures: family verifier must fail.
  vc.evidence[0].envelope = { ...vc.evidence[0].envelope, body: { purpose: "evil" } };
  const r = await verifyCredential(vc, { fetcher: docFetcher(k), now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.checks.envelopeSignature, false);
});

test("issuer mismatch (vc.issuer diverges from envelope.iss) is rejected before resolution", async () => {
  const k = newKey();
  const vc = toVerifiableCredential(await mint(k));
  vc.issuer = "did:web:evil.example";
  const r = await verifyCredential(vc, { fetcher: docFetcher(k), now: NOW });
  assert.equal(r.ok, false);
  assert.equal(r.reason, "issuer_mismatch");
  assert.equal(r.checks.issuerMatch, false);
});

test("non-did:web issuer with no resolveKey override is not trust-rooted", async () => {
  const k = newKey();
  const vc = toVerifiableCredential(await mint(k, "did:example:abc"));
  const r = await verifyCredential(vc);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "issuer_not_trust_rooted");
});

test("resolveKey override path verifies without network", async () => {
  const k = newKey();
  const vc = toVerifiableCredential(await mint(k, "did:example:abc"));
  const r = await verifyCredential(vc, { resolveKey: async () => new Uint8Array(k.spkiDer) });
  assert.equal(r.ok, true);
  assert.equal(r.checks.envelopeSignature, true);
});

test("tampered wrapper proof marks wrapperProof invalid → overall fail", async () => {
  const k = newKey();
  const env = await mint(k);
  const vc = attachWrapperProof(toVerifiableCredential(env), { kid: "k", privateKey: k.seed, publicKey: k.rawPub }, {
    verificationMethod: verificationMethodFor(env.iss, env.iss_key),
  });
  vc.validFrom = "2000-01-01T00:00:00Z"; // covered by the wrapper proof, not the envelope sig
  const r = await verifyCredential(vc, { fetcher: docFetcher(k), now: NOW });
  assert.equal(r.checks.envelopeSignature, true);
  assert.equal(r.checks.wrapperProof, "invalid");
  assert.equal(r.ok, false);
});
