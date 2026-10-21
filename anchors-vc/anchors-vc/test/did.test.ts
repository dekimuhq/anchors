/**
 * DID helpers (Q5) — self-describing iss_key decode, verificationMethod, and
 * did:web resolution reuse via @dekimuhq/did-web-resolver (mocked fetcher, no
 * network), including the end-to-end attach → resolve(did:web) → verify path.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import type { Envelope } from "@dekimuhq/anchors-envelope";
import { encodeRaw } from "@dekimuhq/anchors-envelope";
import {
  publicKeyFromIssKey,
  verificationMethodFor,
  resolveWrapperKey,
} from "../src/did.ts";
import { toVerifiableCredential } from "../src/wrap.ts";
import { attachWrapperProof, verifyWrapperProof } from "../src/proof.ts";
import { AnchorsVcError } from "../src/unwrap.ts";

function ed25519() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const spkiDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const raw = new Uint8Array(spkiDer.subarray(-32));
  return { privateKey, publicKey, spkiDer, raw, issKey: `ed25519:${encodeRaw(raw)}` };
}

function envWith(issKey: string): Envelope {
  return {
    v: 2, id: "01J0000000000000000000000A", iat: "2026-06-30T12:00:00Z",
    iat_ms: Date.parse("2026-06-30T12:00:00Z"), claim_type: "ar.consent.v1",
    iss: "did:web:issuer.example", iss_key: issKey,
    subject: "did:web:subject.example", exp: null, prev: null, policy_uri: null,
    policy_hash: null, policy_version: null, tsa: null, credentialStatus: null,
    anchor: { log: "l", leaf_index: 0, inclusion_proof: [], tree_head_root: "sha256:00",
      tree_size: 1, log_time: "2026-06-30T12:00:01Z" },
    sig: "ZmFrZQ", countersig: null, body: {},
  } as Envelope;
}

/** A key doc served by a mock did:web fetcher (fingerprint binds to iss_key). */
function keyDocFetcher(issKey: string, spkiDer: Buffer): typeof fetch {
  const doc = {
    version: 1,
    keys: [{
      iss_key: issKey,
      public_key_der_base64: spkiDer.toString("base64"),
      valid_from: "2020-01-01T00:00:00Z",
      valid_until: null,
    }],
  };
  return (async () =>
    new Response(JSON.stringify(doc), { status: 200 })) as unknown as typeof fetch;
}

test("publicKeyFromIssKey decodes alg + raw key bytes", () => {
  const { raw, issKey } = ed25519();
  const r = publicKeyFromIssKey(issKey);
  assert.equal(r.alg, "ed25519");
  assert.deepEqual(new Uint8Array(r.key), raw);
});

test("publicKeyFromIssKey throws on malformed refs", () => {
  assert.throws(() => publicKeyFromIssKey("ed25519"), AnchorsVcError);
  assert.throws(() => publicKeyFromIssKey(":AAAA"), AnchorsVcError);
  assert.throws(() => publicKeyFromIssKey("ed25519:"), AnchorsVcError);
});

test("publicKeyFromIssKey rejects an unsupported sig_alg prefix", () => {
  assert.throws(() => publicKeyFromIssKey("foo:AAAA"), AnchorsVcError);
});

test("resolveWrapperKey rejects a non-ed25519 issuer key (wrapper suite is ed25519-only)", async () => {
  await assert.rejects(() => resolveWrapperKey("did:web:issuer.example", "ml-dsa-65:AAAB"), AnchorsVcError);
});

test("verificationMethodFor builds a fragment DID URL under the issuer", () => {
  const { issKey } = ed25519();
  const vm = verificationMethodFor("did:web:issuer.example", issKey);
  assert.ok(vm.startsWith("did:web:issuer.example#ed25519-"));
});

test("resolveWrapperKey falls back to iss_key for non-did:web issuers", async () => {
  const { raw, issKey } = ed25519();
  const key = await resolveWrapperKey("did:key:whatever", issKey);
  assert.deepEqual(new Uint8Array(key), raw);
});

test("resolveWrapperKey did:web reuses the shared resolver and returns raw 32B", async () => {
  const { raw, issKey, spkiDer } = ed25519();
  const key = await resolveWrapperKey("did:web:issuer.example", issKey, {
    fetcher: keyDocFetcher(issKey, spkiDer),
    now: () => new Date("2026-06-30T00:00:00Z"),
  });
  assert.equal(key.length, 32);
  assert.deepEqual(new Uint8Array(key), raw);
});

test("end-to-end: attach wrapper proof → resolve did:web key → verify", async () => {
  const kp = ed25519();
  const key = { kid: "key-1", privateKey: new Uint8Array((kp.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).subarray(-32)), publicKey: kp.raw };
  const vc = toVerifiableCredential(envWith(kp.issKey));
  const signed = attachWrapperProof(vc, key, {
    verificationMethod: verificationMethodFor("did:web:issuer.example", kp.issKey),
  });
  const resolved = await resolveWrapperKey("did:web:issuer.example", kp.issKey, {
    fetcher: keyDocFetcher(kp.issKey, kp.spkiDer),
    now: () => new Date("2026-06-30T00:00:00Z"),
  });
  assert.deepEqual(verifyWrapperProof(signed, resolved), { ok: true });
});
