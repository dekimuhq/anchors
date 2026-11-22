/**
 * `iss_key` / `sig2_key` algorithm-prefix binding must require the ':' separator
 * (security audit, UNVERIFIED item). `slice(0, indexOf(":"))` with indexOf === -1
 * drops the last character, so "ed25519X" (no colon) used to read as prefix
 * "ed25519" and pass the §L8 binding.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import type { Envelope } from "../src/envelope-types.ts";
import { signEnvelope, verifyEnvelopeSignature } from "../src/envelope.ts";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const PUB_DER = new Uint8Array(publicKey.export({ format: "der", type: "spki" }) as Buffer);

function base(iss_key: string): Envelope {
  return {
    v: 2,
    id: "01HZ0000000000000000000042",
    iat: "2026-05-16T14:00:00Z",
    claim_type: "ar.consent.v1",
    iss: "did:key:z6MkTestIssuer",
    iss_key,
    subject: "sha256:aa",
    exp: null,
    prev: null,
    policy_uri: "https://example.com/p",
    policy_hash: "sha256:" + "a".repeat(64),
    policy_version: "1",
    tsa: null,
    credentialStatus: null,
    anchor: null as unknown as Envelope["anchor"],
    sig: "",
    countersig: null,
    body: {},
  } as Envelope;
}

test("iss_key with correct '<alg>:' prefix verifies (control)", async () => {
  const e = await signEnvelope(base("ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), privateKey);
  assert.equal(verifyEnvelopeSignature(e, PUB_DER), true);
});

test("iss_key lacking ':' (e.g. 'ed25519X') is rejected, not read as prefix 'ed25519'", async () => {
  const e = await signEnvelope(base("ed25519X"), privateKey);
  assert.equal(verifyEnvelopeSignature(e, PUB_DER), false);
});

test("iss_key lacking ':' ('ed25519' / 'ed25519AAAA') is rejected", async () => {
  for (const k of ["ed25519", "ed25519AAAA"]) {
    const e = await signEnvelope(base(k), privateKey);
    assert.equal(verifyEnvelopeSignature(e, PUB_DER), false, k);
  }
});

test("sig2_key lacking ':' is rejected by verifyEnvelopeSig2", async () => {
  const { sign } = await import("node:crypto");
  const { preSigCanonical, verifyEnvelopeSig2 } = await import("../src/envelope.ts");
  const { base64UrlEncode } = await import("../src/base64url.ts");
  const mk = (sig2_key: string) => {
    const e = { ...base("ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), sig2_alg: "ed25519", sig2_key, sig2: "x" } as Envelope;
    const sig = sign(null, Buffer.from(preSigCanonical(e), "utf8"), privateKey);
    return { ...e, sig2: base64UrlEncode(new Uint8Array(sig)) } as Envelope;
  };
  assert.equal(verifyEnvelopeSig2(mk("ed25519:AAAA"), PUB_DER), true, "control");
  assert.equal(verifyEnvelopeSig2(mk("ed25519X"), PUB_DER), false);
});
