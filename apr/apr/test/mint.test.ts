/**
 * Smoke test: a freshly minted APR round-trips through the verifier.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { mint, generateKeypair } from "../src/issue/index.ts";
import {
  verifyClaim,
  type ClaimKeyResolver,
  type APRBody,
} from "../src/index.ts";

const body: APRBody = {
  artifact: {
    type: "miniterms.document",
    id: "art-001",
    hash: "0".repeat(64),
    hashAlgorithm: "sha256",
  },
  agent: { kind: "template" },
  authorization: { principalId: "principal-1" },
  startedAt: 1000,
  completedAt: 1001,
  disclosure: "public_minimal",
  qts_attestation_hash: null,
};

test("mint → verifyClaim round-trip succeeds", () => {
  const kp = generateKeypair("test-2026");
  const claim = mint({
    issuer: "test-issuer",
    subject: "art-001",
    body,
    signingKey: { kid: kp.kid, privateKey: kp.privateKey },
    now: () => 1000,
    newId: () => "01J0TEST00000000000000A001",
  });
  assert.equal(claim.kind, "ar.provenance.v1");
  assert.equal(claim.kid, kp.kid);
  assert.equal(claim.iat, 1000);
  assert.equal(claim.id, "01J0TEST00000000000000A001");

  const resolver: ClaimKeyResolver = (k) =>
    k === kp.kid ? { kid: kp.kid, publicKey: kp.publicKey, issuer: "test-issuer" } : undefined;
  const result = verifyClaim(claim, resolver, 1500);
  assert.equal(result.ok, true);
});

test("mint rejects empty issuer / subject / wrong-length key", () => {
  const kp = generateKeypair("k");
  assert.throws(() =>
    mint({
      issuer: "",
      subject: "x",
      body,
      signingKey: { kid: kp.kid, privateKey: kp.privateKey },
    }),
  );
  assert.throws(() =>
    mint({
      issuer: "i",
      subject: "",
      body,
      signingKey: { kid: kp.kid, privateKey: kp.privateKey },
    }),
  );
  assert.throws(() =>
    mint({
      issuer: "i",
      subject: "x",
      body,
      signingKey: { kid: "k2", privateKey: new Uint8Array(16) },
    }),
  );
});

test("optional fields propagate", () => {
  const kp = generateKeypair("opt-2026");
  const claim = mint({
    issuer: "i",
    subject: "x",
    body,
    signingKey: { kid: kp.kid, privateKey: kp.privateKey },
    holder: "h",
    audience: ["a1", "a2"],
    exp: 9999,
    parent: "p",
    now: () => 100,
    newId: () => "01J0OPT00000000000000000A1",
  });
  assert.equal(claim.holder, "h");
  assert.deepEqual(claim.audience, ["a1", "a2"]);
  assert.equal(claim.exp, 9999);
  assert.equal(claim.parent, "p");
});

test("two mints produce different ids by default", () => {
  const kp = generateKeypair("u-2026");
  const a = mint({ issuer: "i", subject: "x", body, signingKey: { kid: kp.kid, privateKey: kp.privateKey } });
  const b = mint({ issuer: "i", subject: "x", body, signingKey: { kid: kp.kid, privateKey: kp.privateKey } });
  assert.notEqual(a.id, b.id);
  assert.equal(a.id.length, 26);
});
