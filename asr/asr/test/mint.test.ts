/**
 * Smoke tests for `mintAsrV2` — confirms the issuer-kit re-export is wired
 * correctly to the factory pipeline. Real coverage of the mint surface
 * lives in `@dekimuhq/asr`'s round-trip suite; this test set
 * exercises the re-export's identity and a single end-to-end mint.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mintAsrV2, asrFamily, generateKeypair } from "../src/issue/index.ts";

test("mintAsrV2 is identical to asrFamily.mintV2", () => {
  assert.equal(mintAsrV2, asrFamily.mintV2);
});

test("generateKeypair re-export produces a 32-byte private key + 32-byte public key", () => {
  const kp = generateKeypair("test");
  assert.equal(kp.privateKey.length, 32);
  assert.equal(kp.publicKey.length, 32);
});

test("mintAsrV2 produces a v=2 envelope with claim_type ar.subject_rights.v1", async () => {
  const kp = generateKeypair("test");
  const env = await mintAsrV2({
    body: {
      event_type: "request.received",
      subject_rights_request_id: "req-1",
      channel: "email",
      received_at: "2026-05-19T08:00:00Z",
      deadline_at: "2026-06-18T08:00:00Z",
    },
    issuerPrivateKey: kp.privateKey,
    issuerDid: "did:web:test.example.com",
    subject: `sha256:${"a".repeat(64)}`,
    anchor: {
      log: "https://verify.dekimu.com/asr/v1",
      leaf_index: 0,
      inclusion_proof: [`sha256:${"b".repeat(64)}`],
      tree_head_root: `sha256:${"c".repeat(64)}`,
      tree_size: 1,
      log_time: "2026-05-19T00:00:00Z",
    },
    policy_uri: "https://example.test/policy.json",
    policy_hash: `sha256:${"d".repeat(64)}`,
    policy_version: "2026-05-19",
  });
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.subject_rights.v1");
  assert.ok(env.iss_key.startsWith("ed25519:"));
  assert.ok(typeof env.sig === "string" && env.sig.length > 0);
});
