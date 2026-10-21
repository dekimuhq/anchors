/**
 * Tests for the four per-event-type convenience wrappers in mint-single.ts.
 * Each wrapper should produce a receipt the verifier accepts and with the
 * correct `event_type` discriminator in the body.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";

import {
  mintDerivedFrom,
  mintForkedFrom,
  mintSupersededBy,
  mintDisclosed,
} from "../src/issue/index.ts";
import { verifyReceipt } from "../src/index.ts";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

const H = (b: string) => `sha256:${b.repeat(64)}`;

function makeSigningKey() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const seed = (
    privateKey.export({ format: "der", type: "pkcs8" }) as Buffer
  ).subarray(-32);
  return { kid: "k-" + Math.random().toString(36).slice(2), privateKey: new Uint8Array(seed) };
}

const anchor: AnchorProof = {
  log: "https://verify.dekimu.com/alr/v1",
  leaf_index: 0,
  inclusion_proof: [],
  tree_head_root: "sha256:" + "0".repeat(64),
  tree_size: 1,
  log_time: "2026-05-17T00:00:00Z",
};

const baseCommon = {
  issuer: "did:web:processor.example",
  profile: "aiact.art13.transparency" as const,
  artifact_hash: H("c"),
  event_at: "2026-05-16T14:23:00Z",
  policy_uri: "https://processor.example/lineage-policy",
  policy_hash: "sha256:" + "e".repeat(64),
  policy_version: "1.0.0",
  anchor,
};

function makeResolveKey() {
  return async (envelope: unknown): Promise<Uint8Array> => {
    const issKey = (envelope as { iss_key: string }).iss_key;
    const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
    return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
  };
}

test("mintDerivedFrom round-trips", async () => {
  const env = await mintDerivedFrom({
    ...baseCommon,
    signingKey: makeSigningKey(),
    parents: [{ artifact_hash: H("a"), parent_apr_id: null, parent_alr_id: null, uri: null }],
    transform_claim: { summary: "x", uri: null },
  });
  assert.equal((env.body as { event_type: string }).event_type, "derived_from");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintForkedFrom round-trips", async () => {
  const env = await mintForkedFrom({
    ...baseCommon,
    signingKey: makeSigningKey(),
    parents: [{ artifact_hash: H("a"), parent_apr_id: null, parent_alr_id: null, uri: null }],
  });
  assert.equal((env.body as { event_type: string }).event_type, "forked_from");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintSupersededBy round-trips", async () => {
  const env = await mintSupersededBy({
    ...baseCommon,
    signingKey: makeSigningKey(),
    successor: { artifact_hash: H("b"), parent_apr_id: null, parent_alr_id: null, uri: null },
    transform_claim: { summary: "x", uri: null },
  });
  assert.equal((env.body as { event_type: string }).event_type, "superseded_by");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});

test("mintDisclosed round-trips", async () => {
  const env = await mintDisclosed({
    ...baseCommon,
    signingKey: makeSigningKey(),
    disclosure: {
      recipient: "did:web:auditor.example",
      recipient_role: "auditor",
      scope_hash: H("d"),
      basis: "gdpr.art6.1.c",
    },
  });
  assert.equal((env.body as { event_type: string }).event_type, "disclosed");
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, r.reason ?? "ok");
});
