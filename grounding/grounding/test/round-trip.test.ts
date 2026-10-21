/**
 * Tests for the top-level verifyReceipt (envelope dispatch + end-to-end verify)
 * and tamper-evidence of the signed AGrR body.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import type {
  CheckSource,
  CheckClaim,
  CheckCitation,
} from "@dekimuhq/grounding-check";
import { mintGroundingV1 } from "../src/issue/mint-v1.ts";
import { verifyReceipt } from "../src/index.ts";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

const ANSWER = "The capital of France is Paris. The Eiffel Tower is in Paris.";

const SOURCES: CheckSource[] = [
  {
    source_id: "doc-1",
    text: "Paris is the capital of France. It is a large European city.",
    media_type: "text/plain",
  },
  {
    source_id: "doc-2",
    text: "The Eiffel Tower is a landmark located in Paris, France.",
  },
];

const CLAIMS: CheckClaim[] = [
  { claim_id: "c1", text: "Paris is the capital of France" },
  { claim_id: "c2", text: "The Eiffel Tower is in Paris" },
];

const CITATIONS: CheckCitation[] = [
  { claim_id: "c1", source_id: "doc-1", start: 0, end: 31 },
  { claim_id: "c2", source_id: "doc-2", start: 0, end: 55 },
];

function makeSigningKey() {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const seed = (
    privateKey.export({ format: "der", type: "pkcs8" }) as Buffer
  ).subarray(-32);
  return {
    kid: "k-" + crypto.randomBytes(6).toString("hex"),
    privateKey: new Uint8Array(seed),
  };
}

function makeAnchor(): AnchorProof {
  return {
    log: "https://verify.dekimu.com/grounding/v1",
    leaf_index: 0,
    inclusion_proof: [],
    tree_head_root: "sha256:" + "aa".repeat(32),
    tree_size: 1,
    log_time: "2026-06-20T00:00:00.000Z",
  };
}

function makeResolveKey() {
  return async (envelope: unknown): Promise<Uint8Array> => {
    const issKey = (envelope as { iss_key: string }).iss_key;
    const raw = base64UrlDecode(issKey.replace("ed25519:", ""));
    return new Uint8Array(Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(raw)]));
  };
}

function mint() {
  return mintGroundingV1({
    issuer: "did:web:app.dekimu.com",
    signingKey: makeSigningKey(),
    anchor: makeAnchor(),
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
    scored_at: "2026-06-20T10:00:00.000Z",
  });
}

// ── dispatch fallbacks ─────────────────────────────────────────────────────────

test("RT1: non-object input → schema_invalid", async () => {
  const r = await verifyReceipt("not-an-object");
  assert.equal(r.envelope_version, "unknown");
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "schema_invalid");
});

test("RT2: null input → schema_invalid", async () => {
  const r = await verifyReceipt(null);
  assert.equal(r.envelope_version, "unknown");
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "schema_invalid");
});

test("RT3: v=1 input → unsupported_envelope_version", async () => {
  const r = await verifyReceipt({ v: 1, claim_type: "ar.grounding.v1" });
  assert.equal(r.envelope_version, "unknown");
  assert.equal(r.signature_valid, false);
  assert.equal(r.reason, "unsupported_envelope_version");
});

// ── happy path ─────────────────────────────────────────────────────────────────

test("RT4: mint → verifyReceipt round-trips valid", async () => {
  const env = await mint();
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, (r as { reason?: string }).reason ?? "ok");
  assert.equal(r.envelope_version, 2);
  assert.equal(r.claim_type, "ar.grounding.v1");
});

test("RT5: no resolver → signature_valid:false, no throw", async () => {
  const env = await mint();
  const r = await verifyReceipt(env);
  assert.equal(r.envelope_version, 2);
  assert.equal(r.signature_valid, false);
});

// ── tamper evidence ──────────────────────────────────────────────────────────--

test("RT6: mutating body.coverage breaks signature", async () => {
  const env = await mint();
  const tampered = {
    ...env,
    body: { ...(env.body as object), coverage: 0.5 },
  };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.envelope_version, 2);
  assert.equal(r.signature_valid, false);
});

test("RT7: mutating a citation span_commit breaks signature", async () => {
  const env = await mint();
  const body = env.body as { citations: Array<Record<string, unknown>> };
  const tampered = {
    ...env,
    body: {
      ...(env.body as object),
      citations: body.citations.map((c, i) =>
        i === 0 ? { ...c, span_commit: "f".repeat(64) } : c,
      ),
    },
  };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.envelope_version, 2);
  assert.equal(r.signature_valid, false);
});

test("RT8: mutating answer_commit breaks signature", async () => {
  const env = await mint();
  const tampered = {
    ...env,
    body: { ...(env.body as object), answer_commit: "a".repeat(64) },
  };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});

test("RT9: mutating grounded_count breaks signature", async () => {
  const env = await mint();
  const tampered = {
    ...env,
    body: { ...(env.body as object), grounded_count: 0 },
  };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});

test("RT10: setting a non-null subject breaks signature", async () => {
  const env = await mint();
  const tampered = { ...env, subject: "sha256:" + "b".repeat(64) };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});

test("RT11: mutating the scorer threshold breaks signature", async () => {
  const env = await mint();
  const body = env.body as { scorer: Record<string, unknown> };
  const tampered = {
    ...env,
    body: {
      ...(env.body as object),
      scorer: { ...body.scorer, threshold: 0.99 },
    },
  };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});

test("RT12: mutating scored_at breaks signature", async () => {
  const env = await mint();
  const tampered = {
    ...env,
    body: { ...(env.body as object), scored_at: "2020-01-01T00:00:00.000Z" },
  };
  const r = await verifyReceipt(tampered, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, false);
});
