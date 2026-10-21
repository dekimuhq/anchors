/**
 * Tests for mintGroundingV1 — the AGrR v=2 issuer-kit. Verify-before-sign,
 * subject null, ar.grounding.v1. Chip 18.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as crypto from "node:crypto";
import type { AnchorProof } from "@dekimuhq/anchors-envelope";
import { base64UrlDecode } from "@dekimuhq/anchors-envelope";
import { check } from "@dekimuhq/grounding-check";
import type {
  CheckSource,
  CheckClaim,
  CheckCitation,
} from "@dekimuhq/grounding-check";
import { verifyGroundingBody } from "../src/verify-single.ts";
import { verifyReceipt } from "../src/index.ts";
import { mintGroundingV1 } from "../src/issue/mint-v1.ts";
import type { MintGroundingInput } from "../src/issue/mint-v1.ts";

const ED25519_SPKI_PREFIX = Buffer.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

const SCORED_AT = "2026-06-20T10:00:00.000Z";

// ── Fixtures ──────────────────────────────────────────────────────────────────
// The span "Paris is the capital of France" fully covers claim "Paris is the
// capital of France" → lexicalOverlap === 1 ≥ threshold → support "supported".

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

// doc-1[0:31] === "Paris is the capital of France." → covers c1 fully.
// doc-2[0:55] covers c2.
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

function baseInput(): MintGroundingInput {
  return {
    issuer: "did:web:app.dekimu.com",
    signingKey: makeSigningKey(),
    anchor: makeAnchor(),
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
    scored_at: SCORED_AT,
  };
}

// ── M1: mints a verifiable receipt, round-trips valid ──────────────────────────

test("M1: mints a verifiable grounding receipt (round-trip signature_valid)", async () => {
  const env = await mintGroundingV1(baseInput());
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, (r as { reason?: string }).reason ?? "ok");
  assert.equal(r.envelope_version, 2);
  assert.equal(r.claim_type, "ar.grounding.v1");
});

// ── M2: subject is null (must-be-null invariant) ───────────────────────────────

test("M2: subject is null", async () => {
  const env = await mintGroundingV1(baseInput());
  assert.equal(env.subject, null);
});

// ── M3: claim_type ar.grounding.v1, v=2 ────────────────────────────────────────

test("M3: produces v=2 envelope with claim_type ar.grounding.v1", async () => {
  const env = await mintGroundingV1(baseInput());
  assert.equal(env.v, 2);
  assert.equal(env.claim_type, "ar.grounding.v1");
});

// ── M4: body passes verifyGroundingBody + commits are 64-hex ────────────────────

test("M4: minted body passes verifyGroundingBody and binds commits", async () => {
  const env = await mintGroundingV1(baseInput());
  const r = verifyGroundingBody(env.body);
  assert.equal(r.valid, true, r.errors.join(","));
  const body = env.body as Record<string, unknown>;
  assert.match(String(body.answer_commit), /^[0-9a-f]{64}$/);
});

// ── M5: derived fields match the engine ────────────────────────────────────────

test("M5: coverage + grounded_count match the engine re-check", async () => {
  const env = await mintGroundingV1(baseInput());
  const expected = check({
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.coverage, expected.coverage);
  assert.equal(body.grounded_count, expected.grounded_count);
  assert.equal(body.coverage, 1); // both claims cited
  assert.equal(body.grounded_count, 2); // both supported
});

// ── M6: sig non-empty + field_root present ─────────────────────────────────────

test("M6: sig non-empty and body carries field_root", async () => {
  const env = await mintGroundingV1(baseInput());
  assert.equal(typeof env.sig, "string");
  assert.ok(env.sig.length > 0);
  const body = env.body as Record<string, unknown>;
  assert.equal(typeof body.field_root, "string");
  assert.ok((body.field_root as string).length > 0);
});

// ── M7: mint WITHOUT a supplied result works ───────────────────────────────────

test("M7: mint without a supplied result succeeds", async () => {
  const env = await mintGroundingV1(baseInput());
  const r = verifyGroundingBody(env.body);
  assert.equal(r.valid, true, r.errors.join(","));
});

// ── M8: supplied result agreeing with the re-check is accepted ──────────────────

test("M8: supplied result agreeing with the re-check is accepted", async () => {
  const result = check({
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
  });
  const env = await mintGroundingV1({ ...baseInput(), result });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, (r as { reason?: string }).reason ?? "ok");
});

// ── M9: supplied result that disagrees → rejected (verify-before-sign) ──────────

test("M9: supplied result disagreeing with re-check is rejected (coverage)", async () => {
  const result = check({
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
  });
  const tampered = { ...result, coverage: 0.5 };
  await assert.rejects(
    () => mintGroundingV1({ ...baseInput(), result: tampered }),
    /disagrees with re-check/,
  );
});

test("M10: supplied result disagreeing on a span_commit is rejected", async () => {
  const result = check({
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
  });
  const tampered = {
    ...result,
    citations: result.citations.map((c, i) =>
      i === 0 ? { ...c, span_commit: "f".repeat(64) } : c,
    ),
  };
  await assert.rejects(
    () => mintGroundingV1({ ...baseInput(), result: tampered }),
    /disagrees with re-check/,
  );
});

test("M11: supplied result disagreeing on a score is rejected", async () => {
  const result = check({
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
  });
  const tampered = {
    ...result,
    citations: result.citations.map((c, i) =>
      i === 0 ? { ...c, score: 0.123 } : c,
    ),
  };
  await assert.rejects(
    () => mintGroundingV1({ ...baseInput(), result: tampered }),
    /disagrees with re-check/,
  );
});

test("M12: supplied result disagreeing on answer_commit is rejected", async () => {
  const result = check({
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
  });
  const tampered = { ...result, answer_commit: "a".repeat(64) };
  await assert.rejects(
    () => mintGroundingV1({ ...baseInput(), result: tampered }),
    /disagrees with re-check/,
  );
});

test("M13: supplied result disagreeing on grounded_count is rejected", async () => {
  const result = check({
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
  });
  const tampered = { ...result, grounded_count: 0 };
  await assert.rejects(
    () => mintGroundingV1({ ...baseInput(), result: tampered }),
    /disagrees with re-check/,
  );
});

test("M14: supplied result disagreeing on a source_commit is rejected", async () => {
  const result = check({
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
  });
  const tampered = {
    ...result,
    sources: result.sources.map((s, i) =>
      i === 0 ? { ...s, source_commit: "b".repeat(64) } : s,
    ),
  };
  await assert.rejects(
    () => mintGroundingV1({ ...baseInput(), result: tampered }),
    /disagrees with re-check/,
  );
});

test("M15: supplied result disagreeing on scorer threshold is rejected", async () => {
  const result = check({
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
  });
  const tampered = { ...result, scorer: { ...result.scorer, threshold: 0.99 } };
  await assert.rejects(
    () => mintGroundingV1({ ...baseInput(), result: tampered }),
    /disagrees with re-check/,
  );
});

// ── M16: custom threshold flows into the scorer + verify-before-sign ────────────

test("M16: custom threshold flows into scorer and a result built at the default threshold is rejected", async () => {
  // Build a result at the DEFAULT threshold but mint at threshold 0.9 → mismatch.
  const defaultResult = check({
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
  });
  await assert.rejects(
    () =>
      mintGroundingV1({ ...baseInput(), threshold: 0.9, result: defaultResult }),
    /disagrees with re-check/,
  );
  // And a matching result at 0.9 is accepted.
  const r09 = check({
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations: CITATIONS,
    threshold: 0.9,
  });
  const env = await mintGroundingV1({
    ...baseInput(),
    threshold: 0.9,
    result: r09,
  });
  const body = env.body as { scorer: { threshold: number } };
  assert.equal(body.scorer.threshold, 0.9);
});

// ── M17: optional fields round-trip ────────────────────────────────────────────

test("M17: answer_media_type + credential_id + caveats_consumed round-trip", async () => {
  const env = await mintGroundingV1({
    ...baseInput(),
    answer_media_type: "text/markdown",
    credential_id: "cred-xyz",
    caveats_consumed: {
      data_scope: "tenant:acme",
      spend_step: 1,
      capability: "operator.answer",
    },
  });
  const body = env.body as Record<string, unknown>;
  assert.equal(body.answer_media_type, "text/markdown");
  assert.equal(body.credential_id, "cred-xyz");
  assert.deepEqual(body.caveats_consumed, {
    data_scope: "tenant:acme",
    spend_step: 1,
    capability: "operator.answer",
  });
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, (r as { reason?: string }).reason ?? "ok");
});

// ── M18: rejects empty issuer ──────────────────────────────────────────────────

test("M18: rejects empty issuer", async () => {
  await assert.rejects(
    () => mintGroundingV1({ ...baseInput(), issuer: "" }),
    /issuer required/,
  );
});

// ── M19: rejects non-32-byte signing key ───────────────────────────────────────

test("M19: rejects non-32-byte signing key", async () => {
  await assert.rejects(
    () =>
      mintGroundingV1({
        ...baseInput(),
        signingKey: { kid: "k", privateKey: new Uint8Array(16) },
      }),
    /must be 32 bytes/,
  );
});

// ── M20: rejects missing scored_at ─────────────────────────────────────────────

test("M20: rejects missing scored_at", async () => {
  await assert.rejects(
    () => mintGroundingV1({ ...baseInput(), scored_at: "" }),
    /scored_at is required/,
  );
});

// ── M21: rejects tsa config without tsaFetcher ─────────────────────────────────

test("M21: rejects tsa config without tsaFetcher", async () => {
  await assert.rejects(
    () =>
      mintGroundingV1({
        ...baseInput(),
        tsa: { url: "https://tsa.example", hashAlg: "sha256" } as never,
      }),
    /tsaFetcher required/,
  );
});

// ── M22: multi-source, partially-grounded fixture ──────────────────────────────

test("M22: partially-grounded multi-citation answer mints + round-trips", async () => {
  // c2 cited with a poorly-overlapping span → not "supported".
  const citations: CheckCitation[] = [
    { claim_id: "c1", source_id: "doc-1", start: 0, end: 31 }, // strong
    { claim_id: "c2", source_id: "doc-1", start: 31, end: 60 }, // weak overlap
  ];
  const env = await mintGroundingV1({ ...baseInput(), citations });
  const expected = check({
    answer: ANSWER,
    sources: SOURCES,
    claims: CLAIMS,
    citations,
  });
  const body = env.body as { coverage: number; grounded_count: number };
  assert.equal(body.coverage, expected.coverage);
  assert.equal(body.grounded_count, expected.grounded_count);
  const r = await verifyReceipt(env, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, (r as { reason?: string }).reason ?? "ok");
});

// ── M23: explicit null envelope_kind is honoured ───────────────────────────────

test("M23: explicit null envelope_kind is honoured (default observation otherwise)", async () => {
  const def = await mintGroundingV1(baseInput());
  assert.equal(def.kind, "observation");
  const nullKind = await mintGroundingV1({ ...baseInput(), envelope_kind: null });
  assert.equal(nullKind.kind, null);
  const r = await verifyReceipt(nullKind, { resolveKey: makeResolveKey() });
  assert.equal(r.signature_valid, true, (r as { reason?: string }).reason ?? "ok");
});
