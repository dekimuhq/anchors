import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyGroundingBody } from "../src/verify-single.ts";

const H = "a".repeat(64);

function validBody() {
  return {
    profile: "grounding.rag",
    answer_commit: H,
    sources: [{ source_id: "s1", source_commit: H }],
    claims: [{ claim_id: "c1", claim_commit: H }, { claim_id: "c2", claim_commit: H }],
    citations: [{ claim_id: "c1", source_id: "s1", start: 0, end: 5, span_commit: H, support: "supported", score: 0.9 }],
    coverage: 0.5,
    grounded_count: 1,
    scorer: { method: "lexical_overlap", name: "dekimu/grounding-check", version: "1.0.0", threshold: 0.6 },
    scored_at: "2026-06-20T10:00:00Z",
  };
}

test("rejects non-object (null)", () => {
  const r = verifyGroundingBody(null);
  assert.equal(r.valid, false);
  assert.ok(r.errors.length > 0);
  assert.equal(r.body, null);
});

test("rejects non-object (string)", () => {
  assert.equal(verifyGroundingBody("string").valid, false);
});

test("rejects unknown profile", () => {
  const r = verifyGroundingBody({ profile: "x" });
  assert.equal(r.valid, false);
  assert.ok(r.errors[0]?.includes("unknown profile"));
});

test("rejects wrong profile (guard.input)", () => {
  const r = verifyGroundingBody({ profile: "guard.input" });
  assert.equal(r.valid, false);
});

test("rejects missing profile", () => {
  assert.equal(verifyGroundingBody({}).valid, false);
});

test("accepts a valid grounding.rag body", () => {
  const r = verifyGroundingBody(validBody());
  assert.equal(r.valid, true);
  assert.equal(r.errors.length, 0);
  assert.ok(r.body !== null);
  assert.equal(r.body?.profile, "grounding.rag");
});

test("delegates shape rejects to validateGroundingRag (bad coverage)", () => {
  const b = validBody();
  b.coverage = 1; // mismatch — should be 0.5
  const r = verifyGroundingBody(b);
  assert.equal(r.valid, false);
  assert.ok(r.errors.length > 0);
});

test("delegates shape rejects to validateGroundingRag (bad scored_at)", () => {
  const b = validBody() as Record<string, unknown>;
  b.scored_at = "not-a-date";
  const r = verifyGroundingBody(b);
  assert.equal(r.valid, false);
});
