import { test } from "node:test";
import assert from "node:assert/strict";
import { validateGroundingRag } from "../src/validate.ts";

// 64-char hex string used as a valid sha-256 placeholder
const H = "a".repeat(64);
// A different valid hex to use for distinctness where needed
const H2 = "b".repeat(64);

/** Returns a fresh valid grounding.rag body. Mutate one field per reject test. */
function valid() {
  return {
    profile: "grounding.rag" as const,
    answer_commit: H,
    sources: [{ source_id: "s1", source_commit: H }, { source_id: "s2", source_commit: H2 }],
    claims: [
      { claim_id: "c1", claim_commit: H },
      { claim_id: "c2", claim_commit: H },
    ],
    citations: [
      { claim_id: "c1", source_id: "s1", start: 0, end: 5, span_commit: H, support: "supported" as const, score: 0.9 },
    ],
    // coverage = 1 cited claim (c1) / 2 claims = 0.5
    coverage: 0.5,
    // grounded_count = 1 (c1 has ≥1 "supported" citation)
    grounded_count: 1,
    scorer: { method: "lexical_overlap" as const, name: "dekimu/grounding-check", version: "1.0.0", threshold: 0.6 },
    scored_at: "2026-06-20T10:00:00Z",
  };
}

// ── ACCEPT ────────────────────────────────────────────────────────────────

test("accepts a valid grounding.rag body", () => {
  const r = validateGroundingRag(valid());
  assert.equal(r.ok, true);
  assert.deepEqual(r.errors, []);
});

test("accepts body with no citations (coverage 0, grounded_count 0)", () => {
  const b = { ...valid(), citations: [], coverage: 0, grounded_count: 0 };
  assert.equal(validateGroundingRag(b).ok, true);
});

test("accepts body where all claims are cited and supported (coverage 1, grounded_count 2)", () => {
  const b = {
    ...valid(),
    citations: [
      { claim_id: "c1", source_id: "s1", start: 0, end: 5, span_commit: H, support: "supported" as const, score: 0.9 },
      { claim_id: "c2", source_id: "s2", start: 0, end: 5, span_commit: H2, support: "supported" as const, score: 0.8 },
    ],
    coverage: 1,
    grounded_count: 2,
  };
  assert.equal(validateGroundingRag(b).ok, true);
});

test("accepts body with partial support citation (grounded_count 0 if no supported)", () => {
  // c1 cited but only partial — grounded_count stays 0
  const b = {
    ...valid(),
    claims: [{ claim_id: "c1", claim_commit: H }],
    citations: [
      { claim_id: "c1", source_id: "s1", start: 0, end: 5, span_commit: H, support: "partial" as const, score: 0.5 },
    ],
    coverage: 1,
    grounded_count: 0,
    sources: [{ source_id: "s1", source_commit: H }],
  };
  assert.equal(validateGroundingRag(b).ok, true);
});

test("accepts body with score === 0 → unsupported", () => {
  const b = {
    ...valid(),
    claims: [{ claim_id: "c1", claim_commit: H }],
    citations: [
      { claim_id: "c1", source_id: "s1", start: 0, end: 5, span_commit: H, support: "unsupported" as const, score: 0 },
    ],
    coverage: 1,
    grounded_count: 0,
    sources: [{ source_id: "s1", source_commit: H }],
  };
  assert.equal(validateGroundingRag(b).ok, true);
});

test("accepts body with threshold === 0 (score 0.1 → supported)", () => {
  // threshold 0: score 0.1 >= 0 → supported (but score === 0 is always unsupported first)
  const b = {
    ...valid(),
    claims: [{ claim_id: "c1", claim_commit: H }],
    citations: [
      { claim_id: "c1", source_id: "s1", start: 0, end: 5, span_commit: H, support: "supported" as const, score: 0.1 },
    ],
    coverage: 1,
    grounded_count: 1,
    sources: [{ source_id: "s1", source_commit: H }],
    scorer: { method: "lexical_overlap" as const, name: "dekimu/grounding-check", version: "1.0.0", threshold: 0 },
  };
  assert.equal(validateGroundingRag(b).ok, true);
});

test("accepts optional fields when present (answer_media_type, credential_id, caveats_consumed)", () => {
  const b = {
    ...valid(),
    answer_media_type: "text/markdown",
    credential_id: "cred-123",
    caveats_consumed: {
      data_scope: "user:123",
      spend_step: 1,
      capability: "operator.draft-reminder",
    },
  };
  assert.equal(validateGroundingRag(b).ok, true);
});

test("accepts optional caveats_consumed with spend_currency", () => {
  const b = {
    ...valid(),
    caveats_consumed: {
      data_scope: "user:456",
      spend_step: 2,
      spend_currency: "EUR",
      capability: "operator.something",
    },
  };
  assert.equal(validateGroundingRag(b).ok, true);
});

test("accepts source with optional media_type", () => {
  const b = {
    ...valid(),
    sources: [{ source_id: "s1", source_commit: H, media_type: "text/plain" }, { source_id: "s2", source_commit: H2 }],
  };
  assert.equal(validateGroundingRag(b).ok, true);
});

test("accepts multiple citations for the same claim (coverage still 0.5 = 1/2)", () => {
  // Two citations for c1, none for c2
  const b = {
    ...valid(),
    citations: [
      { claim_id: "c1", source_id: "s1", start: 0, end: 5, span_commit: H, support: "supported" as const, score: 0.9 },
      { claim_id: "c1", source_id: "s2", start: 0, end: 3, span_commit: H2, support: "partial" as const, score: 0.4 },
    ],
    coverage: 0.5,
    grounded_count: 1,
  };
  assert.equal(validateGroundingRag(b).ok, true);
});

test("accepts scored_at with fractional seconds", () => {
  const b = { ...valid(), scored_at: "2026-06-20T10:00:00.123Z" };
  assert.equal(validateGroundingRag(b).ok, true);
});

test("accepts scored_at with timezone offset", () => {
  const b = { ...valid(), scored_at: "2026-06-20T12:00:00+02:00" };
  assert.equal(validateGroundingRag(b).ok, true);
});

test("accepts threshold === 1 (only score 1.0 → supported, else partial)", () => {
  const b = {
    ...valid(),
    claims: [{ claim_id: "c1", claim_commit: H }],
    citations: [
      { claim_id: "c1", source_id: "s1", start: 0, end: 5, span_commit: H, support: "supported" as const, score: 1 },
    ],
    coverage: 1,
    grounded_count: 1,
    sources: [{ source_id: "s1", source_commit: H }],
    scorer: { method: "lexical_overlap" as const, name: "dekimu/grounding-check", version: "1.0.0", threshold: 1 },
  };
  assert.equal(validateGroundingRag(b).ok, true);
});

// ── REJECT: profile ────────────────────────────────────────────────────────

test("rejects wrong profile", () => {
  const b = { ...valid(), profile: "guard.input" } as unknown;
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects missing profile", () => {
  const { profile: _, ...b } = valid();
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: hex commits ────────────────────────────────────────────────────

test("rejects non-hex answer_commit", () => {
  const b = { ...valid(), answer_commit: "not-hex" };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects answer_commit that is only 63 chars (too short)", () => {
  const b = { ...valid(), answer_commit: "a".repeat(63) };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects answer_commit with uppercase hex", () => {
  const b = { ...valid(), answer_commit: "A".repeat(64) };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects non-hex source_commit", () => {
  const b = { ...valid(), sources: [{ source_id: "s1", source_commit: "ZZ".repeat(32) }, { source_id: "s2", source_commit: H2 }] };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects non-hex claim_commit", () => {
  const b = { ...valid(), claims: [{ claim_id: "c1", claim_commit: "not-hex" }, { claim_id: "c2", claim_commit: H }] };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects non-hex span_commit", () => {
  const b = { ...valid() };
  b.citations[0] = { ...b.citations[0], span_commit: "not-hex-at-all" };
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: empty arrays ───────────────────────────────────────────────────

test("rejects empty sources array", () => {
  const b = { ...valid(), sources: [] };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects empty claims array", () => {
  const b = { ...valid(), claims: [] };
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: duplicate ids ──────────────────────────────────────────────────

test("rejects duplicate source_id", () => {
  const b = { ...valid(), sources: [{ source_id: "s1", source_commit: H }, { source_id: "s1", source_commit: H2 }] };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects duplicate claim_id", () => {
  const b = { ...valid(), claims: [{ claim_id: "c1", claim_commit: H }, { claim_id: "c1", claim_commit: H2 }] };
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: referential integrity ─────────────────────────────────────────

test("rejects citation with dangling source_id", () => {
  const b = { ...valid() };
  b.citations[0] = { ...b.citations[0], source_id: "no-such-source" };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects citation with dangling claim_id", () => {
  const b = { ...valid() };
  b.citations[0] = { ...b.citations[0], claim_id: "no-such-claim" };
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: span offsets ───────────────────────────────────────────────────

test("rejects end <= start (end === start)", () => {
  const b = { ...valid() };
  b.citations[0] = { ...b.citations[0], start: 5, end: 5 };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects end < start", () => {
  const b = { ...valid() };
  b.citations[0] = { ...b.citations[0], start: 10, end: 3 };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects negative start offset", () => {
  const b = { ...valid() };
  b.citations[0] = { ...b.citations[0], start: -1, end: 5 };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects non-integer start offset", () => {
  const b = { ...valid() };
  b.citations[0] = { ...b.citations[0], start: 0.5, end: 5 };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects non-integer end offset", () => {
  const b = { ...valid() };
  b.citations[0] = { ...b.citations[0], start: 0, end: 4.9 };
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: score bounds ───────────────────────────────────────────────────

test("rejects score > 1", () => {
  const b = { ...valid() };
  b.citations[0] = { ...b.citations[0], score: 1.01 };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects score < 0", () => {
  const b = { ...valid() };
  b.citations[0] = { ...b.citations[0], score: -0.1 };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects non-number score", () => {
  const b = { ...valid() } as unknown as Record<string, unknown>;
  (b["citations"] as Array<Record<string, unknown>>)[0]["score"] = "high";
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: support↔score coherence ───────────────────────────────────────

test("rejects support/score mismatch: score 0 but support is partial", () => {
  const b = valid();
  // score === 0 must be "unsupported"; intentionally setting wrong value via unknown cast
  (b.citations[0] as unknown as Record<string, unknown>)["score"] = 0;
  (b.citations[0] as unknown as Record<string, unknown>)["support"] = "partial";
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects support/score mismatch: score 0.9 >= threshold 0.6 but support is partial", () => {
  const b = valid();
  // score 0.9 >= threshold 0.6 → should be "supported", not "partial"
  (b.citations[0] as unknown as Record<string, unknown>)["score"] = 0.9;
  (b.citations[0] as unknown as Record<string, unknown>)["support"] = "partial";
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects support/score mismatch: score 0.4 < threshold 0.6 but support is supported", () => {
  const b = valid();
  // score 0.4 < 0.6 → should be "partial", not "supported"
  // (it was originally "supported" with score 0.9 in valid(); change score only)
  (b.citations[0] as unknown as Record<string, unknown>)["score"] = 0.4;
  // support stays "supported" — that's the mismatch we're testing
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects support/score mismatch: score 0.5 == threshold 0.5 but support is partial (boundary: exact == supported)", () => {
  const b = valid();
  // Change scorer threshold to 0.5, set score 0.5 → should be "supported" not "partial"
  (b.scorer as unknown as Record<string, unknown>)["threshold"] = 0.5;
  (b.citations[0] as unknown as Record<string, unknown>)["score"] = 0.5;
  (b.citations[0] as unknown as Record<string, unknown>)["support"] = "partial";
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: coverage mismatch ─────────────────────────────────────────────

test("rejects coverage mismatch (says 1 but 1 of 2 claims cited = 0.5)", () => {
  const b = { ...valid(), coverage: 1 };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects coverage mismatch (says 0 but 1 of 2 claims cited = 0.5)", () => {
  const b = { ...valid(), coverage: 0 };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects coverage mismatch (says 0.75 but actual is 0.5)", () => {
  const b = { ...valid(), coverage: 0.75 };
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: grounded_count mismatch ───────────────────────────────────────

test("rejects grounded_count mismatch (says 2 but only 1 claim has supported citation)", () => {
  const b = { ...valid(), grounded_count: 2 };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects grounded_count mismatch (says 0 but 1 claim has supported citation)", () => {
  const b = { ...valid(), grounded_count: 0 };
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: scorer ─────────────────────────────────────────────────────────

test("rejects bad scorer.method", () => {
  const b = { ...valid(), scorer: { ...valid().scorer, method: "nli" as unknown as "lexical_overlap" } };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects threshold > 1", () => {
  const b = { ...valid(), scorer: { ...valid().scorer, threshold: 1.01 } };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects threshold < 0", () => {
  const b = { ...valid(), scorer: { ...valid().scorer, threshold: -0.1 } };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects empty scorer.version", () => {
  const b = { ...valid(), scorer: { ...valid().scorer, version: "" } };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects empty scorer.name", () => {
  const b = { ...valid(), scorer: { ...valid().scorer, name: "" } };
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: scored_at ──────────────────────────────────────────────────────

test("rejects invalid scored_at (not a date)", () => {
  const b = { ...valid(), scored_at: "not-a-date" };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects scored_at missing time zone (bare ISO date)", () => {
  const b = { ...valid(), scored_at: "2026-06-20" };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects scored_at without seconds", () => {
  const b = { ...valid(), scored_at: "2026-06-20T10:00Z" };
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: missing required fields ───────────────────────────────────────

test("rejects non-object body", () => {
  assert.equal(validateGroundingRag(null).ok, false);
  assert.equal(validateGroundingRag(42).ok, false);
  assert.equal(validateGroundingRag("string").ok, false);
});

test("rejects missing answer_commit", () => {
  const { answer_commit: _, ...b } = valid();
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects missing scorer", () => {
  const { scorer: _, ...b } = valid();
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects missing scored_at", () => {
  const { scored_at: _, ...b } = valid();
  assert.equal(validateGroundingRag(b).ok, false);
});

// ── REJECT: invalid optional fields when present ───────────────────────────

test("rejects invalid caveats_consumed (missing capability)", () => {
  const b = {
    ...valid(),
    caveats_consumed: {
      data_scope: "user:123",
      spend_step: 1,
      // capability missing
    } as unknown,
  };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects caveats_consumed.spend_step that is not a number", () => {
  const b = {
    ...valid(),
    caveats_consumed: {
      data_scope: "user:123",
      spend_step: "one" as unknown as number,
      capability: "foo",
    },
  };
  assert.equal(validateGroundingRag(b).ok, false);
});

test("rejects support enum value not in allowed set", () => {
  const b = { ...valid() } as unknown as Record<string, unknown>;
  (b["citations"] as Array<Record<string, unknown>>)[0]["support"] = "maybe";
  assert.equal(validateGroundingRag(b).ok, false);
});
