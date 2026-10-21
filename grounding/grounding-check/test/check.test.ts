import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { check } from "../src/check.ts";

const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const SRC = "The cat sat on the mat. Dogs bark loudly.";

test("binds spans, hashes, scores, computes arithmetic", () => {
  const r = check({
    answer: "Cats sit on mats. Birds fly.",
    sources: [{ source_id: "s1", text: SRC }],
    claims: [{ claim_id: "c1", text: "cat sat mat" }, { claim_id: "c2", text: "birds fly" }],
    citations: [{ claim_id: "c1", source_id: "s1", start: 0, end: 22 }],
    threshold: 0.6,
  });
  assert.equal(r.citations[0].span_commit, sha(SRC.slice(0, 22)));
  assert.equal(r.sources[0].source_commit, sha(SRC));
  assert.equal(r.citations[0].support, "supported");   // all 3 claim tokens in span
  assert.equal(r.coverage, 0.5);                        // c1 cited, c2 not → 1/2
  assert.equal(r.grounded_count, 1);
  assert.equal(r.scorer.method, "lexical_overlap");
});

test("out-of-bounds span is a hard error (binding cannot be faked)", () => {
  assert.throws(() => check({
    answer: "x", sources: [{ source_id: "s1", text: "short" }],
    claims: [{ claim_id: "c1", text: "x" }],
    citations: [{ claim_id: "c1", source_id: "s1", start: 0, end: 999 }],
  }), /span out of bounds|end/i);
});

test("end<=start is a hard error", () => {
  assert.throws(() => check({
    answer: "x", sources: [{ source_id: "s1", text: "short" }],
    claims: [{ claim_id: "c1", text: "x" }],
    citations: [{ claim_id: "c1", source_id: "s1", start: 3, end: 3 }],
  }), /end must be > start/i);
});

test("citation referencing unknown source/claim is a hard error", () => {
  assert.throws(() => check({
    answer: "x", sources: [{ source_id: "s1", text: "short" }],
    claims: [{ claim_id: "c1", text: "x" }],
    citations: [{ claim_id: "c1", source_id: "MISSING", start: 0, end: 2 }],
  }), /unknown source_id/i);
});

test("no citations → coverage 0, grounded_count 0", () => {
  const r = check({ answer: "a", sources: [{ source_id: "s1", text: "z" }], claims: [{ claim_id: "c1", text: "a" }], citations: [] });
  assert.equal(r.coverage, 0);
  assert.equal(r.grounded_count, 0);
});
