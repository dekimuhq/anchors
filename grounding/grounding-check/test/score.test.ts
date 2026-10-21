import { test } from "node:test";
import assert from "node:assert/strict";
import { tokenize } from "../src/tokenize.ts";
import { lexicalOverlap, supportFor, SCORER_NAME, SCORER_VERSION, DEFAULT_THRESHOLD } from "../src/score.ts";

test("tokenize is deterministic + lowercases + splits on non-word", () => {
  assert.deepEqual(tokenize("The Cat, sat!"), ["the", "cat", "sat"]);
  assert.deepEqual(tokenize("café CAFÉ"), ["café", "café"]);
  assert.deepEqual(tokenize("  "), []);
});

test("lexicalOverlap = fraction of claim tokens present in span", () => {
  assert.equal(lexicalOverlap("cat sat", "the cat sat on a mat"), 1);   // both present
  assert.equal(lexicalOverlap("cat dog", "the cat ran"), 0.5);          // 1 of 2
  assert.equal(lexicalOverlap("dog", "the cat ran"), 0);                // none
  assert.equal(lexicalOverlap("", "anything"), 0);                      // empty claim → 0 (no support)
});

test("supportFor uses ordered mapping (threshold-0 safe)", () => {
  assert.equal(supportFor(0, 0), "unsupported");      // score 0 always unsupported
  assert.equal(supportFor(0.5, 0.7), "partial");
  assert.equal(supportFor(0.7, 0.7), "supported");
  assert.equal(supportFor(1, 0.7), "supported");
});

test("scorer identity constants are non-empty", () => {
  assert.ok(SCORER_NAME.length > 0 && SCORER_VERSION.length > 0);
  assert.ok(DEFAULT_THRESHOLD >= 0 && DEFAULT_THRESHOLD <= 1);
});
