import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalize } from "../src/canonicalize.ts";

test("canonicalize sorts object keys lexicographically", () => {
  const out = canonicalize({ b: 1, a: 2 });
  assert.equal(out, '{"a":2,"b":1}');
});

test("canonicalize is stable across nested objects", () => {
  const out = canonicalize({ z: { b: 1, a: 2 }, a: 3 });
  assert.equal(out, '{"a":3,"z":{"a":2,"b":1}}');
});

test("canonicalize preserves null", () => {
  const out = canonicalize({ a: null });
  assert.equal(out, '{"a":null}');
});

test("canonicalize handles arrays as-is (order preserved)", () => {
  const out = canonicalize({ a: [3, 1, 2] });
  assert.equal(out, '{"a":[3,1,2]}');
});
