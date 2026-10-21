/**
 * Canonicalisation conformance — RFC 8785-lite, matching `apr-spec/v1.md` §4.1.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";
import { canonicalize } from "../src/canonicalize.ts";

test("sorts object keys by UTF-16 code unit", () => {
  assert.equal(
    canonicalize({ b: 1, a: 2, c: 3 }),
    '{"a":2,"b":1,"c":3}',
  );
});

test("nested objects sort recursively", () => {
  assert.equal(
    canonicalize({ b: { y: 1, x: 2 }, a: 3 }),
    '{"a":3,"b":{"x":2,"y":1}}',
  );
});

test("arrays preserve order", () => {
  assert.equal(canonicalize([3, 1, 2]), "[3,1,2]");
});

test("emits no whitespace", () => {
  const s = canonicalize({ a: 1, b: [1, 2, { c: 3 }] });
  assert.equal(s.includes(" "), false);
  assert.equal(s.includes("\n"), false);
  assert.equal(s.includes("\t"), false);
});

test("rejects NaN, Infinity, -Infinity", () => {
  assert.throws(() => canonicalize({ x: Number.NaN }));
  assert.throws(() => canonicalize({ x: Number.POSITIVE_INFINITY }));
  assert.throws(() => canonicalize({ x: Number.NEGATIVE_INFINITY }));
});

test("rejects undefined and bigint", () => {
  assert.throws(() => canonicalize({ x: undefined as unknown as number }));
  assert.throws(() => canonicalize({ x: 1n as unknown as number }));
});

test("rejects functions and symbols", () => {
  assert.throws(() => canonicalize({ x: (() => 0) as unknown as number }));
  assert.throws(() => canonicalize({ x: Symbol("x") as unknown as number }));
});

test("rejects circular references", () => {
  const a: Record<string, unknown> = {};
  a.self = a;
  assert.throws(() => canonicalize(a));
});

test("NFC-normalises strings", () => {
  // "é" composed (U+00E9) and decomposed (U+0065 U+0301) must canonicalise the same
  const composed = "é";
  const decomposed = "é";
  assert.equal(canonicalize({ x: composed }), canonicalize({ x: decomposed }));
});

test("preserves null and booleans", () => {
  assert.equal(canonicalize(null), "null");
  assert.equal(canonicalize(true), "true");
  assert.equal(canonicalize(false), "false");
});

test("emits numbers as JSON.stringify (round-trippable shortest form)", () => {
  assert.equal(canonicalize(0.1), "0.1");
  assert.equal(canonicalize(1e21), "1e+21");
  assert.equal(canonicalize(-0), "0");
});
