/**
 * Hand-curated RFC 8785 edge-case corpus for JCS canonicalization.
 *
 * 21 cases covering: IEEE 754 number formatting, empty structures, null,
 * key sorting (UTF-16, special chars, Unicode NFC), nested structures,
 * mixed-type arrays, string escapes, booleans, deep nesting.
 *
 * Reference: RFC 8785 §3 + Appendix B (test vectors).
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { canonicalize } from "../src/canonicalize.ts";

interface CorpusCase {
  label: string;
  input: unknown;
  expected: string;
}

const corpus: CorpusCase[] = [
  // ---- IEEE 754 number formatting ----------------------------------------
  {
    label: "zero",
    input: 0,
    expected: "0",
  },
  {
    label: "negative zero → 0 (IEEE 754 -0 serialized as 0 per RFC 8785 §3.2.2.3)",
    input: -0,
    expected: "0",
  },
  {
    label: "float: 1.5",
    input: 1.5,
    expected: "1.5",
  },
  {
    label: "large integer: 1000000",
    input: 1_000_000,
    expected: "1000000",
  },
  {
    label: "scientific notation boundary: 1e21",
    input: 1e21,
    expected: "1e+21",
  },
  {
    label: "small float: 1e-7",
    input: 1e-7,
    expected: "1e-7",
  },
  // ---- Empty structures ---------------------------------------------------
  {
    label: "empty object",
    input: {},
    expected: "{}",
  },
  {
    label: "empty array",
    input: [],
    expected: "[]",
  },
  // ---- Null ---------------------------------------------------------------
  {
    label: "null scalar",
    input: null,
    expected: "null",
  },
  // ---- Key sorting (UTF-16 code unit) ------------------------------------
  {
    label: "keys sorted: a before b before z",
    input: { z: 3, a: 1, b: 2 },
    expected: '{"a":1,"b":2,"z":3}',
  },
  {
    label: "uppercase before lowercase in UTF-16: Z < a",
    input: { a: 1, Z: 2 },
    expected: '{"Z":2,"a":1}',
  },
  {
    label: "digits before letters in UTF-16: 1 < a",
    input: { a: "alpha", "1": "one" },
    expected: '{"1":"one","a":"alpha"}',
  },
  {
    label: "special char keys: sorted by code unit",
    input: { "!": true, " ": false },
    expected: '{" ":false,"!":true}',
  },
  // ---- Unicode NFC normalization -----------------------------------------
  {
    label: "NFC-normalised key: café (precomposed) stays as-is",
    input: { "café": "value" },
    expected: '{"caf\u00e9":"value"}',
  },
  // ---- Nested structures -------------------------------------------------
  {
    label: "nested objects: keys sorted at every level",
    input: { z: { b: 2, a: 1 }, a: { y: 9, x: 8 } },
    expected: '{"a":{"x":8,"y":9},"z":{"a":1,"b":2}}',
  },
  {
    label: "nested array of objects",
    input: { items: [{ b: 2, a: 1 }, { d: 4, c: 3 }] },
    expected: '{"items":[{"a":1,"b":2},{"c":3,"d":4}]}',
  },
  // ---- Mixed-type arrays -------------------------------------------------
  {
    label: "mixed-type array: null, bool, number, string",
    input: [null, true, false, 42, "hello"],
    expected: '[null,true,false,42,"hello"]',
  },
  // ---- String escapes ----------------------------------------------------
  {
    label: "string with backslash and quote",
    input: { s: 'say "hi"' },
    expected: '{"s":"say \\"hi\\""}',
  },
  {
    label: "string with newline",
    input: { s: "line1\nline2" },
    expected: '{"s":"line1\\nline2"}',
  },
  // ---- Booleans ----------------------------------------------------------
  {
    label: "boolean true",
    input: true,
    expected: "true",
  },
  // ---- Deep nesting ------------------------------------------------------
  {
    label: "deeply nested object: 4 levels",
    input: { a: { b: { c: { d: 42 } } } },
    expected: '{"a":{"b":{"c":{"d":42}}}}',
  },
];

describe("JCS canonicalize fuzz corpus (RFC 8785 edge cases)", () => {
  for (const { label, input, expected } of corpus) {
    it(label, () => {
      assert.equal(canonicalize(input), expected);
    });
  }
});
