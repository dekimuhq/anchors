import { test } from "node:test";
import { strict as assert } from "node:assert";
import {
  AIR_MONTH_MS,
  AIR_PROFILE_ERROR_CODES,
  AIR_PROFILE_WARNING_CODES,
  AIR_REVIEW_WINDOW_MONTHS_STRICT,
  AIR_REVIEW_WINDOW_MONTHS_VOLUNTARY,
  AIR_V1_PROFILES,
  isNonEmptyStringArray,
  parseTimestamp,
} from "../src/index.ts";

test("types: AIR_V1_PROFILES has five entries", () => {
  assert.equal(AIR_V1_PROFILES.length, 5);
});

test("types: AIR_V1_PROFILES entries are all unique", () => {
  assert.equal(new Set(AIR_V1_PROFILES).size, AIR_V1_PROFILES.length);
});

test("types: AIR_REVIEW_WINDOW_MONTHS_STRICT is 12", () => {
  assert.equal(AIR_REVIEW_WINDOW_MONTHS_STRICT, 12);
});

test("types: AIR_REVIEW_WINDOW_MONTHS_VOLUNTARY is 36", () => {
  assert.equal(AIR_REVIEW_WINDOW_MONTHS_VOLUNTARY, 36);
});

test("types: AIR_MONTH_MS approximates 30.4375 days", () => {
  assert.equal(AIR_MONTH_MS, 30.4375 * 86_400_000);
});

test("types: error code PROFILE_MISMATCH is stable", () => {
  assert.equal(AIR_PROFILE_ERROR_CODES.PROFILE_MISMATCH, "profile.mismatch");
});

test("types: every warning code is a non-empty snake_case literal", () => {
  const codes = Object.values(AIR_PROFILE_WARNING_CODES);
  for (const c of codes) {
    assert.equal(typeof c, "string");
    assert.ok(c.length > 0);
    assert.ok(/^[a-z][a-z0-9_]*$/.test(c), `code=${c}`);
  }
});

test("isNonEmptyStringArray: accepts non-empty array of non-empty strings", () => {
  assert.equal(isNonEmptyStringArray(["a"]), true);
  assert.equal(isNonEmptyStringArray(["a", "b"]), true);
});

test("isNonEmptyStringArray: rejects empty array", () => {
  assert.equal(isNonEmptyStringArray([]), false);
});

test("isNonEmptyStringArray: rejects null / undefined / non-array", () => {
  assert.equal(isNonEmptyStringArray(null), false);
  assert.equal(isNonEmptyStringArray(undefined), false);
  assert.equal(isNonEmptyStringArray("a"), false);
  assert.equal(isNonEmptyStringArray({ 0: "a", length: 1 }), false);
});

test("isNonEmptyStringArray: rejects array containing an empty string", () => {
  assert.equal(isNonEmptyStringArray([""]), false);
  assert.equal(isNonEmptyStringArray(["a", ""]), false);
});

test("isNonEmptyStringArray: rejects array containing a non-string", () => {
  assert.equal(isNonEmptyStringArray(["a", 1]), false);
  assert.equal(isNonEmptyStringArray(["a", null]), false);
  assert.equal(isNonEmptyStringArray(["a", undefined]), false);
});

test("parseTimestamp: parses a valid ISO 8601 UTC string", () => {
  const ms = parseTimestamp("2026-01-01T00:00:00Z");
  assert.equal(typeof ms, "number");
  assert.equal(ms, Date.parse("2026-01-01T00:00:00Z"));
});

test("parseTimestamp: returns null for empty / null / undefined", () => {
  assert.equal(parseTimestamp(""), null);
  assert.equal(parseTimestamp(null), null);
  assert.equal(parseTimestamp(undefined), null);
});

test("parseTimestamp: returns null for non-string input", () => {
  // @ts-expect-error — testing runtime guard for non-string inputs
  assert.equal(parseTimestamp(123), null);
});

test("parseTimestamp: returns null for unparseable string", () => {
  assert.equal(parseTimestamp("not-a-date"), null);
});

test("parseTimestamp: accepts non-Z offsets per RFC 3339", () => {
  const ms = parseTimestamp("2026-01-01T00:00:00+00:00");
  assert.equal(ms, Date.parse("2026-01-01T00:00:00Z"));
});

test("parseTimestamp: round-trips through Date.toISOString()", () => {
  const original = "2027-06-15T12:34:56.000Z";
  const ms = parseTimestamp(original);
  assert.equal(new Date(ms!).toISOString(), original);
});
