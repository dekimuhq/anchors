/**
 * Property-based tests for JCS canonicalization (RFC 8785).
 *
 * Uses a lightweight hand-rolled runner (no external dependencies) that
 * generates random inputs and asserts invariants over N trials.
 */

import { describe, it } from "node:test";
import * as assert from "node:assert/strict";
import { canonicalize } from "../src/canonicalize.ts";

// ---------------------------------------------------------------------------
// Minimal property-test helpers
// ---------------------------------------------------------------------------

// Keys always start with a lowercase letter to avoid V8's integer-indexed
// property promotion, which re-orders digit-only or small-integer keys before
// string keys during JSON.stringify regardless of insertion order.
const LETTERS = "abcdefghijklmnopqrstuvwxyz";
function randomString(maxLen = 12): string {
  const first = LETTERS[Math.floor(Math.random() * LETTERS.length)];
  const rest = Math.random().toString(36).slice(2, 1 + Math.floor(Math.random() * maxLen) + 1);
  return first + rest;
}

function randomScalar(): unknown {
  const r = Math.random();
  if (r < 0.25) return Math.floor(Math.random() * 10000);
  if (r < 0.5) return randomString();
  if (r < 0.75) return Math.random() < 0.5;
  return null;
}

function randomKeys(n: number): string[] {
  const out = new Set<string>();
  while (out.size < n) out.add(randomString(8));
  return Array.from(out);
}

function randomFlatObject(maxKeys = 6): Record<string, unknown> {
  const keys = randomKeys(1 + Math.floor(Math.random() * maxKeys));
  const obj: Record<string, unknown> = {};
  for (const k of keys) obj[k] = randomScalar();
  return obj;
}

function forAll<T>(
  label: string,
  runs: number,
  gen: () => T,
  check: (value: T) => void,
): void {
  for (let i = 0; i < runs; i++) {
    const value = gen();
    try {
      check(value);
    } catch (err) {
      throw new Error(
        `Property "${label}" failed on run ${i + 1}:\n  input: ${JSON.stringify(value)}\n  error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

describe("JCS canonicalize property-based tests", () => {
  it("idempotence: canonicalize(parse(canonicalize(x))) === canonicalize(x) (500 runs)", () => {
    forAll(
      "idempotence",
      500,
      () => randomFlatObject(),
      (obj) => {
        const first = canonicalize(obj);
        const second = canonicalize(JSON.parse(first));
        assert.equal(second, first);
      },
    );
  });

  it("key ordering: keys sorted by UTF-16 code unit (200 runs)", () => {
    forAll(
      "key ordering",
      200,
      () => randomFlatObject(8),
      (obj) => {
        const result = canonicalize(obj);
        // Extract key order from the raw JSON string to avoid V8's integer-key
        // reordering that Object.keys() applies after JSON.parse().
        // Keys appear as `"<key>":` in the output; grab them in appearance order.
        const keyPattern = /"([^"\\]*)"\s*:/g;
        const keysInOutput: string[] = [];
        let m: RegExpExecArray | null;
        while ((m = keyPattern.exec(result)) !== null) {
          keysInOutput.push(m[1]!);
        }
        // Verify each adjacent pair is in non-decreasing JS default sort order.
        // JS default sort is locale-independent lexicographic (UTF-16 code unit).
        for (let i = 1; i < keysInOutput.length; i++) {
          const prev = keysInOutput[i - 1]!;
          const curr = keysInOutput[i]!;
          const cmp = prev < curr ? -1 : prev > curr ? 1 : 0;
          assert.ok(
            cmp <= 0,
            `key "${prev}" should sort before "${curr}" but appears after it in: ${result}`,
          );
        }
      },
    );
  });

  it("no whitespace in output (200 runs)", () => {
    forAll(
      "no whitespace",
      200,
      () => randomFlatObject(),
      (obj) => {
        const result = canonicalize(obj);
        // RFC 8785 §3.2: no insignificant whitespace
        assert.equal(/[ \t\n\r]/.test(result), false, `found whitespace in: ${result}`);
      },
    );
  });

  it("NaN and Infinity are rejected", () => {
    assert.throws(() => canonicalize(NaN), /non-finite/);
    assert.throws(() => canonicalize(Infinity), /non-finite/);
    assert.throws(() => canonicalize(-Infinity), /non-finite/);
    assert.throws(() => canonicalize({ x: NaN }), /non-finite/);
    assert.throws(() => canonicalize({ x: Infinity }), /non-finite/);
  });

  it("circular references are rejected", () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj["self"] = obj;
    assert.throws(() => canonicalize(obj), /circular/);

    const arr: unknown[] = [1, 2];
    arr.push(arr);
    assert.throws(() => canonicalize(arr), /circular/);
  });
});
