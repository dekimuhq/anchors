/**
 * Tests for the v1.2 JSON Logic evaluator (Phase B, Task B3).
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope §5
 *
 * Coverage rule: ≥2 positive + 1 negative per operator group across the
 * 27-operator allowlist, plus dedicated fixtures for iteration context
 * shift, 3-ary between form, var-path escapes, arithmetic-by-zero error
 * classes, short-circuit semantics, missing/missing_some, and the four
 * worked examples from spec §5.5.
 */

import { test } from "node:test";
import * as assert from "node:assert/strict";

import {
  evaluate,
  JsonLogicError,
  JsonLogicDivisionByZero,
  JsonLogicModuloByZero,
  JsonLogicVarPathInvalid,
} from "../src/jsonlogic-eval.ts";
import type { JsonLogicAst } from "../src/jsonlogic-types.ts";

// ── Equality (4) ────────────────────────────────────────────────────────────

test("eval == loose equality true", () => {
  assert.strictEqual(evaluate({ "==": [1, "1"] } as JsonLogicAst, {}), true);
});
test("eval == loose equality false", () => {
  assert.strictEqual(evaluate({ "==": [1, 2] } as JsonLogicAst, {}), false);
});
test("eval == negative: distinct types coerce false", () => {
  assert.strictEqual(evaluate({ "==": ["foo", 1] } as JsonLogicAst, {}), false);
});

test("eval === strict equality true", () => {
  assert.strictEqual(evaluate({ "===": ["analytics", "analytics"] } as JsonLogicAst, {}), true);
});
test("eval === strict equality false on type mismatch", () => {
  assert.strictEqual(evaluate({ "===": [1, "1"] } as JsonLogicAst, {}), false);
});
test("eval === negative: null !== undefined-resolved", () => {
  assert.strictEqual(evaluate({ "===": [{ var: "missing.path" }, null] } as JsonLogicAst, {}), true);
});

test("eval != true on differing values", () => {
  assert.strictEqual(evaluate({ "!=": [1, 2] } as JsonLogicAst, {}), true);
});
test("eval != false on coerced equal", () => {
  assert.strictEqual(evaluate({ "!=": [1, "1"] } as JsonLogicAst, {}), false);
});
test("eval != negative: equal strings should not differ", () => {
  assert.strictEqual(evaluate({ "!=": ["x", "x"] } as JsonLogicAst, {}), false);
});

test("eval !== true on type mismatch", () => {
  assert.strictEqual(evaluate({ "!==": [1, "1"] } as JsonLogicAst, {}), true);
});
test("eval !== false on identical strings", () => {
  assert.strictEqual(evaluate({ "!==": ["a", "a"] } as JsonLogicAst, {}), false);
});
test("eval !== negative: same number not strict-different", () => {
  assert.strictEqual(evaluate({ "!==": [3, 3] } as JsonLogicAst, {}), false);
});

// ── Boolean (4) ─────────────────────────────────────────────────────────────

test("eval ! negates truthy", () => {
  assert.strictEqual(evaluate({ "!": 1 } as unknown as JsonLogicAst, {}), false);
});
test("eval ! negates falsy", () => {
  assert.strictEqual(evaluate({ "!": 0 } as unknown as JsonLogicAst, {}), true);
});
test("eval ! negative: array-wrapped truthy still negates to false", () => {
  assert.strictEqual(evaluate({ "!": ["x"] } as unknown as JsonLogicAst, {}), false);
});

test("eval !! coerces truthy to true", () => {
  assert.strictEqual(evaluate({ "!!": "non-empty" } as unknown as JsonLogicAst, {}), true);
});
test("eval !! coerces empty string to false", () => {
  assert.strictEqual(evaluate({ "!!": "" } as unknown as JsonLogicAst, {}), false);
});
test("eval !! negative: empty array is falsy", () => {
  assert.strictEqual(evaluate({ "!!": [[]] } as unknown as JsonLogicAst, {}), false);
});

test("eval and returns last truthy value (not boolean)", () => {
  assert.strictEqual(evaluate({ and: [1, "hello"] } as JsonLogicAst, {}), "hello");
});
test("eval and short-circuits on first falsy", () => {
  assert.strictEqual(evaluate({ and: [1, 0, "never"] } as JsonLogicAst, {}), 0);
});
test("eval and negative: not all truthy → returns falsy operand", () => {
  assert.strictEqual(evaluate({ and: [true, false, true] } as JsonLogicAst, {}), false);
});

test("eval or returns first truthy operand", () => {
  assert.strictEqual(evaluate({ or: [0, "hit", "never"] } as JsonLogicAst, {}), "hit");
});
test("eval or returns last operand if all falsy", () => {
  assert.strictEqual(evaluate({ or: [0, "", null] } as JsonLogicAst, {}), null);
});
test("eval or negative: returns falsy when no truthy", () => {
  assert.strictEqual(evaluate({ or: [false, 0] } as JsonLogicAst, {}), 0);
});

// ── Ordering (4) ────────────────────────────────────────────────────────────

test("eval > greater true", () => {
  assert.strictEqual(evaluate({ ">": [5, 3] } as JsonLogicAst, {}), true);
});
test("eval > equal is false", () => {
  assert.strictEqual(evaluate({ ">": [5, 5] } as JsonLogicAst, {}), false);
});
test("eval > negative: lesser returns false", () => {
  assert.strictEqual(evaluate({ ">": [1, 2] } as JsonLogicAst, {}), false);
});

test("eval >= greater true", () => {
  assert.strictEqual(evaluate({ ">=": [5, 3] } as JsonLogicAst, {}), true);
});
test("eval >= equal is true", () => {
  assert.strictEqual(evaluate({ ">=": [5, 5] } as JsonLogicAst, {}), true);
});
test("eval >= negative: lesser returns false", () => {
  assert.strictEqual(evaluate({ ">=": [1, 2] } as JsonLogicAst, {}), false);
});

test("eval < binary less true", () => {
  assert.strictEqual(evaluate({ "<": [1, 2] } as JsonLogicAst, {}), true);
});
test("eval < binary equal is false", () => {
  assert.strictEqual(evaluate({ "<": [2, 2] } as JsonLogicAst, {}), false);
});
test("eval < 3-ary between-form true", () => {
  assert.strictEqual(evaluate({ "<": [1, 5, 10] } as JsonLogicAst, {}), true);
});
test("eval < 3-ary between-form false on equal mid", () => {
  // 1 < 5 && 5 < 5 → false
  assert.strictEqual(evaluate({ "<": [1, 5, 5] } as JsonLogicAst, {}), false);
});
test("eval < negative: out-of-range returns false", () => {
  assert.strictEqual(evaluate({ "<": [1, 10, 5] } as JsonLogicAst, {}), false);
});

test("eval <= binary equal true", () => {
  assert.strictEqual(evaluate({ "<=": [5, 5] } as JsonLogicAst, {}), true);
});
test("eval <= 3-ary inclusive between true", () => {
  assert.strictEqual(evaluate({ "<=": [1, 1, 10] } as JsonLogicAst, {}), true);
});
test("eval <= 3-ary negative: outside range returns false", () => {
  assert.strictEqual(evaluate({ "<=": [1, 11, 10] } as JsonLogicAst, {}), false);
});

// ── Arithmetic (5) ──────────────────────────────────────────────────────────

test("eval + adds variadic", () => {
  assert.strictEqual(evaluate({ "+": [1, 2, 3] } as JsonLogicAst, {}), 6);
});
test("eval + unary returns the operand as number", () => {
  assert.strictEqual(evaluate({ "+": ["7"] } as JsonLogicAst, {}), 7);
});
test("eval + negative: string concat does NOT apply — coerces to number", () => {
  // "1" + "2" is NOT "12" in JSON Logic spec; we coerce to numbers.
  assert.strictEqual(evaluate({ "+": ["1", "2"] } as JsonLogicAst, {}), 3);
});

test("eval - subtracts pair", () => {
  assert.strictEqual(evaluate({ "-": [10, 4] } as JsonLogicAst, {}), 6);
});
test("eval - unary negates", () => {
  assert.strictEqual(evaluate({ "-": [5] } as JsonLogicAst, {}), -5);
});
test("eval - negative: variadic subtract chains", () => {
  assert.strictEqual(evaluate({ "-": [10, 4, 2] } as JsonLogicAst, {}), 4);
});

test("eval * multiplies variadic", () => {
  assert.strictEqual(evaluate({ "*": [2, 3, 4] } as JsonLogicAst, {}), 24);
});
test("eval * single arg returns itself", () => {
  assert.strictEqual(evaluate({ "*": [7] } as JsonLogicAst, {}), 7);
});
test("eval * negative: zero short-circuits arithmetically to 0", () => {
  assert.strictEqual(evaluate({ "*": [2, 0, 99] } as JsonLogicAst, {}), 0);
});

test("eval / divides", () => {
  assert.strictEqual(evaluate({ "/": [10, 2] } as JsonLogicAst, {}), 5);
});
test("eval / fractional", () => {
  assert.strictEqual(evaluate({ "/": [1, 4] } as JsonLogicAst, {}), 0.25);
});
test("eval / throws JsonLogicDivisionByZero with stable code", () => {
  assert.throws(
    () => evaluate({ "/": [1, 0] } as JsonLogicAst, {}),
    (err: unknown) => {
      return (
        err instanceof JsonLogicDivisionByZero &&
        err.code === "predicate_division_by_zero" &&
        err instanceof JsonLogicError
      );
    },
  );
});

test("eval % modulo", () => {
  assert.strictEqual(evaluate({ "%": [10, 3] } as JsonLogicAst, {}), 1);
});
test("eval % returns zero on clean divisor", () => {
  assert.strictEqual(evaluate({ "%": [9, 3] } as JsonLogicAst, {}), 0);
});
test("eval % throws JsonLogicModuloByZero with stable code", () => {
  assert.throws(
    () => evaluate({ "%": [1, 0] } as JsonLogicAst, {}),
    (err: unknown) => {
      return (
        err instanceof JsonLogicModuloByZero &&
        err.code === "predicate_modulo_by_zero" &&
        err instanceof JsonLogicError
      );
    },
  );
});

// ── Conditional (1) ─────────────────────────────────────────────────────────

test("eval if returns then-branch on truthy cond", () => {
  assert.strictEqual(evaluate({ if: [true, "yes", "no"] } as JsonLogicAst, {}), "yes");
});
test("eval if returns else-branch on falsy cond", () => {
  assert.strictEqual(evaluate({ if: [false, "yes", "no"] } as JsonLogicAst, {}), "no");
});
test("eval if chained selects matching arm", () => {
  // if [c1, t1, c2, t2, else]
  assert.strictEqual(
    evaluate({ if: [false, "a", true, "b", "fallback"] } as JsonLogicAst, {}),
    "b",
  );
});
test("eval if chained falls through to else", () => {
  assert.strictEqual(
    evaluate({ if: [false, "a", false, "b", "fallback"] } as JsonLogicAst, {}),
    "fallback",
  );
});
test("eval if negative: no match + no else → null", () => {
  assert.strictEqual(evaluate({ if: [false, "a"] } as JsonLogicAst, {}), null);
});

// ── Set / membership (4) ────────────────────────────────────────────────────

test("eval in array membership true", () => {
  assert.strictEqual(evaluate({ in: ["x", ["x", "y"]] } as JsonLogicAst, {}), true);
});
test("eval in array membership false", () => {
  assert.strictEqual(evaluate({ in: ["z", ["x", "y"]] } as JsonLogicAst, {}), false);
});
test("eval in substring match", () => {
  assert.strictEqual(evaluate({ in: ["foo", "foobar"] } as JsonLogicAst, {}), true);
});
test("eval in negative: null haystack returns false", () => {
  assert.strictEqual(evaluate({ in: ["x", null] } as JsonLogicAst, {}), false);
});

test("eval all true on all-match", () => {
  const ast: JsonLogicAst = { all: [[1, 2, 3], { ">": [{ var: "" }, 0] }] };
  assert.strictEqual(evaluate(ast, {}), true);
});
test("eval all false when one fails", () => {
  const ast: JsonLogicAst = { all: [[1, 0, 3], { ">": [{ var: "" }, 0] }] };
  assert.strictEqual(evaluate(ast, {}), false);
});
test("eval all negative: empty array returns false (JSON Logic convention)", () => {
  const ast: JsonLogicAst = { all: [[], { ">": [{ var: "" }, 0] }] };
  assert.strictEqual(evaluate(ast, {}), false);
});

test("eval none true on no-match", () => {
  const ast: JsonLogicAst = { none: [[1, 2, 3], { "<": [{ var: "" }, 0] }] };
  assert.strictEqual(evaluate(ast, {}), true);
});
test("eval none false when one matches", () => {
  const ast: JsonLogicAst = { none: [[1, -2, 3], { "<": [{ var: "" }, 0] }] };
  assert.strictEqual(evaluate(ast, {}), false);
});
test("eval none negative: non-array collection returns true", () => {
  const ast: JsonLogicAst = { none: [null as unknown as never, { ">": [{ var: "" }, 0] }] };
  assert.strictEqual(evaluate(ast, {}), true);
});

test("eval some true on one-match", () => {
  const ast: JsonLogicAst = { some: [[1, 2, 3], { ">": [{ var: "" }, 2] }] };
  assert.strictEqual(evaluate(ast, {}), true);
});
test("eval some false on zero-match", () => {
  const ast: JsonLogicAst = { some: [[1, 2, 3], { ">": [{ var: "" }, 99] }] };
  assert.strictEqual(evaluate(ast, {}), false);
});
test("eval some negative: empty array returns false", () => {
  const ast: JsonLogicAst = { some: [[], { ">": [{ var: "" }, 0] }] };
  assert.strictEqual(evaluate(ast, {}), false);
});

// Iteration context shift — the critical correctness fixture.
test("iteration context shift: {var: ''} reads the element itself", () => {
  // Note: the inner array holds plain records (element shape), which aren't
  // members of `JsonLogicValue`. We `as unknown as JsonLogicAst` to bypass —
  // the evaluator itself accepts arbitrary `unknown` element ctx at runtime.
  const ast = {
    some: [
      [{ x: false }, { x: true }, { x: false }],
      { "===": [{ var: "x" }, true] },
    ],
  } as unknown as JsonLogicAst;
  assert.strictEqual(evaluate(ast, { unrelated: "outer" }), true);
});
test("iteration context shift: outer ctx is NOT visible inside inner predicate", () => {
  // The inner predicate runs against the element, so `{var: "outer_only"}`
  // must resolve to null — not "leaked" from the outer ctx.
  const ast = {
    all: [[{ a: 1 }, { a: 2 }], { "===": [{ var: "outer_only" }, "outer"] }],
  } as unknown as JsonLogicAst;
  assert.strictEqual(evaluate(ast, { outer_only: "outer" }), false);
});
test("iteration context shift: element fields read via {var:'field'}", () => {
  const ast = {
    all: [[{ ok: true }, { ok: true }], { "===": [{ var: "ok" }, true] }],
  } as unknown as JsonLogicAst;
  assert.strictEqual(evaluate(ast, {}), true);
});

// ── Data access (3) ─────────────────────────────────────────────────────────

test("eval var dotted path resolves nested", () => {
  assert.strictEqual(
    evaluate({ var: "body.subject_age" } as JsonLogicAst, { body: { subject_age: 17 } }),
    17,
  );
});
test("eval var missing terminal returns null", () => {
  assert.strictEqual(
    evaluate({ var: "body.nope" } as JsonLogicAst, { body: { subject_age: 17 } }),
    null,
  );
});
test("eval var with default fallback", () => {
  assert.strictEqual(
    evaluate({ var: ["body.nope", "fallback"] } as JsonLogicAst, { body: {} }),
    "fallback",
  );
});
test("eval var array form pulls path from [0]", () => {
  assert.strictEqual(evaluate({ var: ["body.x"] } as JsonLogicAst, { body: { x: 42 } }), 42);
});
test("eval var numeric path indexes arrays", () => {
  assert.strictEqual(
    evaluate({ var: "list.1" } as JsonLogicAst, { list: ["a", "b", "c"] }),
    "b",
  );
});
test("eval var negative: __proto__ throws JsonLogicVarPathInvalid", () => {
  assert.throws(
    () => evaluate({ var: "__proto__" } as JsonLogicAst, {}),
    (err: unknown) =>
      err instanceof JsonLogicVarPathInvalid && err.code === "predicate_var_path_invalid",
  );
});
test("eval var negative: constructor segment throws", () => {
  assert.throws(
    () => evaluate({ var: "body.constructor" } as JsonLogicAst, { body: {} }),
    (err: unknown) => err instanceof JsonLogicVarPathInvalid,
  );
});
test("eval var negative: prototype segment throws", () => {
  assert.throws(
    () => evaluate({ var: "body.prototype" } as JsonLogicAst, { body: {} }),
    (err: unknown) => err instanceof JsonLogicVarPathInvalid,
  );
});
test("eval var negative: `..` traversal segment throws", () => {
  assert.throws(
    () => evaluate({ var: "body..purpose" } as JsonLogicAst, { body: {} }),
    (err: unknown) => err instanceof JsonLogicVarPathInvalid,
  );
});
test("eval var negative: backslash escape char throws", () => {
  assert.throws(
    () => evaluate({ var: "body\\purpose" } as JsonLogicAst, { body: {} }),
    (err: unknown) => err instanceof JsonLogicVarPathInvalid,
  );
});

test("eval missing returns missing keys", () => {
  const result = evaluate(
    { missing: ["body.a", "body.b"] } as JsonLogicAst,
    { body: { a: 1 } },
  );
  assert.deepStrictEqual(result, ["body.b"]);
});
test("eval missing returns empty when all present", () => {
  assert.deepStrictEqual(
    evaluate({ missing: ["a", "b"] } as JsonLogicAst, { a: 1, b: 2 }),
    [],
  );
});
test("eval missing negative: returns all when nothing present", () => {
  assert.deepStrictEqual(
    evaluate({ missing: ["x", "y"] } as JsonLogicAst, {}),
    ["x", "y"],
  );
});

test("eval missing_some empty when threshold met", () => {
  // 2 of [a,b,c] present, threshold 2 → empty
  assert.deepStrictEqual(
    evaluate({ missing_some: [2, ["a", "b", "c"]] } as JsonLogicAst, { a: 1, b: 2 }),
    [],
  );
});
test("eval missing_some lists missing when below threshold", () => {
  // Only 1 of [a,b,c] present, threshold 2 → list missing
  const result = evaluate(
    { missing_some: [2, ["a", "b", "c"]] } as JsonLogicAst,
    { a: 1 },
  );
  assert.deepStrictEqual(result, ["b", "c"]);
});
test("eval missing_some negative: threshold above total still lists all missing", () => {
  const result = evaluate(
    { missing_some: [5, ["a", "b"]] } as JsonLogicAst,
    {},
  );
  assert.deepStrictEqual(result, ["a", "b"]);
});

// ── Bounds (2) ──────────────────────────────────────────────────────────────

test("eval min picks smallest", () => {
  assert.strictEqual(evaluate({ min: [5, 1, 9, 3] } as JsonLogicAst, {}), 1);
});
test("eval min with single arg returns it", () => {
  assert.strictEqual(evaluate({ min: [42] } as JsonLogicAst, {}), 42);
});
test("eval min negative: empty args returns null", () => {
  assert.strictEqual(evaluate({ min: [] } as JsonLogicAst, {}), null);
});

test("eval max picks largest", () => {
  assert.strictEqual(evaluate({ max: [5, 1, 9, 3] } as JsonLogicAst, {}), 9);
});
test("eval max with single arg returns it", () => {
  assert.strictEqual(evaluate({ max: [42] } as JsonLogicAst, {}), 42);
});
test("eval max negative: empty args returns null", () => {
  assert.strictEqual(evaluate({ max: [] } as JsonLogicAst, {}), null);
});

// ── Spec §5.5 worked examples ───────────────────────────────────────────────

test("worked example 1: ACR consent — age ≥ 16 AND purpose in {analytics, fraud}", () => {
  const ast: JsonLogicAst = {
    and: [
      { ">=": [{ var: "body.subject_age" }, 16] },
      { in: [{ var: "body.purpose" }, ["analytics", "fraud"]] },
    ],
  };
  assert.strictEqual(
    evaluate(ast, { body: { subject_age: 16, purpose: "analytics" } }),
    true,
  );
});

test("worked example 2: AER erasure-eligible — retention_expires_at < iat_ms", () => {
  const ast: JsonLogicAst = {
    "<": [{ var: "body.retention_expires_at" }, { var: "iat_ms" }],
  };
  const ctx = {
    iat_ms: 1_780_000_000_000,
    body: { retention_expires_at: 1_770_000_000_000 },
  };
  assert.strictEqual(evaluate(ast, ctx), true);
});

test("worked example 3: ATR transfer permitted — EEA destination OR adequacy decision", () => {
  const eea = [
    "AT","BE","BG","HR","CY","CZ","DK","EE","FI","FR","DE","GR","HU","IE","IT",
    "LV","LT","LU","MT","NL","PL","PT","RO","SK","SI","ES","SE",
  ];
  const ast: JsonLogicAst = {
    or: [
      { in: [{ var: "body.destination_country" }, eea] },
      { "===": [{ var: "body.adequacy_basis" }, "art45_adequacy_decision"] },
    ],
  };
  // EEA hit
  assert.strictEqual(
    evaluate(ast, { body: { destination_country: "DE", adequacy_basis: null } }),
    true,
  );
  // Non-EEA + adequacy
  assert.strictEqual(
    evaluate(ast, {
      body: { destination_country: "JP", adequacy_basis: "art45_adequacy_decision" },
    }),
    true,
  );
});

test("worked example 4: AAR — at least one principal approved", () => {
  const ast: JsonLogicAst = {
    some: [
      { var: "body.principal_approvals" },
      { "===": [{ var: "" }, true] },
    ],
  };
  assert.strictEqual(
    evaluate(ast, { body: { principal_approvals: [false, true, false] } }),
    true,
  );
  assert.strictEqual(
    evaluate(ast, { body: { principal_approvals: [false, false] } }),
    false,
  );
});

// ── Determinism / pure-function smoke ───────────────────────────────────────

test("evaluator is pure: same inputs ⇒ same output across repeated calls", () => {
  const ast: JsonLogicAst = {
    and: [
      { ">=": [{ var: "body.subject_age" }, 16] },
      { in: [{ var: "body.purpose" }, ["analytics", "fraud"]] },
    ],
  };
  const ctx = { body: { subject_age: 21, purpose: "fraud" } };
  const a = evaluate(ast, ctx);
  const b = evaluate(ast, ctx);
  const c = evaluate(ast, ctx);
  assert.strictEqual(a, true);
  assert.strictEqual(a, b);
  assert.strictEqual(b, c);
});
