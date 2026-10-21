/**
 * JSON Logic AST types for the v1.2 envelope `predicate` field.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope §5.2
 *
 * Operator surface is restricted to the 22-operator allowlist defined in
 * jsonlogic-allowlist.ts. Operators outside the allowlist make the receipt
 * invalid (L5). The grammar below mirrors the standard JSON Logic operator
 * set chosen for the v1.2 amendment — no custom or extension operators.
 */

/** Primitive operand atoms — JSON-Logic leaves. */
export type JsonLogicAtom = string | number | boolean | null;

/** Recursive operand value — atom, nested AST, or an array of operand values. */
export type JsonLogicValue = JsonLogicAtom | JsonLogicAst | JsonLogicValue[];

/** Pinned 22-operator AST per spec §5.1. */
export type JsonLogicAst =
  // Equality (4)
  | { "==": [JsonLogicValue, JsonLogicValue] }
  | { "===": [JsonLogicValue, JsonLogicValue] }
  | { "!=": [JsonLogicValue, JsonLogicValue] }
  | { "!==": [JsonLogicValue, JsonLogicValue] }
  // Boolean (4)
  | { "!": JsonLogicValue }
  | { "!!": JsonLogicValue }
  | { "and": JsonLogicValue[] }
  | { "or": JsonLogicValue[] }
  // Ordering (4) — `<`/`<=` support the 3-ary between form per §5.1.
  | { ">": [JsonLogicValue, JsonLogicValue] }
  | { ">=": [JsonLogicValue, JsonLogicValue] }
  | { "<": [JsonLogicValue, JsonLogicValue] | [JsonLogicValue, JsonLogicValue, JsonLogicValue] }
  | { "<=": [JsonLogicValue, JsonLogicValue] | [JsonLogicValue, JsonLogicValue, JsonLogicValue] }
  // Arithmetic (5)
  | { "+": JsonLogicValue[] }
  | { "-": JsonLogicValue[] }
  | { "*": JsonLogicValue[] }
  | { "/": [JsonLogicValue, JsonLogicValue] }
  | { "%": [JsonLogicValue, JsonLogicValue] }
  // Conditional (1) — chained `if [c1, t1, c2, t2, …, else]` supported.
  | { "if": JsonLogicValue[] }
  // Set / membership (4)
  | { "in": [JsonLogicValue, JsonLogicValue] }
  | { "all": [JsonLogicValue, JsonLogicAst] }
  | { "none": [JsonLogicValue, JsonLogicAst] }
  | { "some": [JsonLogicValue, JsonLogicAst] }
  // Data access (3)
  | { "var": string | [string] | [string, JsonLogicValue] }
  | { "missing": string[] }
  | { "missing_some": [number, string[]] }
  // Bounds (2)
  | { "min": JsonLogicValue[] }
  | { "max": JsonLogicValue[] };
