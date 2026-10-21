/**
 * Static AST validator for v1.2 envelope `predicate` fields.
 *
 * Walks a candidate JSON Logic AST once and reports the first structural
 * violation. Designed to run before the evaluator so a malformed or
 * out-of-allowlist predicate is rejected with a precise error code rather
 * than throwing during evaluation.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope §5 + §7
 * Plan: an internal design record (not published) Phase C
 *
 * Error codes produced (subset of spec §7):
 *   - predicate_malformed_ast        — not a single-key operator-object
 *                                      where one is required, or an
 *                                      operator-object whose argument shape
 *                                      doesn't match standard JSON Logic.
 *   - predicate_operator_not_allowed — operator key not in
 *                                      JSON_LOGIC_ALLOWLIST_V1_2.
 *   - predicate_var_path_invalid     — `var` path escapes the envelope tree
 *                                      (`..` segment, prototype access,
 *                                      control / escape character).
 *
 * Path classification follows spec §7 step 4 — escape-detection, NOT a
 * whitelist of envelope root field names. Inside iteration operators
 * (`all`/`some`/`none`) the element context shifts per standard JSON Logic
 * semantics; the validator stays purely structural and does not predict
 * the shape of the runtime ctx beyond rejecting tree-escape patterns.
 */

import { JSON_LOGIC_ALLOWLIST_V1_2 } from "./jsonlogic-allowlist.ts";

export type ValidateErrorCode =
  | "predicate_malformed_ast"
  | "predicate_operator_not_allowed"
  | "predicate_var_path_invalid";

export interface ValidateOk {
  readonly ok: true;
}

export interface ValidateErr {
  readonly ok: false;
  readonly code: ValidateErrorCode;
  /** Operator-path trace from the AST root to the first violation. */
  readonly path: readonly string[];
  /** Implementation-defined detail string — useful for debugging. */
  readonly detail: string;
}

export type ValidateResult = ValidateOk | ValidateErr;

const ALLOWLIST: ReadonlySet<string> = new Set<string>(JSON_LOGIC_ALLOWLIST_V1_2);

// Standard-JSON-Logic-compatible argument-shape table. Maps each allowed
// operator to its accepted argument shape so we can reject malformed ASTs.
//
// Shape values:
//   "unary"    — single operand (atom, AST, or array). e.g. `{"!": x}`.
//   "binary"   — exactly two operands (array of length 2).
//   "binOrTri" — array of length 2 or 3 (3-ary between form for `<`/`<=`).
//   "variadic" — array of any length (>= 0).
//   "var"      — string OR [string] OR [string, default].
//   "missing"  — string[] (array of strings).
//   "missingSome" — [number, string[]] (length-2 tuple).
type ArgShape =
  | "unary"
  | "binary"
  | "binOrTri"
  | "variadic"
  | "var"
  | "missing"
  | "missingSome";

const OP_SHAPE: Readonly<Record<string, ArgShape>> = {
  "==": "binary",
  "===": "binary",
  "!=": "binary",
  "!==": "binary",
  "!": "unary",
  "!!": "unary",
  and: "variadic",
  or: "variadic",
  ">": "binary",
  ">=": "binary",
  "<": "binOrTri",
  "<=": "binOrTri",
  "+": "variadic",
  "-": "variadic",
  "*": "variadic",
  "/": "binary",
  "%": "binary",
  if: "variadic",
  in: "binary",
  all: "binary",
  none: "binary",
  some: "binary",
  var: "var",
  missing: "missing",
  missing_some: "missingSome",
  min: "variadic",
  max: "variadic",
};

const FORBIDDEN_SEGMENTS: ReadonlySet<string> = new Set([
  "__proto__",
  "constructor",
  "prototype",
]);

function err(code: ValidateErrorCode, path: readonly string[], detail: string): ValidateErr {
  return { ok: false, code, path: [...path], detail };
}

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Single recursive walk. Returns first violation; first-match short-circuits.
 *
 * Note: the runtime `ctx` is not inspected here — the validator is purely
 * structural. Missing path lookups resolve to `null` at evaluation time
 * (standard JSON Logic) and falsify the predicate downstream, which is a
 * `predicate_evaluation_false` (verifier-layer concern), not a
 * `predicate_var_path_invalid` (validator concern).
 */
export function validate(ast: unknown): ValidateResult {
  return walk(ast, []);
}

function walk(node: unknown, path: readonly string[]): ValidateResult {
  // Atoms are always fine — they may appear as inline operand literals.
  if (node === null) return { ok: true };
  if (typeof node === "string") return { ok: true };
  if (typeof node === "number") return { ok: true };
  if (typeof node === "boolean") return { ok: true };

  // Arrays: every element must validate. Arrays are operand-lists, not
  // operator-objects, so we don't require single-key here.
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      const r = walk(node[i], [...path, `[${i}]`]);
      if (!r.ok) return r;
    }
    return { ok: true };
  }

  // Anything other than a plain record at this point is malformed (e.g.
  // function, Date, BigInt, Symbol, undefined as a value).
  if (!isPlainRecord(node)) {
    return err("predicate_malformed_ast", path, `non-plain-record node: ${typeof node}`);
  }

  // Operator-object: exactly one key.
  const keys = Object.keys(node);
  if (keys.length !== 1) {
    return err(
      "predicate_malformed_ast",
      path,
      `operator-object must have exactly one key, got ${keys.length}`,
    );
  }

  const op = keys[0]!;
  if (!ALLOWLIST.has(op)) {
    return err("predicate_operator_not_allowed", path, `operator '${op}' not in allowlist`);
  }

  const args = (node as Record<string, unknown>)[op];
  const shape = OP_SHAPE[op];
  if (!shape) {
    // Should be unreachable — ALLOWLIST and OP_SHAPE must stay in sync.
    return err("predicate_malformed_ast", path, `internal: missing shape for '${op}'`);
  }

  const nextPath: readonly string[] = [...path, op];

  switch (shape) {
    case "unary": {
      // Accepts a single operand (any JsonLogicValue). Recurse into it.
      return walk(args, nextPath);
    }
    case "binary": {
      if (!Array.isArray(args) || args.length !== 2) {
        return err("predicate_malformed_ast", nextPath, `'${op}' requires a 2-tuple`);
      }
      const r0 = walk(args[0], nextPath);
      if (!r0.ok) return r0;
      return walk(args[1], nextPath);
    }
    case "binOrTri": {
      if (!Array.isArray(args) || (args.length !== 2 && args.length !== 3)) {
        return err(
          "predicate_malformed_ast",
          nextPath,
          `'${op}' requires a 2-tuple or 3-tuple (between form)`,
        );
      }
      for (let i = 0; i < args.length; i++) {
        const r = walk(args[i], nextPath);
        if (!r.ok) return r;
      }
      return { ok: true };
    }
    case "variadic": {
      if (!Array.isArray(args)) {
        return err("predicate_malformed_ast", nextPath, `'${op}' requires an array of operands`);
      }
      for (let i = 0; i < args.length; i++) {
        const r = walk(args[i], nextPath);
        if (!r.ok) return r;
      }
      return { ok: true };
    }
    case "var": {
      return validateVarArgs(args, nextPath);
    }
    case "missing": {
      if (!Array.isArray(args) || !args.every((s) => typeof s === "string")) {
        return err(
          "predicate_malformed_ast",
          nextPath,
          "'missing' requires an array of strings",
        );
      }
      for (const p of args as string[]) {
        const r = validateVarPathString(p, nextPath);
        if (!r.ok) return r;
      }
      return { ok: true };
    }
    case "missingSome": {
      if (
        !Array.isArray(args) ||
        args.length !== 2 ||
        typeof args[0] !== "number" ||
        !Array.isArray(args[1]) ||
        !args[1].every((s) => typeof s === "string")
      ) {
        return err(
          "predicate_malformed_ast",
          nextPath,
          "'missing_some' requires [number, string[]]",
        );
      }
      for (const p of args[1] as string[]) {
        const r = validateVarPathString(p, nextPath);
        if (!r.ok) return r;
      }
      return { ok: true };
    }
  }
}

function validateVarArgs(args: unknown, path: readonly string[]): ValidateResult {
  // `var` accepts:
  //   - bare string (the path)
  //   - [string]
  //   - [string, default-value-expression]
  if (typeof args === "string") {
    return validateVarPathString(args, path);
  }
  if (Array.isArray(args)) {
    if (args.length === 0 || args.length > 2) {
      return err("predicate_malformed_ast", path, "'var' requires string OR [string] OR [string, default]");
    }
    const first = args[0];
    if (typeof first !== "string") {
      return err("predicate_malformed_ast", path, "'var' first argument must be a string path");
    }
    const r = validateVarPathString(first, path);
    if (!r.ok) return r;
    if (args.length === 2) {
      // Default expression — recurse like any operand.
      return walk(args[1], path);
    }
    return { ok: true };
  }
  return err("predicate_malformed_ast", path, "'var' requires string OR [string] OR [string, default]");
}

function validateVarPathString(p: string, path: readonly string[]): ValidateResult {
  // Empty / dot — element-context (inside iteration). Accept; not an escape.
  if (p === "" || p === ".") return { ok: true };

  // Reject control / escape characters (mirrors evaluator policy).
  // \x00..\x1f range + backslash + DEL. The evaluator uses the same regex,
  // they MUST stay in sync.
  if (/[\x00-\x1f\\\x7f]/.test(p)) {
    return err("predicate_var_path_invalid", path, `path contains control or escape char: ${JSON.stringify(p)}`);
  }

  const segments = p.split(".");
  for (const seg of segments) {
    if (seg === "") {
      return err("predicate_var_path_invalid", path, `path has empty segment ('..' or leading/trailing dot): ${p}`);
    }
    if (FORBIDDEN_SEGMENTS.has(seg)) {
      return err("predicate_var_path_invalid", path, `path traverses forbidden segment '${seg}': ${p}`);
    }
  }
  return { ok: true };
}
