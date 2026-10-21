/**
 * Composable verifier-side checks for the v1.2 envelope additions.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/envelope §7
 * Plan: an internal design record (not published) Phase D
 *
 * The envelope package keeps signature primitives + per-feature checks as
 * pure functions; member verifiers (apr/acr/arr) compose them. This file
 * exposes the two v1.2-specific checks:
 *
 *   - checkIatMs(envelope)          — iat_ms ↔ iat consistency.
 *   - checkPredicate(envelope)      — predicate forbidden-types + AST
 *                                     validation + evaluation against the
 *                                     canonicalised envelope context.
 *
 * Status-list revocation MUST NOT short-circuit predicate evaluation
 * (spec §7, last paragraph). Composition is the member verifier's job —
 * these helpers do not consult revocation state.
 */

import type { Envelope } from "./envelope-types.ts";
import { validate as validateAst } from "./jsonlogic-validate.ts";
import {
  evaluate as evaluatePredicate,
  JsonLogicDivisionByZero,
  JsonLogicModuloByZero,
  JsonLogicVarPathInvalid,
} from "./jsonlogic-eval.ts";
import type { JsonLogicValue, JsonLogicAst } from "./jsonlogic-types.ts";

export type PredicateReasonCode =
  | "iat_ms_mismatch"
  | "predicate_forbidden_on_claim_type"
  | "predicate_operator_not_allowed"
  | "predicate_var_path_invalid"
  | "predicate_malformed_ast"
  | "predicate_evaluation_false"
  | "predicate_division_by_zero"
  | "predicate_modulo_by_zero";

export type PredicateCheckOk = { ok: true };
export type PredicateCheckErr = { ok: false; reason: PredicateReasonCode; detail?: string };
export type PredicateCheckResult = PredicateCheckOk | PredicateCheckErr;

/** Claim types that may never carry a predicate. Spec §6 + L9. */
const PREDICATE_FORBIDDEN_CLAIM_TYPES: ReadonlySet<string> = new Set([
  "ar.provenance.v1",
  "ar.batch.v1",
]);

/**
 * `iat_ms` is an optional v1.2 field (v1.1 receipts have no iat_ms). When
 * present, it MUST equal `Date.parse(iat)` exactly. Absence is not a check
 * failure under v1.2 — backwards compatibility per spec §7 step 1.
 */
export function checkIatMs(e: Envelope): PredicateCheckResult {
  if (e.iat_ms === undefined) return { ok: true };
  const expected = Date.parse(e.iat);
  if (Number.isNaN(expected)) {
    return {
      ok: false,
      reason: "iat_ms_mismatch",
      detail: `iat is not a parseable ISO 8601 timestamp: ${e.iat}`,
    };
  }
  if (e.iat_ms !== expected) {
    return {
      ok: false,
      reason: "iat_ms_mismatch",
      detail: `iat_ms (${e.iat_ms}) !== Date.parse(iat) (${expected})`,
    };
  }
  return { ok: true };
}

/**
 * Run the v1.2 predicate contract per spec §7:
 *   1. Forbidden-types check (ar.provenance.v1, ar.batch.v1) — spec §6 + L9.
 *   2. Static AST validation against the v1.2 allowlist (Phase C).
 *   3. Evaluation against the canonicalised envelope context (Phase B).
 *      Must produce strict `true`.
 *
 * The "canonicalised envelope context" used at evaluation is the envelope
 * object itself (the same view used for signing). Issuers MUST mint such
 * that the predicate evaluates to `true` against the envelope (spec §7
 * issuer rule 5).
 */
export function checkPredicate(e: Envelope): PredicateCheckResult {
  // Both `null` and `undefined` mean "no predicate" — accept.
  if (e.predicate === null || e.predicate === undefined) {
    if (PREDICATE_FORBIDDEN_CLAIM_TYPES.has(e.claim_type)) {
      return { ok: true };
    }
    return { ok: true };
  }

  if (PREDICATE_FORBIDDEN_CLAIM_TYPES.has(e.claim_type)) {
    return {
      ok: false,
      reason: "predicate_forbidden_on_claim_type",
      detail: `claim_type '${e.claim_type}' must not carry a predicate (L9 + §6)`,
    };
  }

  const v = validateAst(e.predicate as unknown);
  if (!v.ok) {
    return {
      ok: false,
      reason: v.code as PredicateReasonCode,
      detail: `${v.detail} (path: ${v.path.join(".") || "<root>"})`,
    };
  }

  let result: JsonLogicValue;
  try {
    result = evaluatePredicate(e.predicate as JsonLogicAst, e as unknown);
  } catch (err: unknown) {
    if (err instanceof JsonLogicDivisionByZero) {
      return { ok: false, reason: "predicate_division_by_zero" };
    }
    if (err instanceof JsonLogicModuloByZero) {
      return { ok: false, reason: "predicate_modulo_by_zero" };
    }
    if (err instanceof JsonLogicVarPathInvalid) {
      return { ok: false, reason: "predicate_var_path_invalid", detail: err.message };
    }
    return {
      ok: false,
      reason: "predicate_malformed_ast",
      detail: err instanceof Error ? err.message : "non-Error thrown during predicate evaluation",
    };
  }

  if (result !== true) {
    return {
      ok: false,
      reason: "predicate_evaluation_false",
      detail: `predicate evaluated to ${JSON.stringify(result)} (strict 'true' required)`,
    };
  }
  return { ok: true };
}
