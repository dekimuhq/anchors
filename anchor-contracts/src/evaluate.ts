/**
 * Evaluate a contract against a pool: match preconditions → build combined
 * context → run the contract predicate. Pure; deterministic.
 */
import {
  validatePredicate,
  evaluatePredicate,
  JsonLogicDivisionByZero,
  JsonLogicModuloByZero,
  JsonLogicVarPathInvalid,
} from "@dekimuhq/anchors-envelope";
import type { AnchorContract, VerifiedAnchor, TransitionVerdict } from "./types.ts";
import { matchAll } from "./match.ts";
import { buildContext } from "./context.ts";
import { contractHash } from "./contract-hash.ts";

export function evaluateContract(contract: AnchorContract, pool: VerifiedAnchor[]): TransitionVerdict {
  const hash = contractHash(contract);
  const base = {
    contractId: contract.id,
    contractHash: hash,
    from: contract.transition.from,
    to: contract.transition.to,
  };

  const m = matchAll(contract.preconditions, pool);
  if (!m.ok) {
    return { ...base, fired: false, reason: m.reason, ...(m.detail !== undefined ? { detail: m.detail } : {}) };
  }

  if (contract.where) {
    const ctx = buildContext(m.matched);
    const valid = validatePredicate(contract.where as unknown);
    if (!valid.ok) {
      return { ...base, fired: false, reason: "predicate_invalid_ast", detail: `${valid.detail} (path: ${valid.path.join(".") || "<root>"})` };
    }
    let result: unknown;
    try {
      result = evaluatePredicate(contract.where, ctx);
    } catch (err: unknown) {
      const detail = err instanceof JsonLogicDivisionByZero || err instanceof JsonLogicModuloByZero || err instanceof JsonLogicVarPathInvalid
        ? err.message
        : err instanceof Error ? err.message : "non-Error thrown";
      return { ...base, fired: false, reason: "predicate_eval_error", detail };
    }
    if (result !== true) {
      return { ...base, fired: false, reason: "predicate_evaluation_false", detail: `predicate evaluated to ${JSON.stringify(result)}` };
    }
  }

  return { ...base, fired: true, matched: m.matched };
}
