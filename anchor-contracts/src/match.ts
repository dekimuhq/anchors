/**
 * Precondition matching + the P0 trust gate.
 *
 * The trust gate (signature_valid / not-revoked) runs FIRST: P0 never inspects
 * the contents of an anchor the family verifier rejected.
 */
import {
  validatePredicate,
  evaluatePredicate,
  JsonLogicDivisionByZero,
  JsonLogicModuloByZero,
  JsonLogicVarPathInvalid,
} from "@dekimuhq/anchors-envelope";
import type { JsonLogicAst, Envelope } from "@dekimuhq/anchors-envelope";
import type { Precondition, VerifiedAnchor, MatchResult, RefusalReason } from "./types.ts";

/**
 * Good-standing `status_state` allowlist — the trust gate is DENY-BY-DEFAULT.
 *
 * `verdict.status_state` carries the envelope verifier's status result, whose
 * full surface is the ~18-value `StatusCheck["state"]` / `SuspensionCheck["state"]`
 * union (`@dekimuhq/anchors-envelope` status types). Only the values below mean
 * "this anchor is affirmatively in good standing". A present status_state NOT in
 * this set — `revoked`, `revoked_stale`, `revoked_by_chain`, `suspended`,
 * `suspended_stale`, and the could-not-confirm states (`unreachable`,
 * `invalid_pointer`, `list_signature_invalid`, `list_mismatch`) — REFUSES.
 *
 * `status_state === undefined` means the caller supplied no status verdict
 * (opted out of revocation checking); that is allowed, matching the optional
 * field. A trust gate must never fire on an unrecognised state, so the check is
 * an allowlist, never a denylist of known-bad values.
 */
export const ACCEPTABLE_STATUS_STATES: ReadonlySet<string> = new Set([
  "active",
  "active_stale",
  "no_status_pointer",
  "no_suspension_pointer",
  "not_attempted",
  "not_suspended",
  "not_suspended_stale",
]);

/** Validate then evaluate `where` against `ctx`; map results/errors to MatchResult. */
function checkWhere(where: JsonLogicAst, ctx: unknown): MatchResult {
  const v = validatePredicate(where as unknown);
  if (!v.ok) {
    return { ok: false, reason: "predicate_invalid_ast", detail: `${v.detail} (path: ${v.path.join(".") || "<root>"})` };
  }
  let result: unknown;
  try {
    result = evaluatePredicate(where, ctx);
  } catch (err: unknown) {
    if (err instanceof JsonLogicDivisionByZero || err instanceof JsonLogicModuloByZero || err instanceof JsonLogicVarPathInvalid) {
      return { ok: false, reason: "predicate_eval_error", detail: err.message };
    }
    return { ok: false, reason: "predicate_eval_error", detail: err instanceof Error ? err.message : "non-Error thrown" };
  }
  if (result !== true) {
    return { ok: false, reason: "precondition_unmatched", detail: `where evaluated to ${JSON.stringify(result)}` };
  }
  return { ok: true };
}

export function matchPrecondition(pre: Precondition, anchor: VerifiedAnchor): MatchResult {
  const { envelope, verdict } = anchor;

  // 1. Trust gate — always first.
  if (verdict.signature_valid !== true) {
    return { ok: false, reason: "anchor_signature_invalid" };
  }
  const notRevoked = pre.notRevoked ?? true;
  if (
    notRevoked &&
    verdict.status_state !== undefined &&
    !ACCEPTABLE_STATUS_STATES.has(verdict.status_state)
  ) {
    return {
      ok: false,
      reason: "anchor_revoked",
      detail: `status_state '${verdict.status_state}' is not an accepted good-standing state`,
    };
  }

  // 2. Discriminator.
  if (envelope.claim_type !== pre.claimType) {
    return { ok: false, reason: "precondition_unmatched", detail: `claim_type ${envelope.claim_type} != ${pre.claimType}` };
  }

  // 3. Issuer allowlist (when provided + non-empty).
  if (pre.issuers && pre.issuers.length > 0 && !pre.issuers.includes(envelope.iss)) {
    return { ok: false, reason: "precondition_unmatched", detail: `issuer ${envelope.iss} not allowed` };
  }

  // 4. Subject.
  if (pre.subjectEquals !== undefined && envelope.subject !== pre.subjectEquals) {
    return { ok: false, reason: "precondition_unmatched", detail: `subject ${envelope.subject} != ${pre.subjectEquals}` };
  }

  // 5. Time window on iat.
  if (pre.within) {
    const t = Date.parse(envelope.iat);
    if (Number.isNaN(t)) {
      return { ok: false, reason: "precondition_unmatched", detail: `iat unparseable: ${envelope.iat}` };
    }
    if (pre.within.fromIat !== undefined && t < Date.parse(pre.within.fromIat)) {
      return { ok: false, reason: "precondition_unmatched", detail: "iat before fromIat" };
    }
    if (pre.within.toIat !== undefined && t > Date.parse(pre.within.toIat)) {
      return { ok: false, reason: "precondition_unmatched", detail: "iat after toIat" };
    }
  }

  // 6. Field constraints — evaluated against the single matched envelope.
  if (pre.where) {
    return checkWhere(pre.where, envelope as unknown);
  }

  return { ok: true };
}

export type MatchAllResult =
  | { ok: true; matched: Record<string, Envelope> }
  | { ok: false; reason: RefusalReason; detail?: string; preconditionIndex: number };

/**
 * Greedy, no-backtracking assignment: each precondition claims the first
 * unconsumed pool anchor it matches. O(P×N). A later precondition starved by
 * an earlier greedy claim fails the whole match (P0 limitation).
 */
export function matchAll(preconditions: Precondition[], pool: VerifiedAnchor[]): MatchAllResult {
  const matched: Record<string, Envelope> = {};
  const consumed = new Set<number>();

  for (let i = 0; i < preconditions.length; i++) {
    const pre = preconditions[i]!;
    let claimedIdx = -1;
    let lastReason: MatchResult = { ok: false, reason: "precondition_unmatched" };

    for (let j = 0; j < pool.length; j++) {
      if (consumed.has(j)) continue;
      const m = matchPrecondition(pre, pool[j]!);
      if (m.ok) { claimedIdx = j; break; }
      lastReason = m;
    }

    if (claimedIdx === -1) {
      const reason: RefusalReason = lastReason.ok ? "precondition_unmatched" : lastReason.reason;
      const detail = lastReason.ok ? undefined : lastReason.detail;
      return { ok: false, reason, preconditionIndex: i, ...(detail !== undefined ? { detail } : {}) };
    }
    consumed.add(claimedIdx);
    matched[pre.as ?? String(i)] = pool[claimedIdx]!.envelope;
  }

  return { ok: true, matched };
}
