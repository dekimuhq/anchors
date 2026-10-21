/**
 * AGrR body verifier (spec §3/§5). Stateless: SHAPE + internal coherence only — NOT a
 * grounding-truth or authorization check.
 * It DOES enforce, from the body alone: referential integrity (every citation's source_id/claim_id
 * exists), the support↔score ordered mapping, and recomputation of `coverage` + `grounded_count`
 * (derived fields, never trusted). It does NOT — and cannot, lacking the answer/sources — verify
 * span binding (`span_commit === sha256(source[start:end])`) or re-run the scorer: binding is
 * mint-verified (verify-before-sign) and re-checkable only by a holder of the sources.
 * Discriminates on body.profile ("grounding.rag" only).
 */
import { validateGroundingRag } from "@dekimuhq/grounding-profiles";
import type { AGrRBody } from "@dekimuhq/grounding-profiles";

export interface VerifyBodyResult { valid: boolean; errors: string[]; body: AGrRBody | null; }

export function verifyGroundingBody(body: unknown): VerifyBodyResult {
  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;
  if (b.profile !== "grounding.rag") {
    return { valid: false, errors: [`unknown profile: ${String(b.profile)}`], body: null };
  }
  const v = validateGroundingRag(body);
  if (!v.ok) return { valid: false, errors: v.errors, body: null };
  return { valid: true, errors: [], body: body as AGrRBody };
}
