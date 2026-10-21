/**
 * AGR body verifier (spec §5). SHAPE ONLY — not a safety or authorization check.
 * Records the issuer's asserted guard verdict; NEVER re-derives safety or re-screens content.
 * Discriminates on body.profile ("guard.input" only).
 */
import { validateGuardInput } from "@dekimuhq/guard-profiles";
import type { AGRBody } from "@dekimuhq/guard-profiles";

export interface VerifyBodyResult { valid: boolean; errors: string[]; body: AGRBody | null; }

export function verifyGuardBody(body: unknown): VerifyBodyResult {
  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;
  if (b.profile !== "guard.input") {
    return { valid: false, errors: [`unknown profile: ${String(b.profile)}`], body: null };
  }
  const v = validateGuardInput(body);
  if (!v.ok) return { valid: false, errors: v.errors, body: null };
  return { valid: true, errors: [], body: body as AGRBody };
}
