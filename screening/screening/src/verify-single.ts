/**
 * AScR body verifier (spec §5). SHAPE + freshness only: records the issuer's
 * asserted result, NEVER re-runs the matcher and NEVER judges sanctions status.
 */
import { validateScreeningList } from "@dekimuhq/screening-profiles";
import type { AScRBody } from "./types.ts";

export interface VerifyBodyResult { valid: boolean; errors: string[]; body: AScRBody | null; }

export function verifyScreeningBody(body: unknown): VerifyBodyResult {
  if (typeof body !== "object" || body === null) return { valid: false, errors: ["body.not_object"], body: null };
  const v = validateScreeningList(body);
  if (!v.ok) return { valid: false, errors: v.errors, body: null };
  return { valid: true, errors: [], body: body as AScRBody };
}
