/**
 * APIIR body verifier (spec §3). SHAPE ONLY — records the issuer's asserted
 * counts + commits; NEVER re-scans for missed PII and NEVER asserts the content
 * is PII-free. Single profile redaction.prompt.
 */
import type { APIIRBody } from "./types.ts";
import { REDACTION_CATEGORIES } from "@dekimuhq/redaction-profiles";

export interface VerifyBodyResult { valid: boolean; errors: string[]; body: APIIRBody | null; }

const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;
const CATEGORY_SET = new Set<string>(REDACTION_CATEGORIES);

function isNonEmptyString(v: unknown): v is string { return typeof v === "string" && v.length > 0; }
function isNonNegInt(v: unknown): v is number { return typeof v === "number" && Number.isInteger(v) && v >= 0; }
function isSha256(v: unknown): v is string { return typeof v === "string" && SHA256_HEX_RE.test(v); }

export function verifyRedactionBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];
  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;
  if (b.profile !== "redaction.prompt") errors.push("profile.invalid");
  const counts = b.counts as Record<string, unknown> | undefined;
  if (typeof counts !== "object" || counts === null || Array.isArray(counts)) {
    errors.push("counts.missing");
  } else {
    for (const [k, v] of Object.entries(counts)) {
      if (!CATEGORY_SET.has(k)) errors.push(`counts.unknown_category:${k}`);
      else if (!isNonNegInt(v)) errors.push(`counts.invalid:${k}`);
    }
  }
  if (!isSha256(b.ruleset_hash)) errors.push("ruleset_hash.invalid");
  if (!isSha256(b.input_commit)) errors.push("input_commit.invalid");
  if (!isSha256(b.output_commit)) errors.push("output_commit.invalid");
  if (b.commit_alg !== "sha256") errors.push("commit_alg.invalid");
  if (!isNonEmptyString(b.redactor)) errors.push("redactor.missing");
  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as APIIRBody };
}
