/** `redaction.prompt` profile validator — APIIR spec §3. */
import type { APIIRBody } from "./body.ts";
import { REDACTION_CATEGORIES } from "./types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const REDACTION_PROMPT_PROFILE_ID = "redaction.prompt" as const;
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;
const CATEGORY_SET = new Set<string>(REDACTION_CATEGORIES);

function isNonEmptyString(v: unknown): v is string { return typeof v === "string" && v.length > 0; }
function isNonNegInt(v: unknown): v is number { return typeof v === "number" && Number.isInteger(v) && v >= 0; }
function isSha256(v: unknown): v is string { return typeof v === "string" && SHA256_HEX_RE.test(v); }

export function validateRedactionPrompt(body: APIIRBody): ProfileValidationResult {
  const b = body as unknown as Record<string, unknown>;
  const errors: string[] = [];
  if (b.profile !== "redaction.prompt") errors.push("redaction.wrong_profile");
  const counts = b.counts as Record<string, unknown> | undefined;
  if (typeof counts !== "object" || counts === null || Array.isArray(counts)) {
    errors.push("redaction.counts_missing");
  } else {
    for (const [k, v] of Object.entries(counts)) {
      if (!CATEGORY_SET.has(k)) errors.push(`redaction.counts.unknown_category:${k}`);
      else if (!isNonNegInt(v)) errors.push(`redaction.counts.invalid:${k}`);
    }
  }
  if (!isSha256(b.ruleset_hash)) errors.push("redaction.ruleset_hash_malformed");
  if (!isSha256(b.input_commit)) errors.push("redaction.input_commit_malformed");
  if (!isSha256(b.output_commit)) errors.push("redaction.output_commit_malformed");
  if (b.commit_alg !== "sha256") errors.push("redaction.commit_alg_invalid");
  if (!isNonEmptyString(b.redactor)) errors.push("redaction.redactor_missing");
  return { errors };
}

export const validateRedactionPromptProfile = makeProfileAdapter(
  REDACTION_PROMPT_PROFILE_ID, (body) => validateRedactionPrompt(body as APIIRBody),
);
