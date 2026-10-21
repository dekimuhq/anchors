/** `quality.output` profile validator — AQR spec §4.2. */
import type { AQRBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const QUALITY_OUTPUT_PROFILE_ID = "quality.output" as const;
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const SCORER_KINDS = new Set(["deterministic", "llm-judge", "human", "hybrid"]);
const VERDICTS = new Set(["pass", "fail", "warn"]);
function isNonEmptyString(v: unknown): v is string { return typeof v === "string" && v.length > 0; }
function isUnitInterval(v: unknown): v is number { return typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1; }
function isNonNegInt(v: unknown): v is number { return typeof v === "number" && Number.isInteger(v) && v >= 0; }

export function validateQualityCommon(b: Record<string, unknown>): string[] {
  const errors: string[] = [];
  if (!isNonEmptyString(b.suite_id)) errors.push("quality.suite_id_missing");
  if (typeof b.suite_hash !== "string" || !SHA256_HEX_RE.test(b.suite_hash)) errors.push("quality.suite_hash_malformed");
  const scorer = b.scorer as Record<string, unknown> | undefined;
  if (typeof scorer !== "object" || scorer === null) { errors.push("quality.scorer_missing"); }
  else {
    if (typeof scorer.kind !== "string" || !SCORER_KINDS.has(scorer.kind)) errors.push("quality.scorer.kind_invalid");
    if ((scorer.kind === "llm-judge" || scorer.kind === "hybrid") && !isNonEmptyString(scorer.model)) errors.push("quality.scorer.model_required");
  }
  const result = b.result as Record<string, unknown> | undefined;
  if (typeof result !== "object" || result === null) { errors.push("quality.result_missing"); }
  else {
    if (!isUnitInterval(result.score)) errors.push("quality.result.score_range");
    if (!isUnitInterval(result.threshold)) errors.push("quality.result.threshold_range");
    if (typeof result.verdict !== "string" || !VERDICTS.has(result.verdict)) errors.push("quality.result.verdict_invalid");
    if (!isNonNegInt(result.cases_total)) errors.push("quality.result.cases_total_invalid");
    if (!isNonNegInt(result.cases_passed) || (isNonNegInt(result.cases_total) && (result.cases_passed as number) > (result.cases_total as number))) errors.push("quality.result.cases_passed_invalid");
  }
  if (!isNonEmptyString(b.ran_at)) errors.push("quality.ran_at_missing");
  else if (!RFC3339_RE.test(b.ran_at) || Number.isNaN(Date.parse(b.ran_at))) errors.push("quality.ran_at_invalid");
  if (b.samples_commit !== undefined && (typeof b.samples_commit !== "string" || !SHA256_HEX_RE.test(b.samples_commit))) errors.push("quality.samples_commit_malformed");
  if (b.policy_hash !== undefined && (typeof b.policy_hash !== "string" || !SHA256_HEX_RE.test(b.policy_hash))) errors.push("quality.policy_hash_malformed");
  return errors;
}

export function validateQualityOutput(body: AQRBody): ProfileValidationResult {
  const b = body as unknown as Record<string, unknown>;
  const errors = validateQualityCommon(b);
  if (b.profile !== "quality.output") errors.push("quality.output.wrong_profile");
  if (b.output_commit === undefined) errors.push("quality.output.output_commit_missing");
  else if (typeof b.output_commit !== "string" || !SHA256_HEX_RE.test(b.output_commit)) errors.push("quality.output.output_commit_malformed");
  if (b.request_id_commit !== undefined && (typeof b.request_id_commit !== "string" || !SHA256_HEX_RE.test(b.request_id_commit))) errors.push("quality.output.request_id_commit_malformed");
  if (b.credential_id !== undefined && !isNonEmptyString(b.credential_id)) errors.push("quality.output.credential_id_invalid");
  if (b.caveats_consumed !== undefined && b.credential_id === undefined) errors.push("quality.output.caveats_orphan");
  return { errors };
}
export const validateQualityOutputProfile = makeProfileAdapter(
  QUALITY_OUTPUT_PROFILE_ID, (body) => validateQualityOutput(body as AQRBody),
);
