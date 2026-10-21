/**
 * AQR body verifier (spec §5). SHAPE ONLY — not an authorization or truth check.
 * Records the issuer's asserted verdict; NEVER re-derives quality or cross-checks
 * verdict vs score. Discriminates on body.profile.
 */
import type { AQRBody, AQRCaveatsConsumed } from "./types.ts";

export interface VerifyBodyResult { valid: boolean; errors: string[]; body: AQRBody | null; }

const PROFILES = new Set<string>(["quality.output", "quality.release"]);
const SCORER_KINDS = new Set<string>(["deterministic", "llm-judge", "human", "hybrid"]);
const VERDICTS = new Set<string>(["pass", "fail", "warn"]);
const GATES = new Set<string>(["blocking", "advisory"]);
const SHA256_HEX_RE = /^sha256:[0-9a-f]{64}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function isNonEmptyString(v: unknown): v is string { return typeof v === "string" && v.length > 0; }
function isUnitInterval(v: unknown): v is number { return typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1; }
function isNonNegInt(v: unknown): v is number { return typeof v === "number" && Number.isInteger(v) && v >= 0; }
function isSha256(v: unknown): v is string { return typeof v === "string" && SHA256_HEX_RE.test(v); }
function isCaveatsConsumed(v: unknown): v is AQRCaveatsConsumed {
  if (typeof v !== "object" || v === null) return false;
  const c = v as Record<string, unknown>;
  return (
    isNonEmptyString(c.data_scope) &&
    typeof c.spend_step === "number" && Number.isFinite(c.spend_step) && c.spend_step >= 0 &&
    (c.spend_currency === undefined || isNonEmptyString(c.spend_currency)) &&
    isNonEmptyString(c.capability)
  );
}

export function verifyQualityBody(body: unknown): VerifyBodyResult {
  const errors: string[] = [];
  if (typeof body !== "object" || body === null) {
    return { valid: false, errors: ["body.not_object"], body: null };
  }
  const b = body as Record<string, unknown>;

  if (typeof b.profile !== "string" || !PROFILES.has(b.profile)) errors.push("profile.invalid");
  if (!isNonEmptyString(b.suite_id)) errors.push("suite_id.missing");
  if (!isSha256(b.suite_hash)) errors.push("suite_hash.invalid");

  const scorer = b.scorer as Record<string, unknown> | undefined;
  if (typeof scorer !== "object" || scorer === null) {
    errors.push("scorer.missing");
  } else {
    if (typeof scorer.kind !== "string" || !SCORER_KINDS.has(scorer.kind)) errors.push("scorer.kind_invalid");
    if ((scorer.kind === "llm-judge" || scorer.kind === "hybrid") && !isNonEmptyString(scorer.model)) errors.push("scorer.model_required");
  }

  const result = b.result as Record<string, unknown> | undefined;
  if (typeof result !== "object" || result === null) {
    errors.push("result.missing");
  } else {
    if (!isUnitInterval(result.score)) errors.push("result.score_range");
    if (!isUnitInterval(result.threshold)) errors.push("result.threshold_range");
    if (typeof result.verdict !== "string" || !VERDICTS.has(result.verdict)) errors.push("result.verdict_invalid");
    if (!isNonNegInt(result.cases_total)) errors.push("result.cases_total_invalid");
    if (!isNonNegInt(result.cases_passed) || (isNonNegInt(result.cases_total) && (result.cases_passed as number) > (result.cases_total as number))) errors.push("result.cases_passed_invalid");
  }

  if (!isNonEmptyString(b.ran_at)) errors.push("ran_at.missing");
  else if (!RFC3339_RE.test(b.ran_at) || Number.isNaN(Date.parse(b.ran_at))) errors.push("ran_at.invalid");
  if (b.samples_commit !== undefined && !isSha256(b.samples_commit)) errors.push("samples_commit.invalid");
  if (b.policy_hash !== undefined && !isSha256(b.policy_hash)) errors.push("policy_hash.invalid");

  if (b.profile === "quality.output") {
    if (b.output_commit === undefined) errors.push("output_commit.missing");
    else if (!isSha256(b.output_commit)) errors.push("output_commit.invalid");
    if (b.request_id_commit !== undefined && !isSha256(b.request_id_commit)) errors.push("request_id_commit.invalid");
    if (b.credential_id !== undefined && !isNonEmptyString(b.credential_id)) errors.push("credential_id.invalid");
    if (b.caveats_consumed !== undefined && !isCaveatsConsumed(b.caveats_consumed)) errors.push("caveats_consumed.invalid");
    if (b.caveats_consumed !== undefined && b.credential_id === undefined) errors.push("caveats_consumed.orphan");
  } else if (b.profile === "quality.release") {
    if (!isNonEmptyString(b.subject_ref)) errors.push("subject_ref.missing");
    if (typeof b.gate !== "string" || !GATES.has(b.gate)) errors.push("gate.invalid");
  }

  if (errors.length > 0) return { valid: false, errors, body: null };
  return { valid: true, errors: [], body: b as unknown as AQRBody };
}
