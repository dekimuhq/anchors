import type { AnyARRReceipt } from "./body-types.ts";
import type { ProfileValidationResult } from "./gdpr-art17.ts";

const MIN_PERIOD_YEARS = 10;
const YEAR_MS = 365.25 * 86_400_000;

export function validateAiActArt10(r: AnyARRReceipt): ProfileValidationResult {
  const errors: string[] = [];
  const x = r as Record<string, unknown>;

  if (!x.model_commit) errors.push("aiact.art10.model_commit.required");
  if (!x.dataset_commit) errors.push("aiact.art10.dataset_commit.required");

  const conformityRaw = x.conformity_assessment_at;
  const conformitySet = conformityRaw !== null && conformityRaw !== undefined;
  if (!conformitySet) errors.push("aiact.art10.conformity_assessment_at.unset");

  if (
    conformitySet &&
    r.kind !== "ar.batch.v1" &&
    r.kind !== "ar.erasure.v1" &&
    r.kind !== "ar.anonymization.v1"
  ) {
    const conformity = Date.parse(String(conformityRaw));
    const event = Date.parse(String(r.event_at));
    if (event - conformity < MIN_PERIOD_YEARS * YEAR_MS) {
      errors.push("aiact.art10.min_period.violated");
    }
  }

  return { errors };
}
