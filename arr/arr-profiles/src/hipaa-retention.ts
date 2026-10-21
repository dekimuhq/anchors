import type { AnyARRReceipt } from "./body-types.ts";
import type { ProfileValidationResult } from "./gdpr-art17.ts";

const MIN_PERIOD_YEARS = 6;
const YEAR_MS = 365.25 * 86_400_000;

export function validateHipaaRetention(r: AnyARRReceipt): ProfileValidationResult {
  const errors: string[] = [];

  if (r.kind === "ar.batch.v1") {
    errors.push("hipaa.retention.mode_a.required");
    return { errors };
  }

  const x = r as Record<string, unknown>;
  if (!x.covered_entity_commit) errors.push("hipaa.retention.covered_entity_commit.required");
  if (!Array.isArray(x.phi_categories) || (x.phi_categories as unknown[]).length === 0) {
    errors.push("hipaa.retention.phi_categories.required");
  }
  if (!x.record_origin_at) errors.push("hipaa.retention.record_origin_at.required");

  if (r.kind !== "ar.erasure.v1" && r.kind !== "ar.anonymization.v1") {
    const origin = Date.parse(String(x.record_origin_at ?? r.event_at));
    const event = Date.parse(String(r.event_at));
    if (event - origin < MIN_PERIOD_YEARS * YEAR_MS) {
      errors.push("hipaa.retention.min_period.violated");
    }
  }

  return { errors };
}
