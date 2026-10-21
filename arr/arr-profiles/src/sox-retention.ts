import type { AnyARRReceipt } from "./body-types.ts";
import type { ProfileValidationResult } from "./gdpr-art17.ts";

const MIN_PERIOD_YEARS = 7;
const YEAR_MS = 365.25 * 86_400_000;

export function validateSoxRetention(r: AnyARRReceipt): ProfileValidationResult {
  const errors: string[] = [];
  const x = r as Record<string, unknown>;
  if (!x.audit_record_commit) errors.push("sox.retention.audit_record_commit.required");
  if (!x.fiscal_period) errors.push("sox.retention.fiscal_period.required");
  if (!x.record_origin_at) errors.push("sox.retention.record_origin_at.required");

  if (r.kind !== "ar.batch.v1" && r.kind !== "ar.erasure.v1" && r.kind !== "ar.anonymization.v1") {
    const origin = Date.parse(String(x.record_origin_at ?? r.event_at));
    const event = Date.parse(String(r.event_at));
    if (event - origin < MIN_PERIOD_YEARS * YEAR_MS) {
      errors.push("sox.retention.min_period.violated");
    }
  }
  return { errors };
}
