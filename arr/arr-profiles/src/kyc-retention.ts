import type { AnyARRReceipt } from "./body-types.ts";
import type { ProfileValidationResult } from "./gdpr-art17.ts";

const MIN_PERIOD_YEARS = 5;
const YEAR_MS = 365.25 * 86_400_000;

export function validateKycRetention(r: AnyARRReceipt): ProfileValidationResult {
  const errors: string[] = [];
  const x = r as Record<string, unknown>;
  if (!x.customer_commit) errors.push("kyc.retention.customer_commit.required");
  if (!x.relationship_end_at) errors.push("kyc.retention.relationship_end_at.required");
  if (!x.risk_profile_hash) errors.push("kyc.retention.risk_profile_hash.required");

  if (r.kind !== "ar.batch.v1" && r.kind !== "ar.erasure.v1" && r.kind !== "ar.anonymization.v1") {
    const rel = Date.parse(String(x.relationship_end_at ?? r.event_at));
    const event = Date.parse(String(r.event_at));
    if (event - rel < MIN_PERIOD_YEARS * YEAR_MS) {
      errors.push("kyc.retention.min_period.violated");
    }
  }
  return { errors };
}
