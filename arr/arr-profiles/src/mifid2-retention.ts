import type { AnyARRReceipt } from "./body-types.ts";
import type { ProfileValidationResult } from "./gdpr-art17.ts";

const YEAR_MS = 365.25 * 86_400_000;
const MIN_BY_CLASS: Record<string, number> = {
  equity: 5,
  derivative: 7,
  bond: 5,
  other: 5,
};

export function validateMifid2Retention(r: AnyARRReceipt): ProfileValidationResult {
  const errors: string[] = [];
  const x = r as Record<string, unknown>;
  if (!x.trade_commit) errors.push("mifid2.retention.trade_commit.required");
  if (!x.instrument_commit) errors.push("mifid2.retention.instrument_commit.required");
  if (!x.venue_commit) errors.push("mifid2.retention.venue_commit.required");

  const cls = String(x.mifid_class ?? "other");
  if (!(cls in MIN_BY_CLASS)) errors.push("mifid2.retention.mifid_class.invalid");

  if (r.kind !== "ar.batch.v1" && r.kind !== "ar.erasure.v1" && r.kind !== "ar.anonymization.v1") {
    const origin = Date.parse(String(x.record_origin_at ?? r.event_at));
    const event = Date.parse(String(r.event_at));
    const minYears = MIN_BY_CLASS[cls] ?? 5;
    if (event - origin < minYears * YEAR_MS) {
      errors.push("mifid2.retention.min_period.violated");
    }
  }
  return { errors };
}
