import type { AnyARRReceipt } from "./body-types.ts";
import type { ProfileValidationResult } from "./gdpr-art17.ts";

const ALLOWED_KINDS_SINGLE = new Set(["ar.expiry.v1", "ar.archive.v1"]);
const ALLOWED_TRIGGERS = new Set(["scheduled", "operator"]);

export function validateGdprArt5e(r: AnyARRReceipt): ProfileValidationResult {
  const errors: string[] = [];

  if (r.kind === "ar.batch.v1") {
    const b = r as { batch_event_kind?: string };
    if (!b.batch_event_kind || !ALLOWED_KINDS_SINGLE.has(b.batch_event_kind)) {
      errors.push("gdpr.art5e.batch_event_kind.disallowed");
    }
  } else if (!ALLOWED_KINDS_SINGLE.has(r.kind)) {
    errors.push("gdpr.art5e.kind.disallowed");
  }

  if (!ALLOWED_TRIGGERS.has(r.trigger)) errors.push("gdpr.art5e.trigger.disallowed");

  const x = r as Record<string, unknown>;
  if (!x.retention_basis_commit) errors.push("gdpr.art5e.retention_basis_commit.required");
  if (!x.original_collection_at) errors.push("gdpr.art5e.original_collection_at.required");

  return { errors };
}
