/**
 * `purpose.gdpr.art6_4` profile validator — APuR spec §5.2.
 *
 * Hook: GDPR Art 6(4) — compatible secondary use test. Applies to repurpose
 * events only; binding/unbinding events must use `purpose.gdpr.art5`.
 *
 * v1 invariants enforced here:
 *   - Event type must be "repurpose" — others are rejected.
 *   - `new_purpose_class` must be non-empty.
 *   - All 5 compat hash fields must match sha256 format.
 */

import type { ApurBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_ART6_4_PROFILE_ID = "purpose.gdpr.art6_4" as const;

const SHA256_RE = /^sha256:[0-9a-f]+$/;

const COMPAT_HASH_FIELDS = [
  "compat_link_hash",
  "compat_context_hash",
  "compat_subjects_reasonable_hash",
  "compat_consequences_hash",
  "compat_safeguards_hash",
] as const;

export function validateGdprArt6_4(body: ApurBody): ProfileValidationResult {
  const errors: string[] = [];

  const b = body as unknown as Record<string, unknown>;

  if (b["event_type"] !== "repurpose") {
    errors.push("purpose.gdpr.art6_4.wrong_event_type");
    return { errors };
  }

  const newPurposeClass = b["new_purpose_class"];
  if (
    typeof newPurposeClass !== "string" ||
    newPurposeClass.trim().length === 0
  ) {
    errors.push("purpose.gdpr.art6_4.new_purpose_class_missing");
  }

  for (const field of COMPAT_HASH_FIELDS) {
    const val = b[field];
    if (typeof val !== "string" || !SHA256_RE.test(val)) {
      errors.push(`purpose.gdpr.art6_4.${field}_invalid`);
    }
  }

  return { errors };
}

export const validateGdprArt6_4Profile = makeProfileAdapter(
  GDPR_ART6_4_PROFILE_ID,
  (body) => validateGdprArt6_4(body as ApurBody),
);
