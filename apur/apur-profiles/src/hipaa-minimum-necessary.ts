/**
 * `purpose.hipaa.minimum_necessary` profile validator — APuR spec §5.4.
 *
 * Hook: HIPAA §164.502(b) — minimum necessary standard. Applies to binding
 * events only.
 *
 * v1 invariants enforced here:
 *   - Event type must be "binding" — others are rejected.
 *   - `covered_entity_commit` must be present and non-empty.
 *   - `workforce_role_class` must be present and non-empty.
 */

import type { ApurBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const HIPAA_MINIMUM_NECESSARY_PROFILE_ID =
  "purpose.hipaa.minimum_necessary" as const;

export function validateHipaaMinimumNecessary(
  body: ApurBody,
): ProfileValidationResult {
  const errors: string[] = [];

  const b = body as unknown as Record<string, unknown>;

  if (b["event_type"] !== "binding") {
    errors.push("purpose.hipaa.minimum_necessary.wrong_event_type");
    return { errors };
  }

  const coveredEntityCommit = b["covered_entity_commit"];
  if (
    typeof coveredEntityCommit !== "string" ||
    coveredEntityCommit.trim().length === 0
  ) {
    errors.push(
      "purpose.hipaa.minimum_necessary.covered_entity_commit_missing",
    );
  }

  const workforceRoleClass = b["workforce_role_class"];
  if (
    typeof workforceRoleClass !== "string" ||
    workforceRoleClass.trim().length === 0
  ) {
    errors.push("purpose.hipaa.minimum_necessary.workforce_role_class_missing");
  }

  return { errors };
}

export const validateHipaaMinimumNecessaryProfile = makeProfileAdapter(
  HIPAA_MINIMUM_NECESSARY_PROFILE_ID,
  (body) => validateHipaaMinimumNecessary(body as ApurBody),
);
