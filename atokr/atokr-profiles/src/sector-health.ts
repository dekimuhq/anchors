/**
 * `tokenization.sector.health` profile validator — ATokR spec §5.5.
 *
 * Hook: Health sector tokenization. The receipt MUST declare the category
 * of health data use under which the token was issued.
 *
 * v1 invariants enforced here:
 *   - `body.data_use_category` MUST be one of
 *     `primary_care|secondary_research|clinical_trial|public_health`.
 */

import type { AtokrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const SECTOR_HEALTH_PROFILE_ID =
  "tokenization.sector.health" as const;

const VALID_DATA_USE_CATEGORIES: ReadonlySet<string> = new Set([
  "primary_care",
  "secondary_research",
  "clinical_trial",
  "public_health",
]);

export function validateSectorHealth(body: AtokrBody): ProfileValidationResult {
  const errors: string[] = [];

  const b = body as unknown as Record<string, unknown>;

  const duc = b["data_use_category"];
  if (typeof duc !== "string" || !VALID_DATA_USE_CATEGORIES.has(duc)) {
    errors.push("tokenization.sector.health.data_use_category.invalid");
  }

  return { errors };
}

export const validateSectorHealthProfile = makeProfileAdapter(
  SECTOR_HEALTH_PROFILE_ID,
  (body) => validateSectorHealth(body as AtokrBody),
);
