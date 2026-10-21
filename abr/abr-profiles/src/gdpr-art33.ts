/**
 * `breach.gdpr.art33` profile validator — ABR spec §5.1.
 *
 * Hook: GDPR Art. 33 — notification to the competent supervisory authority
 * within 72 hours of awareness. Baseline profile for every EU personal-data
 * breach.
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"breach.gdpr.art33"`.
 *   - `body.incident_correlation_id` MUST be a non-empty string (D10-ABR-3).
 *   - On `breach.detected`: `body.jurisdiction` MUST match ISO 3166-1
 *     alpha-2 (two uppercase letters) OR equal `"EU"` (cross-border-only
 *     cases pre-LSA determination, per §5.1).
 *   - On `breach.detected`: `body.affected_data_categories` MUST be
 *     non-empty (§5.1 — categories are mandatory under Art. 33(3)(a)).
 *   - On `breach.dpa_notified`: `body.notification_phase` MUST be `null`
 *     (Art. 33 is single-phase; phased notification is NIS2 territory).
 *
 * The 72-hour deadline is verified by the §C chain walker (against TSA time
 * of `breach.detected`); this profile does not duplicate that surface.
 */

import type { AbrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const BREACH_GDPR_ART33_PROFILE_ID = "breach.gdpr.art33" as const;

const ISO_3166_1_ALPHA_2 = /^[A-Z]{2}$/;

export function validateBreachGdprArt33(body: AbrBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== BREACH_GDPR_ART33_PROFILE_ID) {
    errors.push("breach.gdpr.art33.profile.mismatch");
    return { errors };
  }

  if (
    typeof body.incident_correlation_id !== "string" ||
    body.incident_correlation_id.length === 0
  ) {
    errors.push("breach.gdpr.art33.incident_correlation_id.empty");
  }

  if (body.event_type === "breach.detected") {
    const j = body.jurisdiction;
    if (j !== "EU" && !ISO_3166_1_ALPHA_2.test(j)) {
      errors.push("breach.gdpr.art33.jurisdiction.invalid");
    }
    if (body.affected_data_categories.length === 0) {
      errors.push("breach.gdpr.art33.affected_data_categories.empty");
    }
  }

  if (
    body.event_type === "breach.dpa_notified" &&
    body.notification_phase !== null
  ) {
    errors.push("breach.gdpr.art33.notification_phase.must_be_null");
  }

  return { errors };
}

export const validateBreachGdprArt33Profile = makeProfileAdapter(BREACH_GDPR_ART33_PROFILE_ID, (body) => validateBreachGdprArt33(body as AbrBody));
