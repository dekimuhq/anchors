/**
 * `breach.nis2.annex1.health` profile validator — ABR spec §5.6.
 *
 * Hook: NIS2 Directive Annex I §5 — health sector (hospitals, healthcare
 * providers, EU reference laboratories, pharmaceutical and medical device
 * manufacturers). Essential entities here layer NIS2 Art. 23 phased
 * notification obligations on top of ENISA health-sector guidelines and
 * cross-border healthcare interoperability requirements under Reg. (EU)
 * 2024/2847 (CRA).
 *
 * v1 invariants enforced here (mirrors breach.nis2.art23 base invariants):
 *   - `body.profile` MUST be `"breach.nis2.annex1.health"`.
 *   - `body.incident_correlation_id` MUST be a non-empty string (D10-ABR-3).
 *   - On `breach.dpa_notified`: `body.notification_phase` MUST NOT be `null`.
 *     Inherits the 3-phase notification flow from NIS2 Art. 23 (§5.3).
 *
 * Sector extension fields (`body.patient_data_involved`,
 * `body.facility_type`, `body.enisa_health_sector_category`) will land via a
 * future spec §5.6 amendment in `body.nis2_specific` when integrator demand
 * surfaces. This profile does not enforce them in v1.
 */

import type { AbrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID =
  "breach.nis2.annex1.health" as const;

export function validateBreachNis2Annex1Health(
  body: AbrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID) {
    errors.push("breach.nis2.annex1.health.profile.mismatch");
    return { errors };
  }

  if (
    typeof body.incident_correlation_id !== "string" ||
    body.incident_correlation_id.length === 0
  ) {
    errors.push("breach.nis2.annex1.health.incident_correlation_id.empty");
  }

  if (
    body.event_type === "breach.dpa_notified" &&
    body.notification_phase === null
  ) {
    errors.push("breach.nis2.annex1.health.notification_phase.missing");
  }

  return { errors };
}

export const validateBreachNis2Annex1HealthProfile = makeProfileAdapter(
  BREACH_NIS2_ANNEX1_HEALTH_PROFILE_ID,
  (body) => validateBreachNis2Annex1Health(body as AbrBody),
);
