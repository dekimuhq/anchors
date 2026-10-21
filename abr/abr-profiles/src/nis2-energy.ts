/**
 * `breach.nis2.annex1.energy` profile validator — ABR spec §5.4.
 *
 * Hook: NIS2 Directive Annex I §1 — energy sector (electricity, oil, gas,
 * hydrogen). Essential entities in this sector are subject to the NIS2 Art. 23
 * phased notification flow AND to sector-specific ACER/ENTSO-E operational
 * incident reporting requirements.
 *
 * v1 invariants enforced here (mirrors breach.nis2.art23 base invariants):
 *   - `body.profile` MUST be `"breach.nis2.annex1.energy"`.
 *   - `body.incident_correlation_id` MUST be a non-empty string (D10-ABR-3).
 *   - On `breach.dpa_notified`: `body.notification_phase` MUST NOT be `null`.
 *     Inherits the 3-phase notification flow from NIS2 Art. 23 (§5.3).
 *
 * Sector extension fields (`body.energy_specific`, `body.operator_type`,
 * `body.acer_reference_id`) will land via a future spec §5.6 amendment in
 * `body.nis2_specific` when integrator demand surfaces. This profile does
 * not enforce them in v1.
 */

import type { AbrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID =
  "breach.nis2.annex1.energy" as const;

export function validateBreachNis2Annex1Energy(
  body: AbrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID) {
    errors.push("breach.nis2.annex1.energy.profile.mismatch");
    return { errors };
  }

  if (
    typeof body.incident_correlation_id !== "string" ||
    body.incident_correlation_id.length === 0
  ) {
    errors.push("breach.nis2.annex1.energy.incident_correlation_id.empty");
  }

  if (
    body.event_type === "breach.dpa_notified" &&
    body.notification_phase === null
  ) {
    errors.push("breach.nis2.annex1.energy.notification_phase.missing");
  }

  return { errors };
}

export const validateBreachNis2Annex1EnergyProfile = makeProfileAdapter(
  BREACH_NIS2_ANNEX1_ENERGY_PROFILE_ID,
  (body) => validateBreachNis2Annex1Energy(body as AbrBody),
);
