/**
 * `breach.nis2.annex1.digital_infrastructure` profile validator — ABR spec §5.7.
 *
 * Hook: NIS2 Directive Annex I §8 — digital infrastructure sector (IXPs,
 * DNS service providers, TLD registries, cloud service providers, data centre
 * service providers, CDNs, trust service providers, public electronic
 * communications networks). These entities are subject to NIS2 Art. 23 phased
 * notification AND to Commission Implementing Regulation (EU) 2024/2690
 * technical specifications (the most detailed NIS2 sectoral ruleset).
 *
 * v1 invariants enforced here (mirrors breach.nis2.art23 base invariants):
 *   - `body.profile` MUST be `"breach.nis2.annex1.digital_infrastructure"`.
 *   - `body.incident_correlation_id` MUST be a non-empty string (D10-ABR-3).
 *   - On `breach.dpa_notified`: `body.notification_phase` MUST NOT be `null`.
 *     Inherits the 3-phase notification flow from NIS2 Art. 23 (§5.3).
 *
 * Sector extension fields (`body.entity_type`, `body.enisa_di_category`,
 * `body.implementing_reg_2024_2690_ref`) will land via a future spec §5.6
 * amendment in `body.nis2_specific` when integrator demand surfaces. This
 * profile does not enforce them in v1.
 */

import type { AbrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID =
  "breach.nis2.annex1.digital_infrastructure" as const;

export function validateBreachNis2Annex1DigitalInfrastructure(
  body: AbrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID) {
    errors.push(
      "breach.nis2.annex1.digital_infrastructure.profile.mismatch",
    );
    return { errors };
  }

  if (
    typeof body.incident_correlation_id !== "string" ||
    body.incident_correlation_id.length === 0
  ) {
    errors.push(
      "breach.nis2.annex1.digital_infrastructure.incident_correlation_id.empty",
    );
  }

  if (
    body.event_type === "breach.dpa_notified" &&
    body.notification_phase === null
  ) {
    errors.push(
      "breach.nis2.annex1.digital_infrastructure.notification_phase.missing",
    );
  }

  return { errors };
}

export const validateBreachNis2Annex1DigitalInfrastructureProfile =
  makeProfileAdapter(
    BREACH_NIS2_ANNEX1_DIGITAL_INFRASTRUCTURE_PROFILE_ID,
    (body) =>
      validateBreachNis2Annex1DigitalInfrastructure(body as AbrBody),
  );
