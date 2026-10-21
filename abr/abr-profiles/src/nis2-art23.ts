/**
 * `breach.nis2.art23` profile validator — ABR spec §5.3.
 *
 * Hook: NIS2 Directive Art. 23 — incident reporting by essential and
 * important entities. Commission Implementing Regulation (EU) 2024/2690 adds
 * digital-infrastructure technical specifications. The only v1 ABR profile
 * with a phased notification flow: 24h early warning + 72h initial + 1 month
 * final report.
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"breach.nis2.art23"`.
 *   - `body.incident_correlation_id` MUST be a non-empty string (D10-ABR-3).
 *   - On `breach.dpa_notified`: `body.notification_phase` MUST NOT be `null`.
 *     NIS2 mandates a 3-phase notification flow (§5.3) — every
 *     `breach.dpa_notified` under this profile names which phase it is.
 *
 * Per-phase deadline checks (24h early warning, 72h initial, 1 month final
 * — all measured from TSA time of `breach.detected`) live in the §C chain
 * walker, not in this profile. The verifier surfaces `notification_overdue`
 * per phase when the deadline is missed.
 *
 * `body.entity_classification` and `body.sector` (spec §5.3 required fields)
 * are extension fields not present on the v1 `AbrBody` discriminated union;
 * they will land via a future spec §5.6 amendment in `body.nis2_specific`
 * when integrator demand surfaces. This profile does not enforce them.
 */

import type { AbrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const BREACH_NIS2_ART23_PROFILE_ID = "breach.nis2.art23" as const;

export function validateBreachNis2Art23(body: AbrBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== BREACH_NIS2_ART23_PROFILE_ID) {
    errors.push("breach.nis2.art23.profile.mismatch");
    return { errors };
  }

  if (
    typeof body.incident_correlation_id !== "string" ||
    body.incident_correlation_id.length === 0
  ) {
    errors.push("breach.nis2.art23.incident_correlation_id.empty");
  }

  if (
    body.event_type === "breach.dpa_notified" &&
    body.notification_phase === null
  ) {
    errors.push("breach.nis2.art23.notification_phase.missing");
  }

  return { errors };
}

export const validateBreachNis2Art23Profile = makeProfileAdapter(BREACH_NIS2_ART23_PROFILE_ID, (body) => validateBreachNis2Art23(body as AbrBody));
