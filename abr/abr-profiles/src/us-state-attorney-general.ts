/**
 * `breach.us_state.attorney_general` profile validator — ABR spec §5.5.
 *
 * Hook: US state attorney-general breach notifications. v1 priority states:
 * California (Civ. Code §1798.82 et seq.), New York (GBL §899-aa), Texas
 * (Bus. & Com. §521.053). Extensible to additional states without a profile
 * bump (each state's required fields live in `body.state_specific` per
 * spec §5.6 — extension surface not yet on the v1 `AbrBody` union).
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"breach.us_state.attorney_general"`.
 *   - `body.incident_correlation_id` MUST be a non-empty string (D10-ABR-3).
 *   - On `breach.dpa_notified`: `body.notification_phase` MUST be `null`
 *     (US-AG is single-phase; phased notification is NIS2 territory).
 *
 * Verifier baseline deadline (60 days from `breach.detected` TSA time, with
 * per-state overrides documented in an internal design record (not published)) is
 * checked by the §C chain walker, not here.
 *
 * `body.state_code` (spec §5.5 required field — ISO 3166-2:US subdivision
 * code like `"US-CA"`) is an extension field not present on the v1
 * `AbrBody` discriminated union; it lands via §5.6 in `body.state_specific`
 * once integrator demand surfaces (and per-state profiles only when ≥3
 * paying US-state customers ask, per spec §11 open question 4).
 *
 * Composability with `breach.gdpr.art33` via shared `incident_correlation_id`
 * (spec §5.5) is a chain-walker concern, not a single-receipt invariant.
 */

import type { AbrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID =
  "breach.us_state.attorney_general" as const;

export function validateBreachUsStateAttorneyGeneral(
  body: AbrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID) {
    errors.push("breach.us_state.attorney_general.profile.mismatch");
    return { errors };
  }

  if (
    typeof body.incident_correlation_id !== "string" ||
    body.incident_correlation_id.length === 0
  ) {
    errors.push("breach.us_state.attorney_general.incident_correlation_id.empty");
  }

  if (
    body.event_type === "breach.dpa_notified" &&
    body.notification_phase !== null
  ) {
    errors.push(
      "breach.us_state.attorney_general.notification_phase.must_be_null",
    );
  }

  return { errors };
}

export const validateBreachUsStateAttorneyGeneralProfile = makeProfileAdapter(BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID, (body) => validateBreachUsStateAttorneyGeneral(body as AbrBody));
