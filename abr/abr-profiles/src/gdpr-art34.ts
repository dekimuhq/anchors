/**
 * `breach.gdpr.art34` profile validator — ABR spec §5.2.
 *
 * Hook: GDPR Art. 34 — notification to the data subject when the breach is
 * likely to result in a high risk. Drives the `breach.subject_notified` and
 * `breach.subject_notification_exempted` event types; `breach.detected` /
 * `breach.assessed` are typically issued under `breach.gdpr.art33` and
 * composed via shared `incident_correlation_id` (D10-ABR-3).
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"breach.gdpr.art34"`.
 *   - `body.incident_correlation_id` MUST be a non-empty string (D10-ABR-3).
 *   - On `breach.subject_notified`: `body.subject_batch_size` MUST be > 0
 *     (a zero-leaf batch under Art. 34 is incoherent; spec §4.5 caps at
 *     65 536 — §C body verifier enforces the upper bound).
 *   - On `breach.dpa_notified`: `body.notification_phase` MUST be `null`
 *     (single-phase, like Art. 33).
 *
 * The "without undue delay" deadline (verifier baseline 30 days from
 * `breach.detected` TSA time) is checked by the §C chain walker, not here.
 * The Art. 34(3)(c) `public_communication_uri` pairing on
 * `breach.subject_notification_exempted` is a §C body-verifier invariant
 * (`art34_3_c_public_comm_missing`), not duplicated here.
 */

import type { AbrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const BREACH_GDPR_ART34_PROFILE_ID = "breach.gdpr.art34" as const;

export function validateBreachGdprArt34(body: AbrBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== BREACH_GDPR_ART34_PROFILE_ID) {
    errors.push("breach.gdpr.art34.profile.mismatch");
    return { errors };
  }

  if (
    typeof body.incident_correlation_id !== "string" ||
    body.incident_correlation_id.length === 0
  ) {
    errors.push("breach.gdpr.art34.incident_correlation_id.empty");
  }

  if (
    body.event_type === "breach.subject_notified" &&
    body.subject_batch_size <= 0
  ) {
    errors.push("breach.gdpr.art34.subject_batch_size.non_positive");
  }

  if (
    body.event_type === "breach.dpa_notified" &&
    body.notification_phase !== null
  ) {
    errors.push("breach.gdpr.art34.notification_phase.must_be_null");
  }

  return { errors };
}

export const validateBreachGdprArt34Profile = makeProfileAdapter(BREACH_GDPR_ART34_PROFILE_ID, (body) => validateBreachGdprArt34(body as AbrBody));
