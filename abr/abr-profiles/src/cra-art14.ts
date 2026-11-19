/**
 * `breach.cra.art14` profile validator.
 *
 * Hook: Regulation (EU) 2024/2847 (Cyber Resilience Act) Art. 14(2) and
 * 14(4) — a manufacturer reports (a) an actively exploited vulnerability in a
 * product with digital elements and (b) a severe incident having an impact on
 * the security of such a product, through the ENISA Single Reporting
 * Platform. Reporting applies from 11 September 2026.
 *
 * Phased flow, mirroring `breach.nis2.art23`:
 *   - early warning  — within 24h of becoming aware  (`early_warning`)
 *   - notification   — within 72h of becoming aware  (`full_notification`)
 *   - final report   — vulnerability: 14 days after a corrective or
 *                      mitigating measure is available; severe incident:
 *                      1 month after the notification (`final_report`)
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"breach.cra.art14"`.
 *   - `body.incident_correlation_id` MUST be a non-empty string (D10-ABR-3).
 *   - On `breach.dpa_notified`: `body.notification_phase` MUST NOT be `null`.
 *
 * The vulnerability-vs-severe-incident distinction is not a body field in
 * v1 (no new `AbrBody` shape); deadline arithmetic lives in the chain walker
 * / the issuing application, not in this profile.
 */

import type { AbrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const BREACH_CRA_ART14_PROFILE_ID = "breach.cra.art14" as const;

export function validateBreachCraArt14(body: AbrBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== BREACH_CRA_ART14_PROFILE_ID) {
    errors.push("breach.cra.art14.profile.mismatch");
    return { errors };
  }

  if (
    typeof body.incident_correlation_id !== "string" ||
    body.incident_correlation_id.length === 0
  ) {
    errors.push("breach.cra.art14.incident_correlation_id.empty");
  }

  if (
    body.event_type === "breach.dpa_notified" &&
    body.notification_phase === null
  ) {
    errors.push("breach.cra.art14.notification_phase.missing");
  }

  return { errors };
}

export const validateBreachCraArt14Profile = makeProfileAdapter(BREACH_CRA_ART14_PROFILE_ID, (body) => validateBreachCraArt14(body as AbrBody));
