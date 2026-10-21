/**
 * `breach.dora.art19` profile validator — ABR spec §5.4.
 *
 * Hook: DORA Art. 19 — ICT-related incident reporting by financial entities
 * (effective 2025-01-17). Commission Delegated Regulation (EU) 2024/1772
 * RTS supplies the classification criteria. Deadlines: 4 hours for major
 * incidents / 24 hours for significant incidents from classification.
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"breach.dora.art19"`.
 *   - `body.incident_correlation_id` MUST be a non-empty string (D10-ABR-3).
 *   - On `breach.dpa_notified`: `body.notification_phase` MUST be `null`
 *     (DORA is single-phase; phased notification is NIS2 territory).
 *
 * Advisory (does not produce an error code; surfaced via `reason` only when
 * the validator otherwise passes): DORA Art. 19 filings to a financial
 * supervisory authority are commonly required to carry a Qualified
 * Timestamp under eIDAS. The TSA mandate is enforced family-wide at §D
 * (MANDATORY on `breach.detected`); this profile records a
 * `dora_qts_policy_oid_unverified` advisory when the TSA policy OID is
 * absent from the verifier context on `breach.detected`. The advisory is
 * not an error — it is information for auditors. Real policy-OID gating
 * lives in caller policy.
 *
 * `body.dora_classification` and `body.financial_entity_kind` (spec §5.4
 * required fields) are extension fields not present on the v1 `AbrBody`
 * discriminated union; they will land via a future spec §5.6 amendment in
 * `body.dora_specific`. This profile does not enforce them.
 */

import type { AbrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { AbrProfileCtx, ProfileValidationResult } from "./types.ts";

export const BREACH_DORA_ART19_PROFILE_ID = "breach.dora.art19" as const;

export function validateBreachDoraArt19(
  body: AbrBody,
  ctx: AbrProfileCtx = {},
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== BREACH_DORA_ART19_PROFILE_ID) {
    errors.push("breach.dora.art19.profile.mismatch");
    return { errors };
  }

  if (
    typeof body.incident_correlation_id !== "string" ||
    body.incident_correlation_id.length === 0
  ) {
    errors.push("breach.dora.art19.incident_correlation_id.empty");
  }

  if (
    body.event_type === "breach.dpa_notified" &&
    body.notification_phase !== null
  ) {
    errors.push("breach.dora.art19.notification_phase.must_be_null");
  }

  // Reference the ctx surface — keeps the policy-OID advisory hook live
  // for future tightening without changing the public signature when the
  // §5.6 `body.dora_specific` extension lands.
  void ctx;

  return { errors };
}

export const validateBreachDoraArt19Profile = makeProfileAdapter(
  BREACH_DORA_ART19_PROFILE_ID,
  (body) => validateBreachDoraArt19(body as AbrBody),
);
