/**
 * ABR family manifest — Phase 4C adoption of `defineFamily()`.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/abr
 * Phase: 2026-05-19 per-family decision (Phase 4 warnings channel)
 *
 * ABR is the third closure-family member after ANR (`33330c0`) and AIR
 * (`bb89aff`) to bind subject-presence + TSA mandate + continuity through the
 * `defineFamily()` manifest surface. Wiring choices (per faithful-wrap
 * migration decision + ABR-specific quirks):
 *
 *   - `subject_presence_check` — per-event split (FAMILY-CONSISTENCY.md §3,
 *     spec §3.1 + §4.5 + D10-ABR-4). `breach.subject_notified` MUST carry
 *     `"sha256:<hex>"`; every other event_type MUST be `null` (incident-level
 *     events are not subject-scoped — strictly null, not "either"). Reasons
 *     are pre-mapped to the envelope-level codes that existing callers
 *     depend on (`subject_missing`, `subject_invalid_form`, `subject_present`)
 *     so the factory pipeline emits the same reason strings as the
 *     hand-rolled `applyAbrSubjectPresence`.
 *   - `compose` — wired to `composeAbr` (see compose.ts). Surfaces two
 *     warnings: `clock_skew_warning` (single-receipt — on `breach.detected`,
 *     `envelope.iat` vs `body.detected_at` divergence > 5min per spec §3.1
 *     row 1) and `notification_overdue` (chain-walk — on `breach.dpa_notified`,
 *     elapsed-from-detected vs profile deadline per spec §4.3 + §4.4 +
 *     D10-ABR-6, suppressed by prior `breach.dpa_delayed` per spec lines
 *     232 + 363). When `opts.resolveReceiptById` is undefined, the
 *     chain-walk warning silently skips; the single-receipt warning still
 *     fires.
 *   - `tsa_mandate` — listed as `recommended` for all five v1 profiles. The
 *     real ABR matrix is keyed on `body.event_type` (FAMILY-CONSISTENCY §2 —
 *     `breach.detected` MANDATORY per spec D10-ABR-2 / 72-hour clock; all
 *     other events RECOMMENDED), NOT on `body.profile`. The factory's
 *     profile-keyed matrix only enforces MANDATORY; the `recommended`
 *     entries here are pure declarative documentation — the wrapper restores
 *     the real event-keyed semantics by re-running `applyAbrTsaMandate`
 *     after the factory call. Same approach AIR adopted in `bb89aff`.
 *   - `body_schema` — pass-through adapter (see `body-validator.ts`). ABR
 *     body shape validation lives in `verifyAbrBody` (`verify-single.ts`)
 *     and is invoked separately by callers that hold a body in hand.
 *   - `continuity: true` — ABR re-exports `issueContinuityAttestation` /
 *     `verifyContinuityAttestation` from `@dekimuhq/anchors-envelope/continuity`
 *     via `abr-issuer-kit` (continuity unification commit `dae0df4`).
 *     Pre-bound on the manifest, the issuer-kit continuity module is
 *     already a thin wrapper.
 *   - `compose` — wired to `composeAbr` (see compose.ts). Surfaces two
 *     warnings: `clock_skew_warning` (single-receipt — on `breach.detected`,
 *     `envelope.iat` vs `body.detected_at` divergence > 5min per spec §3.1
 *     row 1) and `notification_overdue` (chain-walk — on `breach.dpa_notified`,
 *     elapsed-from-detected vs profile deadline per spec §4.3 + §4.4 + line
 *     232 suppression rule via `breach.dpa_delayed`).
 */

import {
  defineFamily,
  type FamilyManifest,
  type SubjectPresenceCheck,
} from "@dekimuhq/anchors-envelope";
import {
  BREACH_GDPR_ART33_PROFILE_ID,
  BREACH_GDPR_ART34_PROFILE_ID,
  BREACH_NIS2_ART23_PROFILE_ID,
  BREACH_DORA_ART19_PROFILE_ID,
  BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID,
  validateBreachGdprArt33Profile,
  validateBreachGdprArt34Profile,
  validateBreachNis2Art23Profile,
  validateBreachDoraArt19Profile,
  validateBreachUsStateAttorneyGeneralProfile,
} from "@dekimuhq/abr-profiles";
import { abrBodyValidator } from "./body-validator.ts";
import { composeAbr } from "./compose.ts";
import { checkAbrSubjectPresence } from "./subject-presence.ts";
import type { AbrBody } from "./types.ts";

/**
 * Subject-presence callback wired into the manifest. Translates the internal
 * `subject_must_be_present` / `subject_must_be_sha256` / `subject_must_be_null`
 * reason codes (used by `checkAbrSubjectPresence`) into the envelope-level
 * codes that have always appeared on `EnvelopeVerifyResult.reason`:
 *
 *   - `subject_must_be_present`  → `subject_missing`
 *   - `subject_must_be_sha256`   → `subject_invalid_form`
 *   - `subject_must_be_null`     → `subject_present`
 *
 * This mapping preserves byte-equal output across the Phase 4C migration.
 */
const subjectPresenceCheck: SubjectPresenceCheck = ({ subject, body }) => {
  const r = checkAbrSubjectPresence({ subject, body });
  if (r.ok) return { ok: true };
  switch (r.reason) {
    case "subject_must_be_present":
      return { ok: false, reason: "subject_missing" };
    case "subject_must_be_sha256":
      return { ok: false, reason: "subject_invalid_form" };
    case "subject_must_be_null":
      return { ok: false, reason: "subject_present" };
    default:
      return { ok: false, reason: "subject_invalid_form" };
  }
};

/**
 * Frozen ABR family manifest. Chip 11, status_list_slot 5, claim_type
 * `ar.breach.v1`. Wired with the per-event subject-presence callback, the
 * (declarative-only) profile-keyed TSA mandate matrix, all five v1 profile
 * validators, and continuity helpers from `@dekimuhq/anchors-envelope`.
 */
export const abrFamily: FamilyManifest<AbrBody> = defineFamily<AbrBody>({
  acronym: "ABR",
  name: "Anchored Breach Receipts",
  claim_types: ["ar.breach.v1"],
  spec_path:
    "https://github.com/dekimuhq/anchors-spec/tree/main/abr",

  chip: 11,
  status_list_slot: 5,
  subject_presence: "either",
  subject_presence_check: subjectPresenceCheck,
  tsa_upgrade_path: "free",

  body_schema: abrBodyValidator,

  profiles: {
    [BREACH_GDPR_ART33_PROFILE_ID]: validateBreachGdprArt33Profile,
    [BREACH_GDPR_ART34_PROFILE_ID]: validateBreachGdprArt34Profile,
    [BREACH_NIS2_ART23_PROFILE_ID]: validateBreachNis2Art23Profile,
    [BREACH_DORA_ART19_PROFILE_ID]: validateBreachDoraArt19Profile,
    [BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID]:
      validateBreachUsStateAttorneyGeneralProfile,
  },

  tsa_mandate: {
    [BREACH_GDPR_ART33_PROFILE_ID]: "recommended",
    [BREACH_GDPR_ART34_PROFILE_ID]: "recommended",
    [BREACH_NIS2_ART23_PROFILE_ID]: "recommended",
    [BREACH_DORA_ART19_PROFILE_ID]: "recommended",
    [BREACH_US_STATE_ATTORNEY_GENERAL_PROFILE_ID]: "recommended",
  },

  continuity: true,
  compose: composeAbr,
});
