/**
 * AIR family manifest — Phase 4B adoption of `defineFamily()`.
 *
 * Spec: https://github.com/dekimuhq/anchors-spec/tree/main/air
 * Phase: 2026-05-19 per-family decision (Phase 4 warnings channel)
 *
 * AIR is the second closure-family member after ANR (`33330c0`) to bind
 * subject-presence + TSA mandate + continuity through the manifest surface,
 * and the first to do so without a pre-existing factory canary. Wiring
 * choices (per faithful-wrap migration decision + AIR-specific quirks):
 *
 *   - `subject_presence_check` — per-event split with the
 *     `dpia.stakeholders_consulted` representative-org / NGO-review carve-out
 *     (spec §4.4 + D10-AIR-6). Reasons are pre-mapped to the envelope-level
 *     codes that existing callers depend on (`subject_present`,
 *     `subject_invalid_form`, `representative_subject_method_mismatch`) so
 *     the factory pipeline emits the same reason strings as the hand-rolled
 *     `applyAirSubjectPresence`.
 *   - `tsa_mandate` — listed as `recommended` for all five v1 profiles. The
 *     real AIR matrix is keyed on `body.event_type` (FAMILY-CONSISTENCY §2 —
 *     `dpia.completed`, `dpia.prior_consultation_initiated`,
 *     `dpia.prior_consultation_resolved` RECOMMENDED; all others OPTIONAL),
 *     not on `body.profile`. The factory's profile-keyed matrix only enforces
 *     MANDATORY (none in AIR v1), so the `recommended` entries here are pure
 *     declarative documentation — the wrapper restores the real event-keyed
 *     semantics by re-running `applyAirTsaMandate` after the factory call.
 *     Same approach ABR will adopt when it migrates.
 *   - `body_schema` — pass-through adapter (see `body-validator.ts`). AIR
 *     body shape validation lives in `verifyAirBody` (`verify-single.ts`)
 *     and is invoked separately by callers that hold a body in hand.
 *   - `continuity: true` — AIR re-exports `mintContinuity`/`verifyContinuity`
 *     from `@dekimuhq/anchors-envelope/continuity` (continuity unification
 *     commit `dae0df4`). Pre-bound on the manifest, the `air-issuer-kit`
 *     continuity module is already a thin wrapper.
 *   - `compose` — wired to `composeAir` (see compose.ts). Surfaces four
 *     single-receipt warnings on `dpia.completed`:
 *     `art35_3a_aer_link_missing`, `art35_3b_alr_link_missing`,
 *     `review_window_long`, `review_window_long_voluntary`. Phase 4B-2
 *     (0.4.0) additionally walks the envelope-`prev` chain via
 *     `FamilyVerifyOptions.resolveReceiptById` to surface six chain-walk
 *     warnings: `dpia_review_overdue`, `art36_consultation_overdue`,
 *     `dpo_commit_drift`, `dpia_post_hoc_warning`,
 *     `re_dpia_predecessor_missing`, and `voluntary_high_risk_no_consultation`.
 *     When the resolver is undefined, chain-walk warnings silently skip;
 *     single-receipt warnings still fire.
 *
 * Per-profile validators are AIR-shaped (`{body, iat} => result-with-warnings`)
 * rather than envelope-shaped. The factory's profile dispatch expects the
 * envelope-shape `(envelope, body, ctx) => ProfileStateEntry` signature.
 * Five inline adapters bridge the gap; the AIR-internal warnings produced
 * by each profile validator are intentionally dropped here because
 * `ProfileStateEntry` has no `warnings` field — this matches the legacy
 * `envelope-v2.ts` behaviour (which also dropped them). The compose channel
 * surfaces them at top-level instead.
 */

import {
  defineFamily,
  type Envelope,
  type FamilyManifest,
  type ProfileValidator,
  type SubjectPresenceCheck,
} from "@dekimuhq/anchors-envelope";
import {
  ART35_3_A_PROFILE_ID,
  ART35_3_B_PROFILE_ID,
  ART35_3_C_PROFILE_ID,
  ART35_4_PROFILE_ID,
  VOLUNTARY_PROFILE_ID,
  validateImpactArt35_3_a,
  validateImpactArt35_3_b,
  validateImpactArt35_3_c,
  validateImpactArt35_4,
  validateImpactVoluntary,
  type ProfileValidator as AirProfileValidator,
  type ProfileValidationResult as AirProfileValidationResult,
} from "@dekimuhq/air-profiles";
import { airBodyValidator } from "./body-validator.ts";
import { composeAir } from "./compose.ts";
import { checkAirSubjectPresence } from "./subject-presence.ts";
import type { AirBody } from "./types.ts";

/**
 * Subject-presence callback wired into the manifest. Translates the internal
 * `subject_must_be_null` / `subject_must_be_sha256` / `method_disallows_subject`
 * reason codes (used by `checkAirSubjectPresence`) into the envelope-level
 * codes that have always appeared on `EnvelopeVerifyResult.reason`:
 *
 *   - `subject_must_be_null`        → `subject_present`
 *   - `subject_must_be_sha256`      → `subject_invalid_form`
 *   - `method_disallows_subject`    → `representative_subject_method_mismatch`
 *
 * This mapping preserves byte-equal output across the Phase 4B migration.
 * The factory passes `subject: string | null | undefined`; AIR's
 * `checkAirSubjectPresence` reads the runtime value (rejecting non-null /
 * non-sha256 forms for non-stakeholder events).
 */
const subjectPresenceCheck: SubjectPresenceCheck = ({ subject, body }) => {
  const r = checkAirSubjectPresence({ subject, body });
  if (r.ok) return { ok: true };
  switch (r.reason) {
    case "subject_must_be_null":
      return { ok: false, reason: "subject_present" };
    case "subject_must_be_sha256":
      return { ok: false, reason: "subject_invalid_form" };
    case "method_disallows_subject":
      return { ok: false, reason: "representative_subject_method_mismatch" };
    default:
      return { ok: false, reason: "subject_invalid_form" };
  }
};

/**
 * Adapter from AIR-shape profile validator (`{body, iat} → {valid, errors, warnings}`)
 * to envelope-shape `ProfileValidator` (`(envelope, body, ctx) → ProfileStateEntry`).
 *
 * The AIR-internal `warnings` array is intentionally dropped — `ProfileStateEntry`
 * has no `warnings` field and the legacy `envelope-v2.ts` dropped them too.
 * Top-level warning surfacing happens via the compose channel (commit 3).
 *
 * `errors[0]` becomes `reason` on failure; defensive default `profile_invalid`
 * for the impossible empty-errors-but-not-valid case.
 */
function adaptAirProfile(
  profile_id: string,
  fn: AirProfileValidator,
): ProfileValidator {
  return (envelope: Envelope, body: unknown, _ctx) => {
    const r: AirProfileValidationResult = fn({
      body: body as AirBody,
      iat: envelope.iat,
    });
    if (r.valid) return { profile_id, ok: true };
    return {
      profile_id,
      ok: false,
      reason: r.errors[0] ?? "profile_invalid",
    };
  };
}

/**
 * Frozen AIR family manifest. Chip 13, status_list_slot 7, claim_type
 * `ar.impact.v1`. Wired with the per-event subject-presence callback,
 * the (declarative-only) profile-keyed TSA mandate matrix, all five v1
 * profile validators via inline envelope-shape adapters, and continuity
 * helpers from `@dekimuhq/anchors-envelope`.
 */
export const airFamily: FamilyManifest<AirBody> = defineFamily<AirBody>({
  acronym: "AIR",
  name: "Anchored Impact-Assessment Receipts",
  claim_types: ["ar.impact.v1"],
  spec_path:
    "https://github.com/dekimuhq/anchors-spec/tree/main/air",

  chip: 13,
  status_list_slot: 7,
  subject_presence: "either",
  subject_presence_check: subjectPresenceCheck,
  tsa_upgrade_path: "free",

  body_schema: airBodyValidator,

  profiles: {
    [ART35_3_A_PROFILE_ID]: adaptAirProfile(
      ART35_3_A_PROFILE_ID,
      validateImpactArt35_3_a,
    ),
    [ART35_3_B_PROFILE_ID]: adaptAirProfile(
      ART35_3_B_PROFILE_ID,
      validateImpactArt35_3_b,
    ),
    [ART35_3_C_PROFILE_ID]: adaptAirProfile(
      ART35_3_C_PROFILE_ID,
      validateImpactArt35_3_c,
    ),
    [ART35_4_PROFILE_ID]: adaptAirProfile(
      ART35_4_PROFILE_ID,
      validateImpactArt35_4,
    ),
    [VOLUNTARY_PROFILE_ID]: adaptAirProfile(
      VOLUNTARY_PROFILE_ID,
      validateImpactVoluntary,
    ),
  },

  tsa_mandate: {
    [ART35_3_A_PROFILE_ID]: "recommended",
    [ART35_3_B_PROFILE_ID]: "recommended",
    [ART35_3_C_PROFILE_ID]: "recommended",
    [ART35_4_PROFILE_ID]: "recommended",
    [VOLUNTARY_PROFILE_ID]: "recommended",
  },

  continuity: true,
  compose: composeAir,
});
