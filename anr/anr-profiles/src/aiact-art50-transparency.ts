/**
 * `notice.aiact.art50_transparency` profile validator — ANR spec §5.5.
 *
 * Hook: EU AI Act Art 50(1–5). Disclosure to end users that they are
 * interacting with an AI system, that AI-generated content is AI-generated,
 * or that emotion-recognition / biometric-categorisation is taking place.
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"notice.aiact.art50_transparency"`.
 *   - `body.event_type` MUST NOT be `"notice.joint_controller_essence"`.
 *   - When `body.event_type ∈ {notice.presented, notice.re_presented}`:
 *     `body.ai_system_kind` MUST be non-null.
 *     `body.ai_system_provider_did` MUST be a non-null, non-empty string.
 *
 * TSA invariant (`tsa` MANDATORY for this profile, AI Act stricter than
 * baseline GDPR transparency — spec §5.5) is enforced family-wide by the
 * verifier's §D per-profile TSA mandate matrix (`ANR_TSA_MANDATE`). This
 * profile does NOT re-check TSA absence to avoid double-fire; instead it
 * tightens the TSA quality requirement when a TSA IS present: the TSA must
 * be EUTL-listed and operate under the eIDAS QTS policy OID.
 *
 * Per-event-pinned null fields (`ai_system_*` on acknowledged / withdrawn /
 * translated) are body-level invariants asserted by the verifier's §C body
 * pass; this profile does not duplicate those.
 */

import type { AnrBody, AnrEventType } from "./body-types.ts";
import type { ProfileValidator, ProfileValidatorCtx } from "@dekimuhq/anchors-envelope";
import type { ProfileValidationResult } from "./types.ts";

/**
 * eIDAS QTS policy OID — ETSI EN 319 421 BTSP.
 * Same OID confirmed for ACR esig.accept@qes in
 * an internal design record (not published).
 * AI Act Art 50 transparency receipts require qualified timestamps from
 * EUTL-listed TSAs operating under this policy.
 */
export const AIACT_ART50_QTS_POLICY_OID = "0.4.0.2023.1.1" as const;

export const AIACT_ART50_TRANSPARENCY_PROFILE_ID =
  "notice.aiact.art50_transparency" as const;

const DISALLOWED_EVENT_TYPES: ReadonlySet<AnrEventType> = new Set([
  "notice.joint_controller_essence",
]);

const FIELD_REQUIRED_EVENT_TYPES: ReadonlySet<AnrEventType> = new Set([
  "notice.presented",
  "notice.re_presented",
]);

export function validateAiactArt50Transparency(
  body: AnrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== AIACT_ART50_TRANSPARENCY_PROFILE_ID) {
    errors.push("notice.aiact.art50_transparency.profile.mismatch");
    return { errors };
  }

  if (DISALLOWED_EVENT_TYPES.has(body.event_type)) {
    errors.push("notice.aiact.art50_transparency.event_type.disallowed");
    return { errors };
  }

  if (FIELD_REQUIRED_EVENT_TYPES.has(body.event_type)) {
    const narrowed = body as {
      ai_system_kind: string | null;
      ai_system_provider_did: string | null;
    };
    if (narrowed.ai_system_kind === null) {
      errors.push("notice.aiact.art50_transparency.ai_system_kind.required");
    }
    if (
      typeof narrowed.ai_system_provider_did !== "string" ||
      narrowed.ai_system_provider_did.length === 0
    ) {
      errors.push(
        "notice.aiact.art50_transparency.ai_system_provider_did.required",
      );
    }
  }

  return { errors };
}

function fail(reason: string) {
  return {
    profile_id: AIACT_ART50_TRANSPARENCY_PROFILE_ID,
    ok: false as const,
    reason,
  };
}

/**
 * Profile adapter with QTS OID pinning.
 *
 * Body validation runs first. If it passes and TSA context indicates a TSA
 * was present (tsa_state defined and not "tsa_absent"), the adapter
 * additionally verifies eIDAS QTS compliance: tsa_verified + EUTL-listed +
 * policy OID match. TSA absence is handled by the family-wide ANR_TSA_MANDATE
 * matrix, not by this profile — avoids double-fire.
 */
export const validateAiactArt50TransparencyProfile: ProfileValidator = (
  _envelope,
  body,
  ctx: ProfileValidatorCtx,
) => {
  const r = validateAiactArt50Transparency(body as AnrBody);
  const firstError = r.errors[0];
  if (firstError !== undefined) {
    return fail(firstError);
  }

  // QTS pinning — only when TSA data is present in ctx
  if (ctx.tsa_state !== undefined && ctx.tsa_state !== "tsa_absent") {
    if (ctx.tsa_state !== "tsa_verified") {
      return fail("notice.aiact.art50_transparency.tsa_not_verified");
    }
    if (ctx.tsa_listed !== true) {
      return fail("notice.aiact.art50_transparency.tsa_listed_required");
    }
    if (ctx.tsa_policy_oid !== AIACT_ART50_QTS_POLICY_OID) {
      return fail("notice.aiact.art50_transparency.tsa_policy_oid_mismatch");
    }
  }

  return {
    profile_id: AIACT_ART50_TRANSPARENCY_PROFILE_ID,
    ok: true as const,
  };
};
