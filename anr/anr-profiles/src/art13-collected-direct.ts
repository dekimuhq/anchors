/**
 * `notice.art13.collected_direct` profile validator — ANR spec §5.1.
 *
 * Hook: GDPR Art 13(1)(a–f) + Art 13(2)(a–f). Data collected directly from
 * the subject — signup forms, account creation, in-product data capture.
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"notice.art13.collected_direct"`.
 *   - `body.event_type` MUST NOT be `"notice.joint_controller_essence"` (that
 *     event type is reserved for the Art. 26 profile).
 *   - When `body.event_type ∈ {notice.presented, notice.re_presented}`:
 *     `body.rights_surface` MUST include the minimum disclosure set
 *     `art15`, `art16`, `art17`, `art18`, `art20`, `art21` (spec §5.1).
 *
 * Event-type-pinned null fields (`rights_surface` on acknowledged / withdrawn
 * / translated) are body-level invariants asserted by the verifier's §C body
 * pass; this profile does not duplicate those.
 *
 * Optional `body.subject_age_band` (spec §5.1) is validated for shape by the
 * §C body verifier; this profile does not constrain its value.
 */

import type { AnrBody, AnrEventType } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const ART13_COLLECTED_DIRECT_PROFILE_ID =
  "notice.art13.collected_direct" as const;

/**
 * Spec §5.1 minimum disclosure surface. Even rights inapplicable to a given
 * controller MUST be listed; the absence of a right from this set is a
 * categorical disclosure failure under Art 13.
 */
export const ART13_RIGHTS_SURFACE_MINIMUM: readonly string[] = [
  "art15",
  "art16",
  "art17",
  "art18",
  "art20",
  "art21",
];

const DISALLOWED_EVENT_TYPES: ReadonlySet<AnrEventType> = new Set([
  "notice.joint_controller_essence",
]);

const RIGHTS_SURFACE_EVENT_TYPES: ReadonlySet<AnrEventType> = new Set([
  "notice.presented",
  "notice.re_presented",
]);

export function validateArt13CollectedDirect(
  body: AnrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== ART13_COLLECTED_DIRECT_PROFILE_ID) {
    errors.push("notice.art13.collected_direct.profile.mismatch");
    return { errors };
  }

  if (DISALLOWED_EVENT_TYPES.has(body.event_type)) {
    errors.push("notice.art13.collected_direct.event_type.disallowed");
    return { errors };
  }

  if (RIGHTS_SURFACE_EVENT_TYPES.has(body.event_type)) {
    // Narrow: only presented / re_presented carry `rights_surface`.
    const rs = (body as { rights_surface: readonly string[] }).rights_surface;
    const present = new Set(rs);
    for (const required of ART13_RIGHTS_SURFACE_MINIMUM) {
      if (!present.has(required)) {
        errors.push(
          `notice.art13.collected_direct.rights_surface.missing:${required}`,
        );
      }
    }
  }

  return { errors };
}

export const validateArt13CollectedDirectProfile = makeProfileAdapter(ART13_COLLECTED_DIRECT_PROFILE_ID, (body) => validateArt13CollectedDirect(body as AnrBody));
