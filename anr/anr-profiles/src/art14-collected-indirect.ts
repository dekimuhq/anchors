/**
 * `notice.art14.collected_indirect` profile validator — ANR spec §5.2.
 *
 * Hook: GDPR Art 14(1)(a–f), Art 14(2)(a–g), Art 14(3)(a–c), Art 14(5)(a–b).
 * Data not collected from the subject (third-party sources, public registries,
 * scraping). The Art. 14(3) collection clock applies.
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"notice.art14.collected_indirect"`.
 *   - `body.event_type` MUST NOT be `"notice.joint_controller_essence"`.
 *   - When `body.event_type ∈ {notice.presented, notice.re_presented}`:
 *     `body.data_source` MUST be a non-null, non-empty string.
 *     `body.collection_horizon` MUST be non-null (Art. 14(3) clock pinned).
 *
 * Spec §5.2 horizon-age warning ("`iat` more than 30 days after
 * `data_acquired_at` when `collection_horizon === "one_month"`") is a
 * verifier-surface WARNING, not an invalidation. The `ProfileValidator`
 * signature carries `{ok, reason}` only — warnings have no representation
 * here — so the clock-breach check is deferred to a future verifier surface
 * extension. v1.0 of this validator enforces the field-presence rules only.
 */

import type { AnrBody, AnrEventType } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const ART14_COLLECTED_INDIRECT_PROFILE_ID =
  "notice.art14.collected_indirect" as const;

const DISALLOWED_EVENT_TYPES: ReadonlySet<AnrEventType> = new Set([
  "notice.joint_controller_essence",
]);

const FIELD_REQUIRED_EVENT_TYPES: ReadonlySet<AnrEventType> = new Set([
  "notice.presented",
  "notice.re_presented",
]);

export function validateArt14CollectedIndirect(
  body: AnrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== ART14_COLLECTED_INDIRECT_PROFILE_ID) {
    errors.push("notice.art14.collected_indirect.profile.mismatch");
    return { errors };
  }

  if (DISALLOWED_EVENT_TYPES.has(body.event_type)) {
    errors.push("notice.art14.collected_indirect.event_type.disallowed");
    return { errors };
  }

  if (FIELD_REQUIRED_EVENT_TYPES.has(body.event_type)) {
    const narrowed = body as {
      data_source: string | null;
      collection_horizon: string | null;
    };
    if (
      typeof narrowed.data_source !== "string" ||
      narrowed.data_source.length === 0
    ) {
      errors.push("notice.art14.collected_indirect.data_source.required");
    }
    if (narrowed.collection_horizon === null) {
      errors.push(
        "notice.art14.collected_indirect.collection_horizon.required",
      );
    }
  }

  return { errors };
}

export const validateArt14CollectedIndirectProfile = makeProfileAdapter(ART14_COLLECTED_INDIRECT_PROFILE_ID, (body) => validateArt14CollectedIndirect(body as AnrBody));
