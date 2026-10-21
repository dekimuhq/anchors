/**
 * `notice.art26.joint_controller_essence` profile validator — ANR spec §5.3.
 *
 * Hook: GDPR Art 26(1)–(3). Essence-of-arrangement disclosure for joint
 * controllership; pairs exclusively with the `notice.joint_controller_essence`
 * event type (§4.6).
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"notice.art26.joint_controller_essence"`.
 *   - `body.event_type` MUST be exactly `"notice.joint_controller_essence"`.
 *   - `body.joint_controllers` MUST be a non-empty array (per §4.6 row 1).
 *
 * Per-joint-controller shape (`did`, `role`, `contact_point_uri`, optional
 * `adr_id`) is enforced by the §C body verifier; the `adr_id` cross-resolution
 * against ADR receipts lives in §G's composition walker. This profile does
 * not duplicate either check.
 */

import type { AnrBody } from "./body-types.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const ART26_JOINT_CONTROLLER_ESSENCE_PROFILE_ID =
  "notice.art26.joint_controller_essence" as const;

export function validateArt26JointControllerEssence(
  body: AnrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== ART26_JOINT_CONTROLLER_ESSENCE_PROFILE_ID) {
    errors.push("notice.art26.joint_controller_essence.profile.mismatch");
    return { errors };
  }

  if (body.event_type !== "notice.joint_controller_essence") {
    errors.push("notice.art26.joint_controller_essence.event_type.disallowed");
    return { errors };
  }

  if (body.joint_controllers.length === 0) {
    errors.push("notice.art26.joint_controller_essence.joint_controllers.empty");
  }

  return { errors };
}

export const validateArt26JointControllerEssenceProfile = makeProfileAdapter(ART26_JOINT_CONTROLLER_ESSENCE_PROFILE_ID, (body) => validateArt26JointControllerEssence(body as AnrBody));
