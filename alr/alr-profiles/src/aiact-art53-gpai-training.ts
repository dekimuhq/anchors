/**
 * `aiact.art53.gpai-training` profile validator — ALR spec §5.3.
 *
 * Hook: EU AI Act Art 53(1)(d). General-purpose AI providers must publish a
 * "sufficiently detailed summary about the content used for training". This
 * profile records each training-data parent as an explicit lineage edge so
 * the published summary is anchored, not promissory.
 *
 * v1 invariants enforced here:
 *   - `body.profile` MUST be `"aiact.art53.gpai-training"`.
 *   - `body.event_type` MUST be exactly `"derived_from"` (spec §5.3 row 1).
 *   - Every `body.parents[i].uri` MUST be a non-null, non-empty string —
 *     the URI is the resolver to the dataset descriptor (spec §5.3 row 2).
 *
 * Internal TSA-mandate upgrade (§D plan delta):
 *   - The family-level matrix declares `OPTIONAL` for every ALR event_type.
 *   - This profile, alone in v1, upgrades the requirement to
 *     `aiact.art53.gpai-training.tsa.required` when `ctx.tsa_state` is
 *     `"tsa_absent"`. Per FAMILY-CONSISTENCY.md §2 and the 10-spec batch
 *     plan, the upgrade lives in `alr-profiles`, NOT in the verifier's
 *     `tsa-mandate.ts`.
 *
 * Spec extras `complete: boolean`, `model_family`, `parameter_count`,
 * `training_compute_flops` are not in `AlrBody` v1.0; deferred to v1.1.
 */

import type { AlrBody, AlrParentRef } from "./body-types.ts";
import type { ProfileValidator } from "@dekimuhq/anchors-envelope";
import type { ProfileValidationResult, AlrProfileCtx } from "./types.ts";

export const AIACT_ART53_GPAI_TRAINING_PROFILE_ID =
  "aiact.art53.gpai-training" as const;

function hasNonEmptyUri(p: AlrParentRef): boolean {
  return typeof p.uri === "string" && p.uri.length > 0;
}

export function validateAiactArt53GpaiTraining(
  body: AlrBody,
  ctx: AlrProfileCtx = {},
): ProfileValidationResult {
  const errors: string[] = [];

  if (body.profile !== AIACT_ART53_GPAI_TRAINING_PROFILE_ID) {
    errors.push("aiact.art53.gpai-training.profile.mismatch");
    return { errors };
  }

  if (body.event_type !== "derived_from") {
    errors.push("aiact.art53.gpai-training.event_type.disallowed");
    return { errors };
  }

  body.parents.forEach((p, i) => {
    if (!hasNonEmptyUri(p)) {
      errors.push(`aiact.art53.gpai-training.parents.${i}.uri.required`);
    }
  });

  if (ctx.tsa_state === undefined || ctx.tsa_state === "tsa_absent") {
    errors.push("aiact.art53.gpai-training.tsa.required");
  }

  return { errors };
}

export const validateAiactArt53GpaiTrainingProfile: ProfileValidator = (
  _envelope,
  body,
  ctx,
) => {
  const marshalled: AlrProfileCtx = {};
  if (ctx.tsa_state !== undefined) marshalled.tsa_state = ctx.tsa_state;
  if (ctx.tsa_listed !== undefined) marshalled.tsa_listed = ctx.tsa_listed;
  if (ctx.tsa_policy_oid !== undefined) marshalled.tsa_policy_oid = ctx.tsa_policy_oid;
  const r = validateAiactArt53GpaiTraining(body as AlrBody, marshalled);
  return {
    profile_id: AIACT_ART53_GPAI_TRAINING_PROFILE_ID,
    ok: r.errors.length === 0,
    ...(r.errors.length > 0 ? { reason: r.errors[0] } : {}),
  };
};
