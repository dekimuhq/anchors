/**
 * BodyValidator<AarBody> adapter for the anchors-envelope factory.
 *
 * Wraps `verifyAarBody` into the factory's `BodyValidator` contract so the
 * factory pipeline enforces AAR structural rules at envelope level.
 */

import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyAarBody } from "./verify-single.ts";
import type { AarBody } from "./types.ts";

export const aarBodyValidator: BodyValidator<AarBody> = {
  validate(body) {
    const r = verifyAarBody(body);
    if (!r.valid) {
      return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    }
    return { ok: true, value: r.body! };
  },
};
