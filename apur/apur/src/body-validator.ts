/**
 * BodyValidator<ApurBody> adapter for the anchors-envelope factory.
 *
 * Wraps `verifyApurBody` into the factory's `BodyValidator` contract so the
 * factory pipeline enforces APuR structural rules at envelope level.
 */

import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyApurBody } from "./verify-single.ts";
import type { ApurBody } from "./types.ts";

export const apurBodyValidator: BodyValidator<ApurBody> = {
  validate(body) {
    const r = verifyApurBody(body);
    if (!r.valid) {
      return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    }
    return { ok: true, value: r.body! };
  },
};
