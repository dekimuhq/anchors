/**
 * BodyValidator<AtokrBody> adapter for the anchors-envelope factory.
 *
 * Wraps `verifyAtokrBody` into the factory's `BodyValidator` contract so the
 * factory pipeline enforces ATokR structural rules at envelope level.
 */

import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyAtokrBody } from "./verify-single.ts";
import type { AtokrBody } from "./types.ts";

export const atokrBodyValidator: BodyValidator<AtokrBody> = {
  validate(body) {
    const r = verifyAtokrBody(body);
    if (!r.valid) {
      return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    }
    return { ok: true, value: r.body! };
  },
};
