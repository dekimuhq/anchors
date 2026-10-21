/**
 * BodyValidator<AtrBody> adapter for the anchors-envelope factory.
 *
 * Wraps `verifyAtrBody` into the factory's `BodyValidator` contract so the
 * factory pipeline enforces ATR structural rules at envelope level.
 */

import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyAtrBody } from "./verify-single.ts";
import type { AtrBody } from "./types.ts";

export const atrBodyValidator: BodyValidator<AtrBody> = {
  validate(body) {
    const r = verifyAtrBody(body);
    if (!r.valid) {
      return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    }
    return { ok: true, value: r.body! };
  },
};
