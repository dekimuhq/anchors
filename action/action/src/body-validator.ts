/**
 * BodyValidator<AActRBody> adapter for the anchors-envelope factory.
 */

import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyActionBody } from "./verify-single.ts";
import type { AActRBody } from "./types.ts";

export const actionBodyValidator: BodyValidator<AActRBody> = {
  validate(body) {
    const r = verifyActionBody(body);
    if (!r.valid) {
      return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    }
    return { ok: true, value: r.body! };
  },
};
