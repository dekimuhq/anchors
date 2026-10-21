/**
 * BodyValidator<AerBody> adapter for the anchors-envelope factory.
 */

import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyAerBody } from "./verify-single.ts";
import type { AerBody } from "./types.ts";

export const aerBodyValidator: BodyValidator<AerBody> = {
  validate(body) {
    const r = verifyAerBody(body);
    if (!r.valid) {
      return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    }
    return { ok: true, value: r.body! };
  },
};
