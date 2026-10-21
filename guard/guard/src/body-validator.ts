/**
 * BodyValidator<AGRBody> adapter for the anchors-envelope factory.
 */
import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyGuardBody } from "./verify-single.ts";
import type { AGRBody } from "./types.ts";

export const guardBodyValidator: BodyValidator<AGRBody> = {
  validate(body) {
    const r = verifyGuardBody(body);
    if (!r.valid) return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    return { ok: true, value: r.body! };
  },
};
