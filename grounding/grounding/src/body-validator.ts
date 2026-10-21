/**
 * BodyValidator<AGrRBody> adapter for the anchors-envelope factory.
 */
import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyGroundingBody } from "./verify-single.ts";
import type { AGrRBody } from "./types.ts";

export const groundingBodyValidator: BodyValidator<AGrRBody> = {
  validate(body) {
    const r = verifyGroundingBody(body);
    if (!r.valid) return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    return { ok: true, value: r.body! };
  },
};
