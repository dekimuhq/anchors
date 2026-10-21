/**
 * BodyValidator<AQRBody> adapter for the anchors-envelope factory.
 */
import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyQualityBody } from "./verify-single.ts";
import type { AQRBody } from "./types.ts";

export const qualityBodyValidator: BodyValidator<AQRBody> = {
  validate(body) {
    const r = verifyQualityBody(body);
    if (!r.valid) return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    return { ok: true, value: r.body! };
  },
};
