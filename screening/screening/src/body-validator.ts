import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyScreeningBody } from "./verify-single.ts";
import type { AScRBody } from "./types.ts";

export const screeningBodyValidator: BodyValidator<AScRBody> = {
  validate(body) {
    const r = verifyScreeningBody(body);
    if (!r.valid) return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    return { ok: true, value: r.body! };
  },
};
