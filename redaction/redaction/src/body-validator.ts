import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyRedactionBody } from "./verify-single.ts";
import type { APIIRBody } from "./types.ts";

export const redactionBodyValidator: BodyValidator<APIIRBody> = {
  validate(body) {
    const r = verifyRedactionBody(body);
    if (!r.valid) return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    return { ok: true, value: r.body! };
  },
};
