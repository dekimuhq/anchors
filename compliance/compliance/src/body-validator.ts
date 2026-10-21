import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyComplianceBundleBody } from "./verify-single.ts";
import type { ComplianceBundleBody } from "./types.ts";

export const complianceBodyValidator: BodyValidator<ComplianceBundleBody> = {
  validate(body) {
    const r = verifyComplianceBundleBody(body);
    if (!r.valid) return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    return { ok: true, value: r.body! };
  },
};
