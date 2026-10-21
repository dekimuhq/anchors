/** BodyValidator adapter for the anchors-envelope factory — dispatches v2 tree bodies
 *  (carry `spans`) to the tree verifier, v1 flat bodies (carry `stages`) to the single verifier. */
import type { BodyValidator } from "@dekimuhq/anchors-envelope/issuer";
import { verifyTraceBody } from "./verify-single.ts";
import { verifyTraceTreeBody } from "./verify-tree.ts";
import type { AgTRBody, AgTRTreeBody } from "./types.ts";

type AnyTraceBody = AgTRBody | AgTRTreeBody;

export const traceBodyValidator: BodyValidator<AnyTraceBody> = {
  validate(body) {
    const isTree =
      typeof body === "object" && body !== null && "spans" in (body as Record<string, unknown>);
    const r = isTree ? verifyTraceTreeBody(body) : verifyTraceBody(body);
    if (!r.valid) return { ok: false, reason: r.errors[0] ?? "body_invalid" };
    return { ok: true, value: r.body! as AnyTraceBody };
  },
};
