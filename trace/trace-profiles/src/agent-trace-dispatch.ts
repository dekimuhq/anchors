/** Shape-dispatching `agent.trace` advisory adapter — routes by body shape.
 *  v2 span-tree bodies (carry `spans`) → the tree validator; v1 flat bodies
 *  (carry `stages`) → the flat validator. Mirrors the body-validator dispatch
 *  in `@dekimuhq/trace`'s body-validator.ts so an explicitly-profile-validated
 *  v2 receipt no longer runs the v1 `stages` validator. Advisory only. */
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import { validateAgentTrace } from "./agent-trace.ts";
import { validateAgentTraceTree } from "./agent-trace-tree.ts";
import type { AgTRBody, AgTRTreeBody } from "./body.ts";
import { AGENT_TRACE_PROFILE_ID } from "./agent-trace.ts";

export const validateAgentTraceProfileDispatch = makeProfileAdapter(
  AGENT_TRACE_PROFILE_ID,
  (body) =>
    typeof body === "object" &&
    body !== null &&
    "spans" in (body as Record<string, unknown>)
      ? validateAgentTraceTree(body as AgTRTreeBody)
      : validateAgentTrace(body as AgTRBody),
);
