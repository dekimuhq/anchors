/**
 * AgTR family manifest — defineFamily() wiring. Chip 19, ar.trace.v1.
 * subject_presence "must-be-null"; status_list_slot null (non-revocable);
 * TSA optional. Asserts execution provenance, not verified behavior.
 */
import { defineFamily, type FamilyManifest } from "@dekimuhq/anchors-envelope";
import { validateAgentTraceProfileDispatch } from "@dekimuhq/trace-profiles";
import { traceBodyValidator } from "./body-validator.ts";
import type { AgTRBody, AgTRTreeBody } from "./types.ts";

type AnyTraceBody = AgTRBody | AgTRTreeBody;

export const traceFamily: FamilyManifest<AnyTraceBody> = defineFamily<AnyTraceBody>({
  acronym: "AgTR",
  name: "Anchored Agent-Trace Receipts",
  claim_types: ["ar.trace.v1", "ar.trace.v2"],
  spec_path: "https://github.com/dekimuhq/anchors-spec/tree/main/trace",
  chip: 19,
  status_list_slot: null,
  subject_presence: "must-be-null",
  tsa_upgrade_path: "free",
  body_schema: traceBodyValidator,
  profiles: { "agent.trace": validateAgentTraceProfileDispatch },
  tsa_mandate: {},
  continuity: false,
});
