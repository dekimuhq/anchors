/**
 * Build an unsigned APIIR body from a redaction descriptor + caller-computed
 * commits. Detector-agnostic: takes counts from ANY redactor. Does NO crypto
 * (caller computes commits via the envelope commit() primitive).
 */
import type { APIIRBody, RedactionCounts } from "./types.ts";

export interface BuildRedactionBodyInput {
  counts: RedactionCounts;
  ruleset_hash: string;   // sha256:<hex>
  input_commit: string;   // sha256:<hex>
  output_commit: string;  // sha256:<hex>
  redactor: string;
}

export function buildRedactionBody(input: BuildRedactionBodyInput): APIIRBody {
  return {
    profile: "redaction.prompt",
    counts: input.counts,
    ruleset_hash: input.ruleset_hash,
    input_commit: input.input_commit,
    output_commit: input.output_commit,
    commit_alg: "sha256",
    redactor: input.redactor,
  };
}
