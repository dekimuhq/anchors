/**
 * AQR (Anchored Quality Receipts) body-type definitions. Asserts evaluation
 * PROVENANCE, not truth. Distinct from AER (ar.evaluation.v1, AI Act conformity).
 * Envelope-level fields are provided by @dekimuhq/anchors-envelope and NOT repeated.
 * field_root is added issuer-side by mintQualityV1.
 */
import type { AQRProfile, QualityScorer, QualityResult } from "./types.ts";

export interface AQRCaveatsConsumed {
  data_scope: string;
  spend_step: number;
  spend_currency?: string;
  capability: string;
}
export interface AQRBodyCommon {
  profile: AQRProfile;
  suite_id: string;
  suite_hash: string;
  scorer: QualityScorer;
  result: QualityResult;
  ran_at: string;
  samples_commit?: string;
  policy_uri?: string;
  policy_hash?: string;
  policy_version?: string;
}
export interface AQROutputBody extends AQRBodyCommon {
  profile: "quality.output";
  output_commit: string;
  request_id_commit?: string;
  credential_id?: string;
  caveats_consumed?: AQRCaveatsConsumed;
}
export interface AQRReleaseBody extends AQRBodyCommon {
  profile: "quality.release";
  subject_ref: string;
  gate: "blocking" | "advisory";
}
export type AQRBody = AQROutputBody | AQRReleaseBody;
