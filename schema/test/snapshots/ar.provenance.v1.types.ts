/**
 * AUTO-GENERATED from ar.provenance.v1.anchor.json
 * Generated: [TIMESTAMP]
 *
 * Do not edit manually — re-run `npm run generate` to regenerate.
 * Manual edits will be lost on next generation.
 */

/** Claim type discriminators for APR. */
export type APRClaimType =
  | "ar.provenance.v1";

/** Body fields for APR receipts. */
export interface APRBody {
  artifact: {
    type: "commander.run.output" | "commander.run.codeChange" | "commander.run.email" | "commander.run.message" | "miniterms.document" | "lethe.letter" | "lethe.document" | "hub.sign-offs.deliverable" | "hub.time-clock.day";
    id: string;
    hash: string;
    hashAlgorithm: "sha256";
    contentType?: string;
    sizeBytes?: number;
  };
  agent: {
    kind: "human" | "ai" | "template" | "hybrid";
    model?: string;
    provider?: string;
    humanRole?: "review" | "edit" | "draft" | "approve" | "none";
  };
  authorization: {
    principalId: string;
  };
  inputs?: readonly ({
    kind: "prompt" | "file" | "url" | "claim" | "schedule";
    hash?: string;
    source?: string;
    claimId?: string;
  })[];
  startedAt: number;
  completedAt: number;
  durationMs?: number;
  disclosure: "public_minimal" | "public_full" | "metadata_only";
  summary?: string;
  /** `sha256:<hex>` */
  qts_attestation_hash: string | null;
}
