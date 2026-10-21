/**
 * `gdpr.art28.processor` profile validator — ADR spec section 5.
 *
 * Hook: GDPR Art. 28 processor authority. The delegation receipt MUST
 * carry a DPA reference (URI + hash), sub-processing policy, and transfer
 * basis declaration.
 *
 * v1 invariants enforced here (grant events only):
 *   - `body.scope.constraints.dpa_uri` MUST be a non-empty string.
 *   - `body.scope.constraints.dpa_hash` MUST be a non-empty string.
 *   - `body.scope.constraints.sub_processing_allowed` MUST be a boolean.
 *   - `body.scope.constraints.transfer_basis` MUST be one of:
 *     "adequacy", "scc", "bcr", "derog".
 */

import type { AdrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_ART28_PROCESSOR_PROFILE_ID = "gdpr.art28.processor" as const;

const VALID_TRANSFER_BASES = new Set(["adequacy", "scc", "bcr", "derog"]);

export function validateGdprArt28Processor(body: AdrBody): ProfileValidationResult {
  const errors: string[] = [];
  if (body.event !== "grant") return { errors };

  const b = body as unknown as Record<string, unknown>;
  const scope = b["scope"] as Record<string, unknown> | undefined;
  const constraints = scope?.["constraints"] as Record<string, unknown> | undefined;

  // dpa_uri
  if (typeof constraints?.["dpa_uri"] !== "string" || constraints["dpa_uri"] === "") {
    errors.push("gdpr.art28.processor.dpa_uri_missing");
  }

  // dpa_hash
  if (typeof constraints?.["dpa_hash"] !== "string" || constraints["dpa_hash"] === "") {
    errors.push("gdpr.art28.processor.dpa_hash_missing");
  }

  // sub_processing_allowed
  if (typeof constraints?.["sub_processing_allowed"] !== "boolean") {
    errors.push("gdpr.art28.processor.sub_processing_allowed_missing");
  }

  // transfer_basis
  const transferBasis = constraints?.["transfer_basis"];
  if (typeof transferBasis !== "string" || !VALID_TRANSFER_BASES.has(transferBasis)) {
    errors.push("gdpr.art28.processor.transfer_basis_invalid");
  }

  return { errors };
}

export const validateGdprArt28ProcessorProfile = makeProfileAdapter(
  GDPR_ART28_PROCESSOR_PROFILE_ID,
  (body) => validateGdprArt28Processor(body as AdrBody),
);
