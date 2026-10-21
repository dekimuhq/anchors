/**
 * `gdpr.art46.scc` profile validator — ATR spec §5.2.
 *
 * Hook: GDPR Art 46 — transfer subject to appropriate safeguards (SCCs).
 * On `arrangement` events the receipt MUST name one of the four 2021
 * Standard Contractual Clause modules via `mechanism_version`.
 *
 * v1 invariants enforced here:
 *   - On `arrangement` events: `body.mechanism_version` MUST be one of
 *     `scc-2021-c-pp`, `scc-2021-c-c`, `scc-2021-p-p`, `scc-2021-p-c`.
 *   - All other event types: pass through (no errors).
 */

import type { AtrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const GDPR_ART46_SCC_PROFILE_ID = "gdpr.art46.scc" as const;

const VALID_SCC_VERSIONS: ReadonlySet<string> = new Set([
  "scc-2021-c-pp",
  "scc-2021-c-c",
  "scc-2021-p-p",
  "scc-2021-p-c",
]);

export function validateGdprArt46Scc(body: AtrBody): ProfileValidationResult {
  const errors: string[] = [];

  if (body.event_type !== "arrangement") {
    return { errors };
  }

  if (!VALID_SCC_VERSIONS.has(body.mechanism_version)) {
    errors.push("gdpr.art46.scc.mechanism_version_invalid");
  }

  return { errors };
}

export const validateGdprArt46SccProfile = makeProfileAdapter(
  GDPR_ART46_SCC_PROFILE_ID,
  (body) => validateGdprArt46Scc(body as AtrBody),
);
