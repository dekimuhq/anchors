/**
 * `tokenization.pci.dss_v4` profile validator — ATokR spec §5.3.
 *
 * Hook: PCI DSS v4 — payment card tokenization. The receipt MUST attest the
 * token is for a PAN (Primary Account Number) and declare the PCI environment.
 *
 * v1 invariants enforced here:
 *   - `body.format_class` MUST be `"pan"`.
 *   - `body.pci_environment` MUST be one of `cde|connected|out_of_scope`.
 */

import type { AtokrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const PCI_DSS_V4_PROFILE_ID = "tokenization.pci.dss_v4" as const;

const VALID_PCI_ENVIRONMENTS: ReadonlySet<string> = new Set([
  "cde",
  "connected",
  "out_of_scope",
]);

export function validatePciDssV4(body: AtokrBody): ProfileValidationResult {
  const errors: string[] = [];

  const b = body as unknown as Record<string, unknown>;

  if (b["format_class"] !== "pan") {
    errors.push("tokenization.pci.dss_v4.format_class_mismatch");
  }

  const pciEnv = b["pci_environment"];
  if (typeof pciEnv !== "string" || !VALID_PCI_ENVIRONMENTS.has(pciEnv)) {
    errors.push("tokenization.pci.dss_v4.pci_environment.invalid");
  }

  return { errors };
}

export const validatePciDssV4Profile = makeProfileAdapter(
  PCI_DSS_V4_PROFILE_ID,
  (body) => validatePciDssV4(body as AtokrBody),
);
