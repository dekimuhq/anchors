/**
 * `tokenization.eudi.wallet_arf` profile validator — ATokR spec §5.4.
 *
 * Hook: EU Digital Identity Wallet Architecture Reference Framework. The
 * receipt MUST identify the wallet provider and the attribute category.
 *
 * v1 invariants enforced here:
 *   - `body.wallet_provider_did` MUST be a non-empty string.
 *   - `body.attribute_category` MUST be one of `pid|qeaa|eaa|pda`.
 */

import type { AtokrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const EUDI_WALLET_ARF_PROFILE_ID =
  "tokenization.eudi.wallet_arf" as const;

const VALID_ATTRIBUTE_CATEGORIES: ReadonlySet<string> = new Set([
  "pid",
  "qeaa",
  "eaa",
  "pda",
]);

export function validateEudiWalletArf(
  body: AtokrBody,
): ProfileValidationResult {
  const errors: string[] = [];

  const b = body as unknown as Record<string, unknown>;

  const did = b["wallet_provider_did"];
  if (typeof did !== "string" || did.trim() === "") {
    errors.push("tokenization.eudi.wallet_arf.wallet_provider_did.missing");
  }

  const attrCat = b["attribute_category"];
  if (
    typeof attrCat !== "string" ||
    !VALID_ATTRIBUTE_CATEGORIES.has(attrCat)
  ) {
    errors.push("tokenization.eudi.wallet_arf.attribute_category.invalid");
  }

  return { errors };
}

export const validateEudiWalletArfProfile = makeProfileAdapter(
  EUDI_WALLET_ARF_PROFILE_ID,
  (body) => validateEudiWalletArf(body as AtokrBody),
);
