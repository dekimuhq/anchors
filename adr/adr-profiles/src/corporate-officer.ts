/**
 * `corporate.officer` profile validator — ADR spec section 5.
 *
 * Hook: Corporate officer authority. The delegation receipt MUST carry
 * a monetary limit, transaction categories, and a rationale URI on grant.
 * If delegable, a sub-delegation authority URI is required.
 *
 * v1 invariants enforced here (grant events only):
 *   - `body.scope.constraints.monetary_limit` MUST be an object with:
 *     - `currency`: 3-character ISO string
 *     - `amount`: number > 0
 *   - `body.scope.constraints.transaction_categories` MUST be a non-empty string array.
 *   - `body.rationale_uri` MUST be a non-empty string on grant.
 *   - If `body.delegable === true`, `body.scope.constraints.sub_delegation_authority_uri`
 *     MUST be a non-empty string.
 */

import type { AdrBody } from "./body.ts";
import { makeProfileAdapter } from "@dekimuhq/anchors-envelope/issuer";
import type { ProfileValidationResult } from "./types.ts";

export const CORPORATE_OFFICER_PROFILE_ID = "corporate.officer" as const;

const ISO_CURRENCY_RE = /^[A-Z]{3}$/;

export function validateCorporateOfficer(body: AdrBody): ProfileValidationResult {
  const errors: string[] = [];
  if (body.event !== "grant") return { errors };

  const b = body as unknown as Record<string, unknown>;
  const scope = b["scope"] as Record<string, unknown> | undefined;
  const constraints = scope?.["constraints"] as Record<string, unknown> | undefined;

  // monetary_limit
  const monetaryLimit = constraints?.["monetary_limit"];
  if (monetaryLimit === undefined || monetaryLimit === null || typeof monetaryLimit !== "object") {
    errors.push("corporate.officer.monetary_limit_missing");
  } else {
    const ml = monetaryLimit as Record<string, unknown>;
    if (typeof ml["currency"] !== "string" || !ISO_CURRENCY_RE.test(ml["currency"])) {
      errors.push("corporate.officer.monetary_limit_currency_invalid");
    }
    if (typeof ml["amount"] !== "number" || ml["amount"] <= 0) {
      errors.push("corporate.officer.monetary_limit_amount_invalid");
    }
  }

  // transaction_categories
  const txCats = constraints?.["transaction_categories"];
  if (
    !Array.isArray(txCats) ||
    txCats.length === 0 ||
    !txCats.every((c) => typeof c === "string" && c.length > 0)
  ) {
    errors.push("corporate.officer.transaction_categories_missing");
  }

  // rationale_uri on grant
  if (typeof b["rationale_uri"] !== "string" || b["rationale_uri"] === "") {
    errors.push("corporate.officer.rationale_uri_missing");
  }

  // delegable + sub_delegation_authority_uri
  if (b["delegable"] === true) {
    if (
      typeof constraints?.["sub_delegation_authority_uri"] !== "string" ||
      constraints["sub_delegation_authority_uri"] === ""
    ) {
      errors.push("corporate.officer.sub_delegation_authority_uri_missing");
    }
  }

  return { errors };
}

export const validateCorporateOfficerProfile = makeProfileAdapter(
  CORPORATE_OFFICER_PROFILE_ID,
  (body) => validateCorporateOfficer(body as AdrBody),
);
