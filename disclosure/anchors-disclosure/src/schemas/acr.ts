import type { DisclosureSchema } from "../types.ts";

/** Disclosure schema for consent-shaped (ACR) receipts under the generic
 *  path-bound scheme: leaf order is sub, then each purpose, then policy.
 *
 *  NOTE: ACR's *legacy* on-wire receipts store positional per-field COMMITMENTS
 *  (sub_commit/purposes[]/policy_hash) and are verified by acr-verifier's own
 *  verifyDisclosureProof. This schema is for NEW disclosable mints that adopt the
 *  generic raw-value scheme — proving ar.disclosure.v1 end-to-end (decision
 *  2026-06-01, L22). Paths point at raw values, which the generic field tree
 *  commits via leafCommit(salt, path, value). */
export const ACR_DISCLOSURE_SCHEMA: DisclosureSchema = {
  claim_type: "ar.consent.v1",
  leaves: [{ path: "/sub" }, { path: "/purposes", array: true }, { path: "/policy" }],
};
