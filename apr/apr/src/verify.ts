/**
 * Top-level APR verification — orchestrates claim signature, anchor signature,
 * and Merkle inclusion per `apr-spec/v1.md` §8.
 *
 * Pure: no network, no filesystem, no Dekimu infra. Caller supplies key
 * resolvers and the daily-root inclusion id list.
 */

import { verifyClaim } from "./verify-claim.ts";
import { verifyAnchor } from "./verify-anchor.ts";
import type { VerifyInput, VerifyResult, VerifyReason } from "./types.ts";

const CLAIM_FAIL_TAMPER: ReadonlySet<VerifyReason> = new Set([
  "schema_invalid",
  "unknown_kid",
  "issuer_kid_mismatch",
  "kid_not_yet_valid",
  "kid_no_longer_valid",
  "expired",
  "signature_invalid",
]);

export function verify(input: VerifyInput): VerifyResult {
  const now = (input.now ?? defaultNow)();

  const claimResult = verifyClaim(input.claim, input.claimKeyResolver, now);
  if (!claimResult.ok) {
    const status = CLAIM_FAIL_TAMPER.has(claimResult.reason)
      ? "tampered"
      : "unverified";
    return { status, reasons: [claimResult.reason] };
  }

  const claim = claimResult.claim;

  if (input.anchor === null) {
    return { status: "unverified", reasons: ["unanchored"] };
  }

  const anchorResult = verifyAnchor(
    claim.id,
    input.anchor,
    input.anchorIds,
    input.rootKeyResolver,
  );

  if (anchorResult.state === "verified") {
    return { status: "verified", reasons: [] };
  }

  if (anchorResult.reason === "missing-from-anchor") {
    return { status: "tampered", reasons: ["missing-from-anchor"] };
  }
  return { status: "unverified", reasons: [anchorResult.reason] };
}

function defaultNow(): number {
  return Math.floor(Date.now() / 1000);
}
