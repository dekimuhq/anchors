/**
 * Claim-type → family-verifier dispatch for the Anchored Receipts family.
 *
 * Every shipped family is a `FamilyManifest` (via `defineFamily()`) exposing a
 * uniform `verifyReceipt(receipt, opts) => Promise<FamilyVerifyResult>` plus a
 * self-declared `meta.claim_types` set. This module collects all 14 manifests,
 * builds a `claim_type → manifest` index from their own declarations (no second
 * list to drift), and routes an unknown receipt to the owning family.
 *
 * Adding the 15th family = one import + one `ALL_FAMILIES` entry; the index and
 * `supportedClaimTypes()` follow automatically.
 *
 * Pure dispatch — no I/O. Key resolution, trust, and network resolvers are the
 * caller's `FamilyVerifyOptions` (see `resolve-key.ts` for the offline default).
 */

import type {
  FamilyManifest,
  FamilyVerifyOptions,
  FamilyVerifyResult,
} from "@dekimuhq/anchors-envelope";
import {
  apr,
  acr,
  arr,
  alr,
  anr,
  asr,
  abr,
  air,
  atokr,
  aar,
  adr,
  aer,
  atr,
  apur,
} from "@dekimuhq/anchors";

/** The 14 shipped family manifests, in REGISTRY order. */
export const ALL_FAMILIES: readonly FamilyManifest[] = [
  apr.aprFamily,
  acr.acrFamily,
  arr.arrFamily,
  alr.alrFamily,
  anr.anrFamily,
  asr.asrFamily,
  abr.abrFamily,
  air.airFamily,
  atokr.atokrFamily,
  aar.aarFamily,
  adr.adrFamily,
  aer.aerFamily,
  atr.atrFamily,
  apur.apurFamily,
];

/** `claim_type → owning manifest`, built from each manifest's own declaration. */
const CLAIM_TYPE_INDEX: ReadonlyMap<string, FamilyManifest> = (() => {
  const index = new Map<string, FamilyManifest>();
  for (const family of ALL_FAMILIES) {
    for (const claimType of family.meta.claim_types) {
      const existing = index.get(claimType);
      if (existing !== undefined) {
        throw new Error(
          `anchors-cli: claim_type "${claimType}" is claimed by both ` +
            `${existing.meta.acronym} and ${family.meta.acronym}`
        );
      }
      index.set(claimType, family);
    }
  }
  return index;
})();

/** All claim_type discriminators the CLI can verify, lexicographically sorted. */
export function supportedClaimTypes(): string[] {
  return Array.from(CLAIM_TYPE_INDEX.keys()).sort();
}

/** Result of routing one receipt through the family dispatcher. */
export interface AnchorVerifyOutcome {
  /** Convenience: `true` iff the family verifier returned `signature_valid`. */
  ok: boolean;
  /** The receipt's declared `claim_type`, or `null` when absent/non-string. */
  claim_type: string | null;
  /** Acronym of the family that handled it, or `null` when undispatched. */
  family: string | null;
  /**
   * Dispatch-level failure reason, set only when the receipt never reached a
   * family verifier (`missing_claim_type` / `unknown_claim_type`). When the
   * receipt was dispatched, the verifier's own reason rides `result.reason`.
   */
  reason?: string;
  /** The family verifier's full result, or `null` when undispatched. */
  result: FamilyVerifyResult | null;
}

function readClaimType(receipt: unknown): string | null {
  if (typeof receipt !== "object" || receipt === null) return null;
  const raw = (receipt as { claim_type?: unknown }).claim_type;
  return typeof raw === "string" && raw.length > 0 ? raw : null;
}

/**
 * Route a single receipt to its family verifier by `claim_type` and return a
 * uniform outcome. Never throws — a malformed or unknown receipt comes back as
 * `{ ok: false, reason }` with `result: null`.
 */
export async function verifyAnchor(
  receipt: unknown,
  opts: FamilyVerifyOptions
): Promise<AnchorVerifyOutcome> {
  const claim_type = readClaimType(receipt);
  if (claim_type === null) {
    return {
      ok: false,
      claim_type: null,
      family: null,
      reason: "missing_claim_type",
      result: null,
    };
  }
  const manifest = CLAIM_TYPE_INDEX.get(claim_type);
  if (manifest === undefined) {
    return {
      ok: false,
      claim_type,
      family: null,
      reason: "unknown_claim_type",
      result: null,
    };
  }
  const result = await manifest.verifyReceipt(receipt, opts);
  return {
    ok: result.signature_valid === true,
    claim_type,
    family: manifest.meta.acronym,
    result,
  };
}
