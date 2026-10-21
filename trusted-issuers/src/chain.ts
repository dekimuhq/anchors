/**
 * Append-only hash-chain integrity for `ar.trusted_issuers.v1` lists.
 *
 * Each non-genesis list commits to `sha256(canonical(prev))` via its
 * `previous_sha256` field. The chain is canonicalised with `sig` INCLUDED —
 * the hash binds the signed bytes, not the unsigned payload (so a re-signature
 * with a different key would break the chain at the next link, as intended).
 *
 * Per-list signature verification is `verifyTrustedIssuersList`'s job. This
 * function checks integrity only — callers MAY combine them (verify each
 * list's sig + verify the chain links).
 *
 * Master plan reference: §2.3 (hash-chain semantics).
 */

import { createHash } from "node:crypto";
import { canonicalize } from "@dekimuhq/anchors-envelope";
import type { TrustedIssuerListV1 } from "./types.ts";

export interface VerifyHashChainResult {
  ok: boolean;
  /** 0-indexed position of the first invalid link. `null` if all links valid. */
  brokenAt: number | null;
  reason:
    | "ok"
    | "first_not_genesis"
    | "version_not_increasing"
    | "previous_sha256_mismatch"
    | "empty_chain";
}

const HEX_PREFIX = "sha256:";

export function verifyHashChain(
  chain: TrustedIssuerListV1[],
): VerifyHashChainResult {
  if (chain.length === 0) {
    return { ok: false, brokenAt: null, reason: "empty_chain" };
  }

  const genesis = chain[0]!;
  if (genesis.previous_sha256 !== null) {
    return { ok: false, brokenAt: 0, reason: "first_not_genesis" };
  }

  for (let i = 0; i < chain.length - 1; i++) {
    const prev = chain[i]!;
    const next = chain[i + 1]!;

    if (next.version !== prev.version + 1) {
      return {
        ok: false,
        brokenAt: i + 1,
        reason: "version_not_increasing",
      };
    }

    const expected = `${HEX_PREFIX}${sha256Canonical(prev)}`;
    const got = (next.previous_sha256 ?? "").toLowerCase();
    if (got !== expected) {
      return {
        ok: false,
        brokenAt: i + 1,
        reason: "previous_sha256_mismatch",
      };
    }
  }

  return { ok: true, brokenAt: null, reason: "ok" };
}

function sha256Canonical(doc: TrustedIssuerListV1): string {
  const canonicalJson = canonicalize(doc);
  return createHash("sha256").update(canonicalJson, "utf8").digest("hex");
}

/**
 * Public helper for fixture/test code that needs the same canonical sha256 the
 * chain verifier expects. Kept stable across versions — callers (e.g.
 * `scripts/build-fixtures.mjs`) depend on it.
 */
export function sha256OfCanonical(doc: TrustedIssuerListV1): string {
  return `${HEX_PREFIX}${sha256Canonical(doc)}`;
}
