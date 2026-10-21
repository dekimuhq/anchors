/**
 * Daily-root envelope signature + Merkle inclusion check. Pure, no I/O.
 * Mirrors `apr-spec/v1.md` §7.
 */

import { canonicalize } from "./canonicalize.ts";
import { base64UrlDecode } from "./base64url.ts";
import { ed25519Verify } from "./ed25519.ts";
import { computeMerkleRoot } from "./merkle.ts";
import type {
  DailyRoot,
  RootKeyResolver,
  VerifyReason,
} from "./types.ts";

export type AnchorCheckResult =
  | { state: "verified" }
  | { state: "failed"; reason: VerifyReason };

export function verifyAnchor(
  claimId: string,
  anchor: DailyRoot,
  anchorIds: readonly string[],
  resolver: RootKeyResolver,
): AnchorCheckResult {
  const rootKey = resolver(anchor.kid);
  if (!rootKey) {
    return { state: "failed", reason: "root-sig-invalid" };
  }
  if (rootKey.publicKey.length !== 32) {
    return { state: "failed", reason: "root-sig-invalid" };
  }

  let payload: string;
  try {
    payload = canonicalize({
      v: 1,
      date: anchor.date,
      rootHash: anchor.rootHash,
    });
  } catch {
    return { state: "failed", reason: "root-sig-invalid" };
  }
  let sigBytes: Uint8Array;
  try {
    sigBytes = base64UrlDecode(anchor.sig);
  } catch {
    return { state: "failed", reason: "root-sig-invalid" };
  }
  if (sigBytes.length !== 64) {
    return { state: "failed", reason: "root-sig-invalid" };
  }
  const sigOk = ed25519Verify(
    rootKey.publicKey,
    new TextEncoder().encode(payload),
    sigBytes,
  );
  if (!sigOk) {
    return { state: "failed", reason: "root-sig-invalid" };
  }

  const computed = computeMerkleRoot(anchorIds);
  if (computed !== anchor.rootHash) {
    return { state: "failed", reason: "root-hash-mismatch" };
  }
  if (!anchorIds.includes(claimId)) {
    return { state: "failed", reason: "missing-from-anchor" };
  }
  return { state: "verified" };
}
