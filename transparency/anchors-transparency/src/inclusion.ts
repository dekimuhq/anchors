import { verifyInclusionProof } from "./rfc6962.ts";
import { verifyCheckpoint, parseCheckpoint } from "./checkpoint.ts";
import { verifyPromise } from "./promise.ts";
import type { InclBlock, InclusionProof, LogStatus } from "./types.ts";

const SHA256_SELF_DESCRIBING = /^sha256:[0-9a-f]{64}$/;

function hexOf(selfDescribing: string): Buffer {
  const [, hex] = selfDescribing.split(":");
  return Buffer.from(hex ?? "", "hex");
}

/** Verify an inclusion proof: the proof's checkpoint must verify AND the audit path must reach its root. */
export function verifyInclusion(
  leaf: string,
  proof: InclusionProof,
  logKeys: Record<string, string>,
): boolean {
  if (!SHA256_SELF_DESCRIBING.test(leaf)) return false;
  if (proof.path.some((e) => !SHA256_SELF_DESCRIBING.test(e))) return false;
  if (!verifyCheckpoint(proof.checkpoint, logKeys)) return false;
  const cp = parseCheckpoint(proof.checkpoint);
  if (cp.size !== proof.tree_size) return false;
  const root = Buffer.from(cp.rootHashB64, "base64");
  return verifyInclusionProof(hexOf(leaf), proof.index, proof.tree_size, proof.path.map(hexOf), root);
}

/**
 * Tri-state log status. With `logKeys`, a present-but-invalid block is HARD-fail (`incl_invalid`);
 * callers MUST treat `incl_invalid` as a verification failure, never a silent pass.
 * Without keys, the block is reported as-is (caller cannot cryptographically confirm it).
 */
export function logStatus(
  incl: InclBlock | undefined,
  logKeys?: Record<string, string>,
): LogStatus {
  if (!incl) return "not_logged";
  if (logKeys) {
    if (incl.proof) {
      return verifyInclusion(incl.leaf, incl.proof, logKeys) ? "logged_proven" : "incl_invalid";
    }
    if (incl.promise) {
      return verifyPromise(incl.log_id, incl.leaf, incl.promise, logKeys) ? "logged_promised" : "incl_invalid";
    }
    return "incl_invalid"; // block present but neither promise nor proof
  }
  return incl.proof ? "logged_proven" : "logged_promised";
}
